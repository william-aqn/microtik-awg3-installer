#!/usr/bin/env python3
"""Prepare a private, reviewable RouterOS panel deployment bundle offline.

No SSH connection, no credential extraction, no changes to the router.
Import setup.rsc only after uploading the image and settings to the USB disk.
"""
import argparse
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets


def quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$') + '"'


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii', newline='\n') as stream:
        stream.write(text)


def build_bundle(lan, bridge, disk, upstream, wan_address, password):
    network = ipaddress.IPv4Network(lan, strict=True)
    if network.prefixlen != 24 or not network.is_private:
        raise ValueError('LAN must be a private IPv4 /24.')
    if network.overlaps(ipaddress.IPv4Network('172.18.20.0/23')):
        raise ValueError('LAN overlaps container management networks.')
    for value in (bridge, disk):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', value):
            raise ValueError('Invalid interface or disk name.')
    if not disk.startswith('usb'):
        raise ValueError('Use an external USB disk.')
    if len(password) < 16:
        raise ValueError('Panel password must contain at least 16 characters.')
    gateway = str(network.network_address + 1)
    allowed_hosts = [gateway + ':8088', '172.18.21.2:8088']
    if bool(upstream) != bool(wan_address):
        raise ValueError('Specify both --upstream and --wan-address, or neither.')
    if upstream:
        upstream = str(ipaddress.IPv4Address(upstream))
        wan_address = str(ipaddress.IPv4Address(wan_address))
        if not ipaddress.ip_address(upstream).is_private or not ipaddress.ip_address(wan_address).is_private:
            raise ValueError('Temporary upstream management must use private IPv4 addresses.')
        allowed_hosts.append(wan_address + ':8088')
    api_password = secrets.token_hex(24)
    salt = secrets.token_bytes(16)
    settings = {
        'listen': ':8088', 'router_url': 'http://172.18.21.1',
        'router_user': 'awg-panel', 'router_password': api_password,
        'password_salt': salt.hex(),
        'password_hash': hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex(),
        'hosts': allowed_hosts, 'lan': str(network), 'bridge': bridge, 'data_dir': '/data',
    }
    # Preserve the existing toggle source under a new name. The wrapper keeps
    # the policy entry rule disabled while the original tunnel checks run.
    prefix = '^' + re.escape(str(network.network_address).rsplit('.', 1)[0] + '.')
    wrapper = f'''\
:if ([:len [/system/script/job/find where script="awg-ui-apply" or script="awg-toggle-base"]] > 0 || [:len [/system/script/job/find where script="awg-toggle"]] > 1) do={{ :log warning "AWG3UI: operation in progress"; :return }};
:global awgBusy;
:if ($awgBusy = true) do={{ :log warning "AWG3UI: operation already running"; :return }};
/ip/firewall/mangle/disable [find where comment~"^AWG3UI entry "];
:do {{ /system/script/run awg-toggle-base }} on-error={{ :log error "AWG3UI: base toggle failed" }};
:local r [/routing/rule/find where comment="AWG3 switch LAN"];
:local c [/container/find where name="awg3"];
:if ([:len $r] = 1 && [:len $c] = 1) do={{
    :if ([/routing/rule/get $r disabled] = false && [/container/get $c running] = true) do={{
        /ip/firewall/mangle/enable [find where comment~"^AWG3UI entry "];
    }};
}};
/ip/firewall/connection/remove [find where src-address~{quote(prefix)}];
'''
    setup = [
        '# Private deployment file. Contains a RouterOS service credential. Do not publish.',
        ':if ([/system/resource/get board-name] != "hAP ac^2") do={ :error "Unsupported board" }',
        ':if ([/system/resource/get version] != "7.24.5 (stable)") do={ :error "Requires RouterOS 7.24.5 stable" }',
        ':if ([/system/resource/get free-memory] < 25165824) do={ :error "Need at least 24 MiB free RAM before installation" }',
        ':if ([/system/resource/get free-hdd-space] < 163840) do={ :error "Need at least 160 KiB free flash" }',
        ':if ([:len [/container/find where name="awg3"]] != 1) do={ :error "AWG3 installation missing" }',
        ':if ([:len [/routing/rule/find where comment="AWG3 switch LAN"]] != 1) do={ :error "AWG3 switch rule missing" }',
        ':if ([:len [/system/script/find where name="awg-toggle"]] != 1) do={ :error "AWG3 toggle missing" }',
        ':if ([:len [/user/find where name="awg-panel"]] > 0 || [:len [/user/group/find where name="awg-panel"]] > 0) do={ :error "Panel user/group name already exists" }',
        ':if ([:len [/interface/find where name="awg-ui-veth"]] > 0 || [:len [/container/find where name="awg-panel"]] > 0 || [:len [/system/script/find where name="awg-toggle-base"]] > 0) do={ :error "Panel already installed or partially installed; use rollback first" }',
        ':if ([:len [/ipv6/route/find where dst-address="::/0" and active]] > 0) do={ :error "Active IPv6 internet is not supported" }',
        f':if ([:len [/file/find where name={quote(disk + "/awg-panel.tar")}]] != 1 || [:len [/file/find where name={quote(disk + "/awg-panel-data/settings.json")}]] != 1) do={{ :error "Upload image and settings.json to USB first" }}',
        f'/system/backup/save name={quote(disk + "/before-awg-panel")}',
        '/interface/veth/add name=awg-ui-veth address=172.18.21.2/30 gateway=172.18.21.1 comment="AWG3UI veth"',
        '/ip/address/add address=172.18.21.1/30 interface=awg-ui-veth comment="AWG3UI management"',
        '/user/group/add name=awg-panel policy=read,write,test,rest-api',
        f'/user/add name=awg-panel group=awg-panel address=172.18.21.2/32 password={quote(api_password)} comment="AWG3UI service"',
        # Do not widen a restricted www service silently. Require the operator
        # to have allowed the management /32 before importing this bundle.
        '/ip/firewall/filter/add chain=input in-interface=awg-ui-veth action=drop comment="AWG3UI input guard" place-before=0',
        '/ip/firewall/filter/add chain=input in-interface=awg-ui-veth src-address=172.18.21.2 dst-address=172.18.21.1 protocol=tcp dst-port=80,53 action=accept comment="AWG3UI API and DNS" place-before=0',
        '/ip/firewall/filter/add chain=input in-interface=awg-ui-veth src-address=172.18.21.2 dst-address=172.18.21.1 protocol=udp dst-port=53 action=accept comment="AWG3UI DNS" place-before=0',
        '/ip/firewall/filter/add chain=forward out-interface=awg-ui-veth action=drop comment="AWG3UI access guard" place-before=0',
        '/ip/firewall/filter/add chain=forward out-interface=awg-ui-veth connection-state=established,related action=accept comment="AWG3UI replies" place-before=0',
        f'/ip/firewall/filter/add chain=forward in-interface={bridge} src-address={network} out-interface=awg-ui-veth protocol=tcp dst-port=8088 action=accept comment="AWG3UI LAN panel" place-before=0',
        '/ip/firewall/nat/add chain=srcnat src-address=172.18.21.2 action=masquerade out-interface-list=WAN comment="AWG3UI updates"',
        f'/ip/firewall/nat/add chain=dstnat in-interface={bridge} src-address={network} dst-address-type=local protocol=tcp dst-port=8088 action=dst-nat to-addresses=172.18.21.2 to-ports=8088 comment="AWG3UI LAN panel" place-before=0',
        f'/ip/firewall/filter/add chain=forward in-interface={bridge} connection-state=established,related action=accept comment="AWG3UI skip FastTrack out" place-before=0',
        f'/ip/firewall/filter/add chain=forward out-interface={bridge} connection-state=established,related action=accept comment="AWG3UI skip FastTrack in" place-before=0',
        '/ip/route/add dst-address=0.0.0.0/0 routing-table=to-awg blackhole distance=254 comment="AWG3UI no main fallback"',
        '/ip/firewall/mangle/add chain=AWG3UI-a action=return comment="AWG3UI initial passthrough"',
        f'/ip/firewall/mangle/add chain=prerouting in-interface={bridge} src-address={network} dst-address-type=!local action=jump jump-target=AWG3UI-a disabled=yes comment="AWG3UI entry initial" place-before=0',
        '/system/script/set [find where name="awg-toggle"] name=awg-toggle-base',
        f'/system/script/add name=awg-toggle policy=read,write,test comment="AWG3UI managed" source={{\n{wrapper}}}',
        ':if ([/routing/rule/get [find where comment="AWG3 switch LAN"] disabled] = false) do={ /ip/firewall/mangle/enable [find where comment="AWG3UI entry initial"] }',
        f'/container/mounts/add list=awg_ui_mount src={quote(disk + "/awg-panel-data")} dst=/data',
        f'/container/add file={quote(disk + "/awg-panel.tar")} name=awg-panel interface=awg-ui-veth root-dir={quote(disk + "/awg-panel-root")} mountlists=awg_ui_mount dns=172.18.21.1 logging=yes start-on-boot=yes memory-high=12582912 memory-max=16777216',
        ':local panel [/container/find where name="awg-panel"]',
        ':for attempt from=1 to=120 do={ :if ([/container/get $panel stopped] = false) do={ :delay 1s } }',
        ':if ([/container/get $panel stopped] = false) do={ :error "Image is still extracting; check Container before starting it" }',
        '/container/start $panel',
        ':put "Panel available on LAN gateway port 8088. Check diagnostics before applying policies."',
    ]
    if upstream:
        insertion = setup.index('/ip/firewall/nat/add chain=srcnat src-address=172.18.21.2 action=masquerade out-interface-list=WAN comment="AWG3UI updates"')
        setup[insertion:insertion] = [
            f'/ip/firewall/filter/add chain=forward in-interface-list=WAN src-address={upstream} out-interface=awg-ui-veth protocol=tcp dst-port=8088 action=accept comment="AWG3UI temporary upstream" place-before=0',
            f'/ip/firewall/nat/add chain=dstnat in-interface-list=WAN src-address={upstream} dst-address={wan_address} protocol=tcp dst-port=8088 action=dst-nat to-addresses=172.18.21.2 to-ports=8088 comment="AWG3UI temporary upstream" place-before=0',
        ]
    rollback = f'''\
# Removes only AWG3UI-owned integration. USB files are retained for recovery.
/ip/firewall/mangle/disable [find where comment~"^AWG3UI entry "]
:local c [/container/find where name="awg-panel"]
:if ([:len $c] = 1) do={{
    /container/set $c start-on-boot=no
    :if ([/container/get $c running] = true) do={{ /container/stop $c }}
    :for i from=1 to=15 do={{ :if ([/container/get $c stopped] = false) do={{ :delay 1s }} }}
    :if ([/container/get $c stopped] = false) do={{ :error "Panel has not stopped; retry rollback" }}
    /container/remove $c
}}
:if ([:len [/system/script/find where name="awg-toggle-base"]] = 1) do={{
    /system/script/remove [find where name="awg-toggle" and comment="AWG3UI managed"]
    /system/script/set [find where name="awg-toggle-base"] name=awg-toggle
}}
/system/script/remove [find where comment="AWG3UI managed"]
/ip/firewall/mangle/remove [find where comment~"^AWG3UI "]
/ip/firewall/nat/remove [find where comment~"^AWG3UI "]
/ip/firewall/filter/remove [find where comment~"^AWG3UI "]
/ip/firewall/address-list/remove [find where list~"^AWG3UI-"]
/ip/dns/static/remove [find where comment~"^AWG3UI "]
/ip/route/remove [find where comment~"^AWG3UI "]
/ip/address/remove [find where comment~"^AWG3UI "]
/container/mounts/remove [find where list="awg_ui_mount"]
/interface/veth/remove [find where name="awg-ui-veth"]
/user/remove [find where name="awg-panel" and comment="AWG3UI service"]
/user/group/remove [find where name="awg-panel"]
/ip/firewall/connection/remove [find where src-address~{quote(prefix)}]
/ip/dns/cache/flush
:put "Panel integration removed. Original AWG toggle restored. USB files kept."
'''
    return settings, '\n'.join(setup) + '\n', rollback


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lan', default='192.168.3.0/24')
    p.add_argument('--bridge', default='bridge')
    p.add_argument('--disk', default='usb1-part1')
    p.add_argument('--upstream', help='Optional temporary management PC IPv4')
    p.add_argument('--wan-address', help='Private WAN IPv4 used by that PC')
    p.add_argument('--output', type=Path, default=Path('awg-panel-private'))
    args = p.parse_args()
    if args.output.exists():
        p.error('Output directory already exists; choose a new directory.')
    password = getpass.getpass('New panel password (16+ characters): ')
    if password != getpass.getpass('Repeat panel password: '):
        p.error('Passwords do not match.')
    settings, setup, rollback = build_bundle(args.lan, args.bridge, args.disk, args.upstream, args.wan_address, password)
    write_private(args.output / 'settings.json', json.dumps(settings, indent=2))
    write_private(args.output / 'setup.rsc', setup)
    write_private(args.output / 'rollback.rsc', rollback)
    print('Private bundle prepared. Do not commit or publish this directory.')
    print('Upload settings.json to USB/awg-panel-data/; upload the image and scripts to USB.')
    print('Review setup.rsc and docs before importing. Router settings were not changed.')


if __name__ == '__main__':
    main()

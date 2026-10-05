"""Generate standalone AWG Control integration and reversible legacy migration."""
import hashlib
import ipaddress
import re
import secrets


def quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$') + '"'


def mode_script(lan):
    prefix = '^' + re.escape(str(ipaddress.ip_network(lan).network_address).rsplit('.', 1)[0] + '.')
    return f'''\
:global awgModeClicks;
:if ([:typeof $awgModeClicks] != "num") do={{ :set awgModeClicks 0 }};
:set awgModeClicks ($awgModeClicks + 1);
:if ($awgModeClicks > 1) do={{ :return 0 }};
:delay 1500ms;
:local clicks $awgModeClicks;
:set awgModeClicks 0;
:local c [/container/find where name="awg-control"];
:if ([:len $c] != 1) do={{ :log error "AWGC: container missing"; :return 0 }};
:if ($clicks > 1) do={{
    :log info "AWGC: full stop accepted";
    :local led [/system/leds/find where leds="user-led"];
    :if ([:len $led] = 1) do={{
        /system/leds/set $led type=off;
        :delay 150ms;
        :for pulse from=1 to=2 do={{
            /system/leds/set $led type=on;
            :delay 150ms;
            /system/leds/set $led type=off;
            :delay 150ms;
        }};
    }};
    :local wasRunning [/container/get $c running];
    /container/set $c start-on-boot=no;
    :if ($wasRunning = true) do={{ /container/stop $c }};
    :for wait from=1 to=30 do={{ :if ([/container/get $c stopped] != true) do={{ :delay 1s }} }};
    :if ([/container/get $c stopped] != true) do={{ :log error "AWGC: stop incomplete"; :return 0 }};
    /ip/firewall/mangle/disable [find where comment~"^AWG3UI entry "];
    /routing/rule/disable [find where comment~"^AWGC DNS "];
    /ip/firewall/connection/remove [find where src-address~{quote(prefix)}];
    /ip/dns/cache/flush;
    :if ([:len $led] = 1) do={{ /system/leds/set $led type=off }};
}} else={{
    :if ([/container/get $c running] != true) do={{
        /container/set $c start-on-boot=yes;
        /container/start $c;
        :for wait from=1 to=30 do={{ :if ([/container/get $c running] != true) do={{ :delay 1s }} }};
        :if ([/container/get $c running] != true) do={{ :log error "AWGC: container did not start"; :return 0 }};
        /container/shell $c cmd="/awg-control --control connect" no-sh;
    }} else={{
        /container/shell $c cmd="/awg-control --control toggle" no-sh;
    }};
}};
'''


def legacy_disable(menu, pattern):
    return f'''\
:foreach item in=[{menu}/find where comment~{quote(pattern)}] do={{
    :local label [{menu}/get $item comment];
    :local state "off ";
    :if ([{menu}/get $item disabled] = false) do={{ :set state "on " }};
    {menu}/set $item disabled=yes comment=("AWGC legacy " . $state . $label);
}};'''


def legacy_restore(menu):
    return f'''\
:foreach item in=[{menu}/find where comment~"^AWGC legacy "] do={{
    :local label [{menu}/get $item comment];
    :local enabled ([:pick $label 12 15] = "on ");
    :local offset 16;
    :if ($enabled) do={{ :set offset 15 }};
    {menu}/set $item comment=[:pick $label $offset [:len $label]] disabled=(!$enabled);
}};'''


def build_bundle(lan, bridge, disk, upstream, wan_address, password, *, migration=False, prior_settings=None):
    network = ipaddress.IPv4Network(lan, strict=True)
    if network.prefixlen != 24 or not network.is_private or network.overlaps(ipaddress.ip_network('172.18.20.0/22')):
        raise ValueError('Use a private IPv4 LAN /24 outside 172.18.20.0/22.')
    for value in (bridge, disk):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', value):
            raise ValueError('Invalid bridge or disk name.')
    if not disk.startswith('usb'):
        raise ValueError('Use an external USB disk.')
    if bool(upstream) != bool(wan_address):
        raise ValueError('Specify both upstream PC and private WAN address.')
    if upstream:
        upstream = str(ipaddress.IPv4Address(upstream))
        wan_address = str(ipaddress.IPv4Address(wan_address))
        if not ipaddress.ip_address(upstream).is_private or not ipaddress.ip_address(wan_address).is_private:
            raise ValueError('Upstream management is limited to one private PC.')
    gateway = str(network.network_address + 1)
    if migration:
        if not prior_settings or prior_settings.get('router_user') != 'awg-panel':
            raise ValueError('Migration requires the previous private settings.json.')
        salt, pwd_hash, api_password = (prior_settings[k] for k in ('password_salt', 'password_hash', 'router_password'))
        if not re.fullmatch(r'[a-f0-9]{48}', api_password):
            raise ValueError('Unexpected legacy service credential format.')
    else:
        if len(password) < 16:
            raise ValueError('Use a panel password of at least 16 characters.')
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100000).hex()
        api_password = secrets.token_hex(24)
    settings = {
        'listen': ':8088', 'router_url': 'http://172.18.20.1',
        'router_user': 'awg-panel' if migration else 'awg-control', 'router_password': api_password,
        'password_salt': salt, 'password_hash': pwd_hash,
        'hosts': [gateway + ':8088', '172.18.20.2:8088'] + ([wan_address + ':8088'] if upstream else []),
        'lan': str(network), 'bridge': bridge, 'data_dir': '/data',
        'uplink': 'docker-awg-veth', 'gateway': '172.18.20.1',
    }
    setup = [
        '# Private deployment bundle. Do not publish; contains service credentials in fresh mode.',
        ':if ([/system/resource/get board-name] != "hAP ac^2" || [/system/resource/get version] != "7.24.5 (stable)") do={ :error "Validated target: hAP ac2 / RouterOS 7.24.5 stable" }',
        ':if ([/system/resource/get free-memory] < 25165824 || [/system/resource/get free-hdd-space] < 163840) do={ :error "Need 24 MiB RAM and 160 KiB flash free" }',
        ':if ([:len [/container/find where name="awg-control"]] > 0 || [:len [/user/find where name="awg-control"]] > 0 || [:len [/system/script/find where name="awg-control-restore-dns"]] > 0) do={ :error "Already installed or partial migration; inspect rollback before retrying" }',
        ':if ([:len [/ipv6/route/find where dst-address="::/0" and active]] > 0) do={ :error "IPv6 internet is not supported by this release" }',
        f':if ([:len [/file/find where name={quote(disk + "/awg-control.tar")}]] != 1 || [:len [/file/find where name={quote(disk + "/awg-control-data/settings.json")}]] != 1) do={{ :error "Upload image and private data to USB first" }}',
        ':if ([/ip/service/get [/ip/service/find where name="www" and dynamic=no] disabled] = true || [/ip/service/get [/ip/service/find where name="www" and dynamic=no] port] != 80) do={ :error "Enable local www port 80 and permit 172.18.20.2/32 before import" }',
    ]
    if migration:
        setup += [
            ':if ([:len [/container/find where name="awg3"]] != 1 || [:len [/container/find where name="awg-panel"]] != 1 || [:len [/user/find where name="awg-panel"]] != 1) do={ :error "Expected the two-container 0.1.1 installation" }',
            ':if ([/routing/rule/get [/routing/rule/find where comment="AWG3 switch LAN"] disabled] = true) do={ :error "Enable the existing VPN before migration" }',
            '/system/scheduler/disable [find where name="awg-led"]',
            '/system/routerboard/mode-button/set enabled=no',
            '/ip/firewall/mangle/disable [find where comment~"^AWG3UI entry "]',
            ':foreach c in=[/container/find where name="awg3" or name="awg-panel"] do={ :local wasRunning [/container/get $c running]; /container/set $c start-on-boot=no; :if ($wasRunning = true) do={ /container/stop $c }; :for attempt from=1 to=30 do={ :if ([/container/get $c stopped] != true) do={ :delay 1s } }; :if ([/container/get $c stopped] != true) do={ :error "Legacy container did not stop" } }',
            '/interface/veth/add name=awg-retired-veth address=172.18.23.2/30 gateway=172.18.23.1 comment="AWGC rollback parking"',
            '/container/set [find where name="awg3"] interface=awg-retired-veth',
            legacy_disable('/ip/firewall/filter', '^AWG3'),
            legacy_disable('/ip/firewall/nat', '^AWG3'),
            legacy_disable('/ip/firewall/mangle', '^AWG3 '),
            legacy_disable('/routing/rule', '^AWG3 '),
            '/user/set [find where name="awg-panel"] address=172.18.20.2/32',
        ]
    else:
        setup += [
            ':if ([:len [/interface/find where name="docker-awg-veth"]] > 0 || [:len [/routing/table/find where name="to-awg"]] > 0 || [:len [/system/script/find where name="awg-mode"]] > 0) do={ :error "Existing integration found; use migration or a clean target" }',
            ':if ([/system/routerboard/mode-button/get enabled] = true) do={ :error "Existing Mode binding found; save and disable it before fresh installation" }',
            '/interface/veth/add name=docker-awg-veth address=172.18.20.2/30 gateway=172.18.20.1 comment="AWGC uplink"',
            '/ip/address/add address=172.18.20.1/30 interface=docker-awg-veth comment="AWGC management"',
            '/routing/table/add name=to-awg fib',
            '/ip/route/add dst-address=0.0.0.0/0 gateway=172.18.20.2@main routing-table=to-awg distance=1 comment="AWGC tunnel route"',
            '/ip/route/add dst-address=0.0.0.0/0 routing-table=to-awg blackhole distance=254 comment="AWGC no main fallback"',
            '/ip/firewall/mangle/add chain=AWG3UI-a action=mark-routing new-routing-mark=to-awg passthrough=no comment="AWG3UI initial VPN"',
            f'/ip/firewall/mangle/add chain=prerouting in-interface={bridge} src-address={network} dst-address-type=!local action=jump jump-target=AWG3UI-a disabled=yes comment="AWG3UI entry initial" place-before=0',
            '/user/group/add name=awg-control policy=read,write,test,api,rest-api',
            f'/user/add name=awg-control group=awg-control address=172.18.20.2/32 password={quote(api_password)} comment="AWGC service"',
        ]
    checks = [line for line in setup if line.startswith(':if ') and 'do={ :error' in line]
    actions = [line for line in setup if line not in checks]
    dns_snapshot = r':local oldDNS [/ip/dns/get servers]; :local oldRemote [/ip/dns/get allow-remote-requests]; /system/script/add name=awg-control-restore-dns policy=read,write source=("/ip/dns/set servers=\"" . [:tostr $oldDNS] . "\" allow-remote-requests=" . $oldRemote)'
    setup = checks + [f'/system/backup/save name={quote(disk + "/before-awg-control")}', dns_snapshot] + actions
    setup += [
        '/ip/firewall/filter/add chain=input in-interface=docker-awg-veth action=drop comment="AWGC input guard" place-before=0',
        # The router's own DNS requests return through the tunnel with the
        # remote resolver as source, not the container's management address.
        '/ip/firewall/filter/add chain=input in-interface=docker-awg-veth connection-state=established,related action=accept comment="AWGC router replies" place-before=[find where comment="AWGC input guard"]',
        '/ip/firewall/filter/add chain=input in-interface=docker-awg-veth src-address=172.18.20.2 dst-address=172.18.20.1 protocol=tcp dst-port=80,53 action=accept comment="AWGC API and DNS" place-before=[find where comment="AWGC input guard"]',
        '/ip/firewall/filter/add chain=input in-interface=docker-awg-veth src-address=172.18.20.2 dst-address=172.18.20.1 protocol=udp dst-port=53 action=accept comment="AWGC DNS" place-before=[find where comment="AWGC input guard"]',
        # Only encrypted transport may leave the container for the internet.
        # Geo downloads run through the tunnel, never via an extra WAN hole.
        '/ip/firewall/filter/add chain=forward in-interface=docker-awg-veth action=drop comment="AWGC egress guard" place-before=0',
        '/ip/firewall/filter/add chain=forward in-interface=docker-awg-veth src-address=172.18.20.2 out-interface-list=WAN dst-address=192.0.2.1 protocol=udp dst-port=9 action=accept comment="AWGC encrypted transport" place-before=[find where comment="AWGC egress guard"]',
        f'/ip/firewall/filter/add chain=forward in-interface=docker-awg-veth out-interface={bridge} dst-address={network} connection-state=established,related action=accept comment="AWGC LAN replies" place-before=[find where comment="AWGC egress guard"]',
        '/ip/firewall/filter/add chain=forward out-interface=docker-awg-veth action=drop comment="AWGC access guard" place-before=0',
        '/ip/firewall/filter/add chain=forward out-interface=docker-awg-veth connection-state=established,related action=accept comment="AWGC transport replies" place-before=[find where comment="AWGC access guard"]',
        f'/ip/firewall/filter/add chain=forward in-interface={bridge} src-address={network} out-interface=docker-awg-veth action=accept comment="AWGC LAN traffic" place-before=[find where comment="AWGC access guard"]',
        f'/ip/firewall/filter/add chain=forward in-interface={bridge} src-address={network} connection-state=established,related action=accept comment="AWGC skip FastTrack out" place-before=0',
        f'/ip/firewall/filter/add chain=forward out-interface={bridge} dst-address={network} connection-state=established,related action=accept comment="AWGC skip FastTrack in" place-before=0',
        f'/ip/firewall/nat/add chain=dstnat in-interface={bridge} src-address={network} dst-address-type=local protocol=tcp dst-port=8088 action=dst-nat to-addresses=172.18.20.2 to-ports=8088 comment="AWGC LAN panel" place-before=0',
        f'/ip/firewall/nat/add chain=srcnat src-address={network} out-interface=docker-awg-veth action=masquerade comment="AWGC traffic to container" place-before=0',
        '/ip/firewall/nat/add chain=srcnat src-address=172.18.20.2 dst-address=192.0.2.1 protocol=udp dst-port=9 out-interface-list=WAN action=masquerade comment="AWGC endpoint NAT" place-before=0',
        '/ip/firewall/mangle/add chain=forward out-interface=docker-awg-veth protocol=tcp tcp-flags=syn tcp-mss=1241-65535 action=change-mss new-mss=1240 passthrough=yes comment="AWGC TCP MSS"',
        f'/ip/firewall/filter/add chain=input in-interface={bridge} src-address={network} protocol=udp dst-port=53 action=accept comment="AWGC LAN DNS UDP" place-before=0',
        f'/ip/firewall/filter/add chain=input in-interface={bridge} src-address={network} protocol=tcp dst-port=53 action=accept comment="AWGC LAN DNS TCP" place-before=0',
        '/ip/firewall/filter/add chain=input in-interface-list=WAN protocol=udp dst-port=53 action=drop comment="AWGC block WAN DNS UDP" place-before=0',
        '/ip/firewall/filter/add chain=input in-interface-list=WAN protocol=tcp dst-port=53 action=drop comment="AWGC block WAN DNS TCP" place-before=0',
        '/ip/dns/set allow-remote-requests=yes',
    ]
    if upstream:
        setup += [
            f'/ip/firewall/filter/add chain=forward in-interface-list=WAN src-address={upstream} out-interface=docker-awg-veth protocol=tcp dst-port=8088 action=accept comment="AWGC temporary upstream" place-before=[find where comment="AWGC access guard"]',
            f'/ip/firewall/filter/add chain=forward in-interface=docker-awg-veth dst-address={upstream} src-address=172.18.20.2 protocol=tcp src-port=8088 connection-state=established,related action=accept comment="AWGC upstream replies" place-before=[find where comment="AWGC egress guard"]',
            f'/ip/firewall/nat/add chain=dstnat in-interface-list=WAN src-address={upstream} dst-address={wan_address} protocol=tcp dst-port=8088 action=dst-nat to-addresses=172.18.20.2 to-ports=8088 comment="AWGC temporary upstream" place-before=0',
        ]
    setup += [
        ':if ([:len [/system/leds/find where leds="user-led"]] = 0) do={ /system/leds/add leds=user-led type=off }',
        '/system/leds/set [find where leds="user-led"] type=off',
        f'/system/script/add name=awg-mode policy=read,write,test,policy source={{\n{mode_script(str(network))}}}',
        '/system/routerboard/mode-button/set enabled=yes hold-time=0s..3s on-event=awg-mode',
        f'/container/mounts/add list=awg_control_mount src={quote(disk + "/awg-control-data")} dst=/data',
        f'/container/add file={quote(disk + "/awg-control.tar")} name=awg-control interface=docker-awg-veth root-dir={quote(disk + "/awg-control-root")} mountlists=awg_control_mount dns=172.18.20.1 logging=yes start-on-boot=yes memory-high=25165824 memory-max=33554432',
        ':local c [/container/find where name="awg-control"]',
        ':for attempt from=1 to=120 do={ :if ([/container/get $c stopped] != true) do={ :delay 1s } }',
        ':if ([/container/get $c stopped] != true) do={ :error "Extraction incomplete; inspect Container before starting" }',
        '/container/start $c',
        ':put "AWG Control installed. Open the LAN gateway on port 8088. Check diagnostics."',
    ]
    rollback = [
        '# Removes unified integration; USB data is preserved.',
        '/system/routerboard/mode-button/set enabled=no',
        '/ip/firewall/mangle/disable [find where comment~"^AWG3UI entry "]',
        ':local c [/container/find where name="awg-control"]; :if ([:len $c] = 1) do={ :local wasRunning [/container/get $c running]; /container/set $c start-on-boot=no; :if ($wasRunning = true) do={ /container/stop $c }; :for i from=1 to=30 do={ :if ([/container/get $c stopped] != true) do={ :delay 1s } }; :if ([/container/get $c stopped] != true) do={ :error "Container still stopping" }; /container/remove $c }',
        '/routing/rule/remove [find where comment~"^AWGC DNS "]',
        '/system/script/remove [find where name="awg-mode" or name="awg-control-configure" or name="awg-control-gate"]',
        '/container/mounts/remove [find where list="awg_control_mount"]',
    ]
    for menu in ('/ip/firewall/filter', '/ip/firewall/nat', '/ip/firewall/mangle'):
        rollback.append(f'{menu}/remove [find where comment~"^AWGC " and !(comment~"^AWGC legacy ")]')
    if migration:
        rollback += [legacy_restore(menu) for menu in ('/ip/firewall/filter', '/ip/firewall/nat', '/ip/firewall/mangle', '/routing/rule')]
        rollback += [
            '/user/set [find where name="awg-panel"] address=172.18.21.2/32',
            '/container/set [find where name="awg3"] interface=docker-awg-veth start-on-boot=yes',
            '/interface/veth/remove [find where name="awg-retired-veth"]',
            '/container/set [find where name="awg-panel"] start-on-boot=yes',
            ':foreach c in=[/container/find where name="awg3" or name="awg-panel"] do={ :if ([/container/get $c running] != true) do={ /container/start $c } }',
            '/system/routerboard/mode-button/set enabled=yes hold-time=0s..3s on-event=awg-toggle',
            '/system/scheduler/enable [find where name="awg-led"]',
            '/ip/firewall/mangle/enable [find where comment~"^AWG3UI entry "]',
        ]
    else:
        rollback += [
            '/ip/firewall/mangle/remove [find where comment~"^AWG3UI "]',
            '/ip/dns/static/remove [find where comment~"^AWG3UI "]',
            '/ip/firewall/address-list/remove [find where list~"^AWG3UI-"]',
            '/ip/route/remove [find where comment~"^AWGC "]',
            '/routing/table/remove [find where name="to-awg"]',
            '/ip/address/remove [find where comment="AWGC management"]',
            '/interface/veth/remove [find where name="docker-awg-veth"]',
            '/user/remove [find where name="awg-control"]',
            '/user/group/remove [find where name="awg-control"]',
        ]
    rollback += ['/system/script/run awg-control-restore-dns', '/system/script/remove [find where name="awg-control-restore-dns"]', '/ip/dns/cache/flush', ':put "Rollback completed. Private USB files retained."']
    return settings, '\n'.join(setup) + '\n', '\n'.join(rollback) + '\n'

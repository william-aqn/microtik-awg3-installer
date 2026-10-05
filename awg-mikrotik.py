#!/usr/bin/env python3
"""Interactive AWG 3 installer for hAP ac2 / RouterOS 7.24.5.

Runs on a PC, uses SSH/SFTP. Never prints or exports the VPN configuration.
--diag is read-only; --dry-run needs no SSH or Paramiko.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import tarfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

VERSION = "1.0.0"
TESTED_ROS = "7.24.5"
TESTED_BOARD = "hAP ac^2"
IMAGE_REPO = "catesin/awg-mikrotik-arm"
IMAGE_DIGEST = "sha256:6e1fe2a0ede54bf28fd1560a1483e5c5f352c9cdf1e7c00ce6c0483ca8a999e8"
VETH = "docker-awg-veth"
GATEWAY = "172.18.20.1"
CONTAINER_IP = "172.18.20.2"
TRANSIT = ipaddress.IPv4Network("172.18.20.0/30")
CONTAINER = "awg3"
TABLE = "to-awg"
TAG = "AWG3 "
MOUNT = "awg_conf"
ENV = "awg_env"
MAX_DOWNLOAD = 64 * 1024 * 1024
MIN_DISK_FREE = 256 * 1024 * 1024
MIN_RAM_FREE = 24 * 1024 * 1024
EXTRACT_TIMEOUT = 300
SSH_TIMEOUT = 15
START_TIMEOUT = 45
STOP_WAIT = 15
TUNNEL_ATTEMPTS = 20
LED_INTERVAL = "3s"
MEMORY_HIGH = 32 * 1024 * 1024
MEMORY_MAX = 40 * 1024 * 1024
GO_MEMORY_LIMIT = "24MiB"
GO_GC = "50"
SECRET_KEYS = ("PrivateKey", "PresharedKey", "HeaderProtectionKey", "I1", "I2", "I3", "I4", "I5")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class InstallError(Exception):
    pass


def scrub(text):
    text = ANSI.sub("", str(text)).replace("\r", "")
    keys = "|".join(SECRET_KEYS)
    text = re.sub(rf"(?im)\b({keys}|password|authorization)\s*[=:]\s*[^\n]+", r"\1=<redacted>", text)
    # Also redact standalone WireGuard keys if a container error echoes them.
    return re.sub(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/])", "<key-redacted>", text)


def secure_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    return path


def ros_quote(value):
    value = str(value)
    if any(ord(c) < 32 for c in value):
        raise InstallError("Invalid control character in a parameter.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def ros_bool(value):
    if value in ('true', 'yes'):
        return 'yes'
    if value in ('false', 'no'):
        return 'no'
    raise InstallError('Unexpected RouterOS boolean value.')


def name(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", value):
        raise InstallError("Interface and disk names may contain only ASCII letters, digits, - and _.")
    return value


def ask(label, default=None):
    suffix = f" [{default}]" if default is not None else ""
    value = input(label + suffix + ": ").strip()
    return value or default or ""


def confirm(message, word="YES"):
    if input(f"{message}\nType {word}: ").strip() != word:
        raise InstallError("Operation cancelled.")


@dataclass
class Settings:
    lan: str = "192.168.3.0/24"
    bridge: str = "bridge"
    wan: str = "ether1"
    disk: str = "usb1-part1"
    bind_mode: bool = True
    bind_led: bool = True

    def validate(self):
        net = ipaddress.IPv4Network(self.lan, strict=True)
        if not net.is_private or net.prefixlen < 16 or net.overlaps(TRANSIT):
            raise InstallError("LAN must be a private IPv4 network /16.. /30 without overlap with VETH.")
        if net.prefixlen > 30:
            raise InstallError("LAN /31 and /32 are not supported.")
        for value in (self.bridge, self.wan, self.disk):
            name(value)
        if not self.disk.startswith("usb") or self.bridge == self.wan:
            raise InstallError("A USB disk and different LAN/WAN interfaces are required.")
        return self


@dataclass
class Config:
    text: str
    endpoint: str
    port: int
    dns: tuple[str, str]
    mtu: int


def parse_config(path, resolve=True):
    text = Path(path).read_text(encoding="utf-8-sig")
    sections = {"Interface": [], "Peer": []}
    current = None
    seen_sections = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            current = line.strip("[]")
            if current not in sections or current in seen_sections:
                raise InstallError("The config must have exactly one [Interface] and one [Peer].")
            seen_sections.add(current)
            continue
        if current is None or "=" not in line:
            raise InstallError("Invalid config line; its contents are hidden.")
        key, value = map(str.strip, line.split("=", 1))
        if key in {"PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "Table"}:
            raise InstallError("Remove custom hooks/Table/SaveConfig from a copy of the config.")
        if any(k == key for k, _ in sections[current]):
            raise InstallError(f"Duplicate parameter: {key}.")
        sections[current].append((key, value))
    if seen_sections != set(sections):
        raise InstallError("Missing [Interface] or [Peer].")
    iface, peer = (dict(sections[s]) for s in ("Interface", "Peer"))
    for key, section in (("PrivateKey", iface), ("PublicKey", peer), ("PresharedKey", peer)):
        if key == "PresharedKey" and key not in section:
            continue
        try:
            if len(base64.b64decode(section[key], validate=True)) != 32:
                raise ValueError()
        except (KeyError, ValueError):
            raise InstallError(f"Check {key}; its value is hidden.") from None
    try:
        address = ipaddress.IPv4Interface(iface["Address"])
        if address.network.prefixlen != 32:
            raise ValueError()
        dns = tuple(str(ipaddress.IPv4Address(x.strip())) for x in iface.get("DNS", "1.1.1.1,1.0.0.1").split(","))
        if len(dns) != 2 or dns[0] == dns[1] or any(not ipaddress.ip_address(x).is_global for x in dns):
            raise ValueError()
        allowed = {x.strip() for x in peer["AllowedIPs"].split(",")}
        if not ({"0.0.0.0/0"} <= allowed or {"0.0.0.0/1", "128.0.0.0/1"} <= allowed):
            raise ValueError()
        if not allowed <= {"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1"}:
            raise ValueError()
        mtu = int(iface.get("MTU", "1280"))
        if not 1280 <= mtu <= 1420:
            raise ValueError()
        host, port_text = peer["Endpoint"].rsplit(":", 1)
        port = int(port_text)
        if not 1 <= port <= 65535 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise ValueError()
        try:
            endpoint = str(ipaddress.IPv4Address(host))
        except ValueError:
            if not resolve:
                raise InstallError("Use a literal IPv4 Endpoint for --dry-run.")
            endpoint = socket.gethostbyname(host)
        if not ipaddress.IPv4Address(endpoint).is_global:
            raise ValueError()
    except (KeyError, ValueError, OSError):
        raise InstallError("Required: IPv4 Address /32, two public IPv4 DNS servers, full AllowedIPs, MTU 1280..1420 and an IPv4 Endpoint.") from None
    output = []
    for section in ("Interface", "Peer"):
        output.append(f"[{section}]")
        if section == "Interface":
            output += [f"PreUp = ip route replace {endpoint}/32 via {GATEWAY} dev {VETH}",
                       f"PostDown = ip route del {endpoint}/32 via {GATEWAY} dev {VETH} || true"]
        for key, value in sections[section]:
            if key == "AllowedIPs":
                value = "0.0.0.0/1, 128.0.0.0/1"
            if key in {"I1", "I2", "I3", "I4", "I5"}:
                def compact(match):
                    value = re.sub(r"\s", "", match[1])
                    if not value or len(value) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", value):
                        raise InstallError(f"Invalid hex in {key}; its contents are hidden.")
                    return "<b0x" + value + ">"
                value = re.sub(r"<b0x([^>]*)>", compact, value)
            output.append(f"{key} = {value}")
        if section == "Interface":
            if "DNS" not in iface:
                output.append("DNS = " + ", ".join(dns))
            if "MTU" not in iface:
                output.append(f"MTU = {mtu}")
        output.append("")
    return Config("\n".join(output), endpoint, port, dns, mtu)


def diag_rsc():
    return '''# Read-only diagnostics; no export, keys, environment or config file contents.
/system/script/add name=awg-diag policy=read,test source={
    :put "=== AWG3 diagnostics ==="
    /system/resource/print
    /system/package/print
    /system/device-mode/print
    /container/print
    /disk/print
    /system/routerboard/mode-button/print
    /system/leds/print detail where leds="user-led"
    /system/scheduler/print detail where name="awg-led"
    /routing/rule/print detail where comment~"^AWG3 "
    /ip/route/print detail where routing-table=to-awg
    /ip/firewall/filter/print stats where comment~"^AWG3 "
    /ip/firewall/nat/print stats where comment~"^AWG3 "
    /ip/firewall/mangle/print stats where comment~"^AWG3 "
    :put "For container handshake: /container/shell [find where name=awg3]"
    :put "Never share awg0.conf or showconf. Use awg show awg0 latest-handshakes."
}
'''


def led_rsc():
    # Read routing/container state; never change the VPN or probe the network.
    return '''/system/script/add name=awg-led policy=read,write,test source={
    :local led [/system/leds/find where leds="user-led"]
    :if ([:len $led] != 1) do={ :return }
    :local lit false
    :do {
        :local ct [/container/find where name="awg3"]
        :local rule [/routing/rule/find where comment="AWG3 switch LAN"]
        :if ([:len $ct] = 1 && [:len $rule] = 1) do={
            :if ([/container/get $ct running] = true && [/routing/rule/get $rule disabled] = false) do={ :set lit true }
        }
    } on-error={ :set lit false }
    :local expected "off"
    :if ($lit = true) do={ :set expected "on" }
    :if ([/system/leds/get $led type] != $expected) do={ /system/leds/set $led type=$expected }
}
'''


def toggle_rsc(settings, config):
    # The same working logic as the live router, with a generated regex for the chosen LAN.
    s, c = settings, config
    net = ipaddress.IPv4Network(s.lan)
    low, high = (str(address).split('.') for address in (net.network_address, net.broadcast_address))
    octets = []
    for first, last in zip(low, high):
        if first == last:
            octets.append(first)
        elif first == '0' and last == '255':
            octets.append('[0-9]+')
        else:
            octets.append('(' + '|'.join(str(i) for i in range(int(first), int(last) + 1)) + ')')
    pattern = '^' + '\\.'.join(octets) + '(:|$)'
    flush = f'''/ip/firewall/connection/remove [find where src-address~{ros_quote(pattern)}]
            /ip/dns/cache/flush'''
    return f'''/system/script/add name=awg-toggle policy=read,write,test source={{
    :global awgBusy
    :if ($awgBusy = true) do={{ :log warning "AWG3: operation already running"; :return }}
    :set awgBusy true
    :do {{
        :local ct [/container/find where name="{CONTAINER}"]
        :local lanRule [/routing/rule/find where comment="AWG3 switch LAN"]
        :if ([:len $ct] != 1 || [:len $lanRule] != 1) do={{ :error "AWG3 configuration incomplete" }}
        :if ([/routing/rule/get $lanRule disabled] = false) do={{
            /routing/rule/disable [find where comment~"^AWG3 switch"]
            :if ([/container/get $ct running] = true) do={{ /container/stop $ct }}
            :for attempt from=1 to={STOP_WAIT} do={{ :if ([/container/get $ct stopped] = false) do={{ :delay 1s }} }}
            :if ([/container/get $ct stopped] = false) do={{ :error "Container did not stop" }}
            /container/set $ct start-on-boot=no
            {flush}
            :log info "AWG3 OFF: normal internet"
        }} else={{
            :if ([/container/get $ct running] = true) do={{ /container/stop $ct }}
            :for attempt from=1 to={STOP_WAIT} do={{ :if ([/container/get $ct stopped] = false) do={{ :delay 1s }} }}
            :if ([/container/get $ct stopped] = false) do={{ :error "Container did not stop" }}
            /container/set $ct start-on-boot=yes
            /container/start $ct
            /routing/rule/enable [find where comment="AWG3 switch DNS1"]
            /routing/rule/enable [find where comment="AWG3 switch DNS2"]
            :local ready false
            :for attempt from=1 to={TUNNEL_ATTEMPTS} do={{
                :if ($ready = false) do={{
                    :if ([/ping address={c.dns[0]} src-address={GATEWAY} count=1] > 0) do={{ :set ready true }} else={{ :delay 2s }}
                }}
            }}
            :if ($ready = false) do={{ :error "Tunnel probe failed" }}
            /routing/rule/enable $lanRule
            {flush}
            :log info "AWG3 ON: LAN internet through VPN"
        }}
    }} on-error={{
        /routing/rule/disable [find where comment~"^AWG3 switch"]
        :do {{
            :local ct [/container/find where name="{CONTAINER}"]
            :if ([/container/get $ct running] = true) do={{ /container/stop $ct }}
            :for attempt from=1 to={STOP_WAIT} do={{ :if ([/container/get $ct stopped] = false) do={{ :delay 1s }} }}
            :if ([/container/get $ct stopped] = true) do={{ /container/set $ct start-on-boot=no }}
        }} on-error={{ :log error "AWG3: container cleanup failed" }}
        {flush}
        :log error "AWG3: toggle failed; normal internet selected; diagnostic follows"
        :do {{ /system/script/run awg-diag }} on-error={{ :log error "AWG3: diagnostic failed" }}
    }}
    :set awgBusy false
}}
'''


def make_plan(s, c):
    """Ordered create commands and matching undo; no secrets in this plan."""
    plan = []
    def add(command, undo):
        plan.append((command, undo))
    def item(menu, arguments, comment):
        add(f'{menu}/add {arguments} comment={ros_quote(comment)}',
            f'{menu}/remove [find where comment={ros_quote(comment)}]')
    add(f'/interface/veth/add name={VETH} address={CONTAINER_IP}/30 gateway={GATEWAY} comment="AWG3 container"',
        f'/interface/veth/remove [find where name={ros_quote(VETH)}]')
    item('/ip/address', f'address={GATEWAY}/30 interface={VETH}', 'AWG3 container gateway')
    add(f'/container/mounts/add list={MOUNT} src={s.disk}/awg3/config dst=/etc/amnezia/amneziawg',
        f'/container/mounts/remove [find where list={ros_quote(MOUNT)}]')
    for key, value in (("GOMEMLIMIT", GO_MEMORY_LIMIT), ("GOGC", GO_GC)):
        add(f'/container/envs/add list={ENV} key={key} value={value}',
            f'/container/envs/remove [find where list={ros_quote(ENV)} and key={ros_quote(key)}]')
    add(f'/routing/table/add name={TABLE} fib', f'/routing/table/remove [find where name={ros_quote(TABLE)}]')
    item('/ip/route', f'dst-address=0.0.0.0/0 gateway={CONTAINER_IP}@main routing-table={TABLE}', 'AWG3 default')
    for subnet in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'):
        item('/routing/rule', f'src-address={s.lan} dst-address={subnet} action=lookup-only-in-table table=main', f'AWG3 local {subnet}')
    item('/routing/rule', f'src-address={s.lan} action=lookup-only-in-table table={TABLE} disabled=yes', 'AWG3 switch LAN')
    for index, dns in enumerate(c.dns, 1):
        item('/routing/rule', f'dst-address={dns}/32 action=lookup-only-in-table table={TABLE} disabled=yes', f'AWG3 switch DNS{index}')
    # place-before=0 prepends each rule: add the drop FIRST, then the specific endpoint allow.
    item('/ip/firewall/filter', f'chain=forward action=drop in-interface={VETH} out-interface={s.wan} place-before=0', 'AWG3 prevent unencrypted fallback')
    item('/ip/firewall/filter', f'chain=forward action=accept in-interface={VETH} out-interface={s.wan} src-address={CONTAINER_IP} dst-address={c.endpoint} protocol=udp dst-port={c.port} place-before=0', 'AWG3 encrypted transport')
    item('/ip/firewall/filter', f'chain=forward action=accept in-interface={s.bridge} out-interface={VETH} src-address={s.lan} connection-state=new,established,related place-before=0', 'AWG3 LAN without FastTrack')
    item('/ip/firewall/filter', f'chain=forward action=accept in-interface={VETH} out-interface={s.bridge} dst-address={s.lan} connection-state=established,related place-before=0', 'AWG3 replies without FastTrack')
    for proto in ('udp', 'tcp'):
        item('/ip/firewall/filter', f'chain=input action=accept in-interface={VETH} src-address={CONTAINER_IP} protocol={proto} dst-port=53 place-before=0', f'AWG3 container DNS {proto}')
        item('/ip/firewall/filter', f'chain=input action=accept in-interface={s.bridge} src-address={s.lan} protocol={proto} dst-port=53 place-before=0', f'AWG3 LAN DNS {proto}')
        item('/ip/firewall/filter', f'chain=input action=drop in-interface={s.wan} protocol={proto} dst-port=53 place-before=0', f'AWG3 block WAN DNS {proto}')
    item('/ip/firewall/nat', f'chain=srcnat action=masquerade out-interface={VETH} src-address={s.lan} place-before=0', 'AWG3 traffic to container')
    item('/ip/firewall/nat', f'chain=srcnat action=masquerade src-address={CONTAINER_IP} dst-address={c.endpoint} protocol=udp dst-port={c.port} out-interface={s.wan} place-before=0', 'AWG3 endpoint NAT')
    mss = c.mtu - 40
    item('/ip/firewall/mangle', f'chain=forward action=change-mss out-interface={VETH} protocol=tcp tcp-flags=syn tcp-mss={mss + 1}-65535 new-mss={mss} passthrough=yes', 'AWG3 TCP MSS')
    add(diag_rsc().strip(), '/system/script/remove [find where name="awg-diag"]')
    add(toggle_rsc(s, c).strip(), '/system/script/remove [find where name="awg-toggle"]')
    if s.bind_led:
        add('/system/leds/add leds=user-led type=off', '/system/leds/remove [find where leds="user-led"]')
        add(led_rsc().strip(), '/system/script/remove [find where name="awg-led"]')
        add(f'/system/scheduler/add name=awg-led interval={LED_INTERVAL} start-time=00:00:00 on-event=awg-led policy=read,write,test',
            '/system/scheduler/remove [find where name="awg-led"]')
    return plan


def download(url, token=None):
    headers = {'User-Agent': f'awg-mikrotik/{VERSION}', 'Accept': 'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise InstallError("The image file exceeds the download limit.")
    return data


def checked_blob(data, digest):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest) or hashlib.sha256(data).hexdigest() != digest[7:]:
        raise InstallError("Image SHA256 mismatch. Installation stopped.")
    return data


def build_image(target):
    print("Downloading the pinned ARMv7 image and verifying SHA256 for every layer...")
    token_url = 'https://auth.docker.io/token?' + urllib.parse.urlencode({'service': 'registry.docker.io', 'scope': f'repository:{IMAGE_REPO}:pull'})
    token = json.loads(download(token_url))['token']
    base = f'https://registry-1.docker.io/v2/{IMAGE_REPO}'
    manifest_bytes = checked_blob(download(f'{base}/manifests/{IMAGE_DIGEST}', token), IMAGE_DIGEST)
    manifest = json.loads(manifest_bytes)
    config_desc = manifest['config']
    config_bytes = checked_blob(download(f"{base}/blobs/{config_desc['digest']}", token), config_desc['digest'])
    meta = json.loads(config_bytes)
    if meta.get('architecture') != 'arm' or meta.get('os') != 'linux' or meta.get('variant', 'v7') != 'v7':
        raise InstallError("The image platform is not ARMv7/Linux.")
    index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [{'mediaType': manifest['mediaType'], 'digest': IMAGE_DIGEST, 'size': len(manifest_bytes), 'platform': {'architecture': 'arm', 'os': 'linux', 'variant': 'v7'}}]}
    with tarfile.open(target, 'w', format=tarfile.USTAR_FORMAT) as archive:
        def put(path, data):
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            archive.addfile(info, io.BytesIO(data))
        put('oci-layout', b'{"imageLayoutVersion":"1.0.0"}')
        put('index.json', json.dumps(index, separators=(',', ':')).encode())
        put('blobs/sha256/' + IMAGE_DIGEST[7:], manifest_bytes)
        put('blobs/sha256/' + config_desc['digest'][7:], config_bytes)
        for layer in manifest['layers']:
            data = checked_blob(download(f"{base}/blobs/{layer['digest']}", token), layer['digest'])
            if len(data) != layer['size']:
                raise InstallError("Layer size mismatch.")
            put('blobs/sha256/' + layer['digest'][7:], data)
    return target


class Router:
    def __init__(self, args):
        try:
            import paramiko
        except ImportError:
            raise InstallError("Paramiko is missing. Run install.sh / install.ps1 or install paramiko==4.0.0 in a venv.") from None
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        known = Path.home() / '.ssh' / 'known_hosts'
        if known.exists():
            self.client.load_host_keys(str(known))
        class VerifyHost(paramiko.MissingHostKeyPolicy):
            def missing_host_key(policy, client, hostname, key):
                fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
                confirm(f'New SSH server: {hostname}.\nFingerprint: {fingerprint}\nCompare it with a trusted connection to your MikroTik.')
                known.parent.mkdir(parents=True, exist_ok=True)
                client.get_host_keys().add(hostname, key.get_name(), key)
                client.save_host_keys(str(known))
        self.client.set_missing_host_key_policy(VerifyHost())
        password = getpass.getpass('MikroTik password (hidden): ')
        try:
            self.client.connect(args.host, port=args.port, username=args.user, password=password,
                                look_for_keys=False, allow_agent=False, timeout=SSH_TIMEOUT,
                                auth_timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT)
        except BaseException:
            self.client.close()
            raise
        finally:
            del password

    def run(self, command, timeout=30):
        # RouterOS may return exit status 0 for failed commands. Require the success marker too.
        wrapped = ':do { ' + command + '; :put "__AWG_OK__" } on-error={ :put "__AWG_ERROR__" }'
        stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout)
        stdin.close()
        output = stdout.read().decode('utf-8', 'replace') + stderr.read().decode('utf-8', 'replace')
        status = stdout.channel.recv_exit_status()
        clean = scrub(output.replace('__AWG_OK__', '')).strip()
        if status or '__AWG_OK__' not in output or '__AWG_ERROR__' in output:
            raise InstallError('RouterOS rejected a command: ' + scrub(command[:250]) + '\n' + clean)
        return clean

    def get(self, menu, prop, where=None):
        item = f' [find where {where}]' if where else ''
        return self.run(f':put [{menu}/get{item} {prop}]').strip()

    def count(self, menu, where=None):
        condition = ' where ' + where if where else ''
        return int(self.run(f':put [:len [{menu}/find{condition}]]'))

    def shell(self, command, timeout=45):
        transport = self.client.get_transport()
        channel = transport.open_session(timeout=SSH_TIMEOUT)
        channel.get_pty(term='dumb', width=200, height=40)
        channel.exec_command('/container/shell [/container/find where name="awg3"]')
        output = ''
        deadline = time.monotonic() + timeout
        sent = False
        marker = '__AWG_SHELL_DONE__'
        try:
            while time.monotonic() < deadline:
                if channel.recv_ready():
                    output += channel.recv(65536).decode('utf-8', 'replace')
                    if not sent and re.search(r'(?:^|\n)[^\n]*[#$]\s*$', ANSI.sub('', output).replace('\r', '')):
                        # A literal marker on a separate line distinguishes command echo from output.
                        channel.send(command + "; printf '\\n__AWG_SHELL_%s__\\n' DONE; exit\n")
                        sent = True
                    if re.search(r'(?m)^' + marker + r'\s*$', ANSI.sub('', output).replace('\r', '')):
                        return scrub(output)
                if channel.exit_status_ready() and not channel.recv_ready():
                    break
                time.sleep(0.1)
            raise InstallError('Container console timed out.\n' + scrub(output[-2000:]))
        finally:
            channel.close()

    def upload(self, local, remote):
        with self.client.open_sftp() as sftp:
            # / is RouterOS Files root, not the router's SPI flash folder.
            remote = '/' + remote.lstrip('/')
            sftp.put(str(local), remote)
            if sftp.stat(remote).st_size != Path(local).stat().st_size:
                raise InstallError('Uploaded file size mismatch.')

    def close(self):
        self.client.close()


DIAG_COMMANDS = (
    ('Resources', '/system/resource/print'),
    ('Packages', '/system/package/print'),
    ('Device mode', '/system/device-mode/print'),
    ('Container', '/container/print'),
    ('USB', '/disk/print'),
    ('Mode button', '/system/routerboard/mode-button/print'),
    ('User LED', '/system/leds/print detail where leds="user-led"'),
    ('LED settings', '/system/leds/settings/print'),
    ('LED scheduler', '/system/scheduler/print detail where name="awg-led"'),
    ('LAN addresses', '/ip/address/print'),
    ('WAN DHCP', '/ip/dhcp-client/print'),
    ('Main default', '/ip/route/print detail where dst-address=0.0.0.0/0 and routing-table=main'),
    ('AWG routes', '/ip/route/print detail where routing-table=to-awg'),
    ('AWG rules', '/routing/rule/print detail where comment~"^AWG3 "'),
    ('AWG filter', '/ip/firewall/filter/print stats where comment~"^AWG3 "'),
    ('AWG NAT', '/ip/firewall/nat/print stats where comment~"^AWG3 "'),
    ('AWG MSS', '/ip/firewall/mangle/print stats where comment~"^AWG3 "'),
    ('IPv6 default', '/ipv6/route/print where dst-address="::/0"'),
    ('AWG logs', '/log/print where message~"AWG3"'),
)


def diagnostics(router, report):
    print('\nCollecting diagnostics without keys or configuration contents...')
    parts = [f'AWG MikroTik {VERSION} | {time.strftime("%Y-%m-%d %H:%M:%S")}']
    for label, command in DIAG_COMMANDS:
        try:
            output = router.run(command)
        except Exception as exc:
            output = 'CHECK FAILED: ' + scrub(exc)
        parts.append(f'\n=== {label} ===\n{output}')
    try:
        if router.get('/container', 'running', 'name="awg3"') == 'true':
            command = "printf 'HANDSHAKE_EPOCH\\n'; awg show awg0 latest-handshakes | awk '{print $2}'; printf 'TRANSFER_RX_TX\\n'; awg show awg0 transfer | awk '{print $2, $3}'; printf 'INTERNET_ROUTE\\n'; ip route get 1.1.1.1; printf 'MEMORY\\n'; free -m"
            parts.append('\n=== Container health ===\n' + router.shell(command))
    except Exception as exc:
        parts.append('\n=== Container health ===\n' + scrub(exc))
    result = scrub('\n'.join(parts))
    secure_write(report, result + '\n')
    print(result)
    print(f'\nReport saved: {report}')
    return result


def preflight(router, s):
    version = router.get('/system/resource', 'version').split()[0]
    if version != TESTED_ROS or router.get('/system/resource', 'architecture-name') != 'arm':
        raise InstallError(f'This installer targets ARM/hAP ac2, RouterOS {TESTED_ROS}; found {version}. Other versions need syntax validation.')
    if router.get('/system/resource', 'board-name') != TESTED_BOARD:
        raise InstallError('This profile supports only hAP ac2.')
    if router.count('/system/package', 'name="container" and disabled=no') != 1:
        raise InstallError('Install the matching container package via System -> Packages. This installer does not remove wireless or upgrade RouterOS.')
    if router.get('/system/device-mode', 'container') != 'true':
        raise InstallError('In WebFig Terminal: /system/device-mode/update container=yes routerboard=yes\nBriefly press Mode next to USB, wait for reboot and run the installer again.')
    if s.bind_mode and router.get('/system/device-mode', 'routerboard') != 'true':
        raise InstallError('Run /system/device-mode/update routerboard=yes and physically confirm with Mode.')
    if router.get('/system/device-mode', 'flagged') == 'true':
        raise InstallError('device-mode flagged=yes: audit the router configuration first.')
    for interface in (s.bridge, s.wan):
        if router.count('/interface', f'name={ros_quote(interface)}') != 1:
            raise InstallError(f'Interface not found: {interface}.')
    if router.count('/interface/bridge', f'name={ros_quote(s.bridge)}') != 1:
        raise InstallError('The LAN interface must be a bridge.')
    addresses = router.run(f':foreach id in=[/ip/address/find where interface={ros_quote(s.bridge)} and disabled=no] do={{ :put [/ip/address/get $id address] }}').splitlines()
    if not any(ipaddress.IPv4Interface(x.strip()).network == ipaddress.IPv4Network(s.lan) for x in addresses):
        raise InstallError('The selected LAN network does not match the bridge address.')
    if router.count('/ip/dhcp-client', f'interface={ros_quote(s.wan)} and status="bound" and disabled=no') != 1:
        raise InstallError('This profile requires one WAN DHCP client in bound state.')
    if router.count('/ip/route', 'dst-address="0.0.0.0/0" and routing-table=main and active=yes') != 1:
        raise InstallError('One active default route in main is required.')
    if router.count('/ipv6/route', 'dst-address="::/0" and active=yes'):
        raise InstallError('IPv6 internet is active; this profile is IPv4-only. Handle IPv6 routing or blocking separately first.')
    if router.count('/ip/firewall/mangle', 'action=mark-routing and disabled=no') or router.count('/routing/rule'):
        raise InstallError('Existing policy routing or mark-routing detected. Manual integration is required; existing policies are preserved.')
    if router.count('/ip/firewall/filter') == 0 or router.count('/ip/firewall/nat') == 0:
        raise InstallError('Existing basic routing, firewall and NAT are required.')
    if router.count('/ip/firewall/raw', 'disabled=no'):
        raise InstallError('Raw firewall rules exist; manually check compatibility with VETH.')
    if router.count('/ip/firewall/filter', 'comment~"^AWG3 "') or router.count('/ip/firewall/nat', 'comment~"^AWG3 "') or router.count('/ip/firewall/mangle', 'comment~"^AWG3 "'):
        raise InstallError('AWG3 objects already exist. Use --diag or the rollback journal instead of installing over them.')
    if int(router.get('/system/resource', 'free-memory')) < MIN_RAM_FREE:
        raise InstallError('Free RAM is below 24 MiB.')
    for menu, where in (('/interface', f'name={ros_quote(VETH)}'), ('/routing/table', f'name={ros_quote(TABLE)}'),
                        ('/container', 'name="awg3"'), ('/container/mounts', f'list={ros_quote(MOUNT)}'),
                        ('/container/envs', f'list={ros_quote(ENV)}'),
                        ('/system/script', 'name="awg-toggle" or name="awg-diag"')):
        if router.count(menu, where):
            raise InstallError('Existing AWG configuration detected. Use --diag; repeat installation stopped.')
    if s.bind_led:
        if router.count('/system/leds', 'leds="user-led"') or router.count('/system/script', 'name="awg-led"') or router.count('/system/scheduler', 'name="awg-led"'):
            raise InstallError('User LED or awg-led objects are already assigned. Use --no-led to preserve them, or integrate manually.')
        if router.get('/system/leds/settings', 'all-leds-off') != 'never':
            raise InstallError('LED dark mode is enabled. Use --no-led or disable dark mode in System -> LEDs -> Settings first.')
    if router.count('/container'):
        raise InstallError('Other containers exist; shared RAM and DNS policy need a separate review.')
    addresses = router.run(':foreach id in=[/ip/address/find] do={ :put [/ip/address/get $id address] }').splitlines()
    if any(ipaddress.IPv4Interface(x.strip()).network.overlaps(TRANSIT) for x in addresses):
        raise InstallError('The 172.18.20.0/30 subnet is already in use.')


def prepare_disk(router, s):
    where = f'slot={ros_quote(s.disk)}'
    if router.count('/disk', where) != 1:
        raise InstallError('USB partition not found. Check /disk/print detail.')
    print(router.run(f'/disk/print detail where {where}'))
    if router.get('/disk', 'fs', where) != 'ext4':
        confirm(f'Formatting {s.disk} as ext4 will DELETE ALL files on that partition.', f'ERASE {s.disk}')
        router.run(f'/disk/format [find where {where}] file-system=ext4', timeout=180)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if router.get('/disk', 'mounted', where) == 'true' and router.get('/disk', 'fs', where) == 'ext4':
                break
            time.sleep(2)
        else:
            raise InstallError('USB did not mount after formatting.')
    if router.get('/disk', 'mount-point', where).strip('/') != s.disk:
        raise InstallError('Nonstandard USB mount point; manual preparation is required.')
    if router.get('/disk', 'mounted', where) != 'true' or int(router.get('/disk', 'free', where)) < MIN_DISK_FREE:
        raise InstallError('USB is not mounted or has less than 256 MiB free.')
    if router.count('/file', f'name={ros_quote(s.disk + "/awg3")}'):
        raise InstallError('The awg3 directory already exists. A previous installation will not be overwritten.')


def wait_stopped(router):
    deadline = time.monotonic() + EXTRACT_TIMEOUT
    while time.monotonic() < deadline:
        if router.get('/container', 'stopped', 'name="awg3"') == 'true':
            return
        time.sleep(2)
    raise InstallError('Container did not reach stopped state within 300 seconds.')


def rollback(router, undo, report):
    print('Reverting settings changed by this run...')
    failures = []
    try:
        router.run('/routing/rule/disable [find where comment~"^AWG3 switch"]')
    except Exception as exc:
        failures.append(scrub(exc))
    try:
        if router.count('/container', 'name="awg3"'):
            if router.get('/container', 'running', 'name="awg3"') == 'true':
                router.run('/container/stop [find where name="awg3"]')
            wait_stopped(router)
    except Exception as exc:
        failures.append(scrub(exc))
    for command in reversed(undo):
        try:
            router.run(command, timeout=60)
        except Exception as exc:
            failures.append(scrub(exc))
    if failures:
        secure_write(str(report) + '.rollback.txt', '\n'.join(failures))
        print('Rollback is incomplete; see the .rollback.txt report and backup.')
    else:
        print('Network settings restored. USB files and backups retained for investigation.')
    return failures


def install(router, args, s, c, work):
    preflight(router, s)
    print(f'LAN {s.lan} ({s.bridge}) -> AWG; WAN {s.wan}; USB {s.disk}.')
    print('Local private networks stay in main. Endpoint and keys come from your config file.')
    confirm('Create an AWG container, change DNS and route all LAN IPv4 internet through AWG?' +
            ('\nMode will run awg-toggle. Reset/WPS is preserved.' if s.bind_mode else '') +
            ('\nThe free user-led will show container running + LAN VPN selected.' if s.bind_led else ''))
    prepare_disk(router, s)
    image = build_image(work / 'awg3-arm.tar')
    undo = []
    journal = work / 'rollback.json'
    def change(command, revert):
        # Record the undo BEFORE sending the mutation, to handle a lost SSH response.
        undo.append(revert)
        secure_write(journal, json.dumps({'host': args.host, 'undo': undo}, ensure_ascii=False, indent=2))
        router.run(command, timeout=60)
    timestamp = time.strftime('%Y%m%d-%H%M%S')
    backup = f'{s.disk}/before-awg-{timestamp}'
    router.run(f'/system/backup/save name={ros_quote(backup)}')
    router.run(f'/export file={ros_quote(backup)}')
    with router.client.open_sftp() as sftp:
        for extension in ('.backup', '.rsc'):
            target = work / ('before-awg' + extension)
            sftp.get('/' + backup + extension, str(target))
            os.chmod(target, 0o600)
    print(f'Backup saved on USB and in {work}.')
    try:
        for directory in ('awg3', 'awg3/config', 'awg3/tmp'):
            router.run(f'/file/add type=directory name={ros_quote(s.disk + "/" + directory)}')
        config_path = secure_write(work / 'awg0.conf', c.text)
        router.upload(config_path, f'{s.disk}/awg3/config/awg0.conf')
        config_path.unlink()
        router.upload(image, f'{s.disk}/awg3/awg3-arm.tar')
        # Do not change global container/config paths: per-container layer-dir is enough for file import.
        for command, revert in make_plan(s, c):
            change(command, revert)
        old_dns = router.get('/ip/dns', 'servers')
        old_remote = ros_bool(router.get('/ip/dns', 'allow-remote-requests'))
        old_peer = ros_bool(router.get('/ip/dhcp-client', 'use-peer-dns', f'interface={ros_quote(s.wan)}'))
        change(f'/ip/dhcp-client/set [find where interface={ros_quote(s.wan)}] use-peer-dns=no',
               f'/ip/dhcp-client/set [find where interface={ros_quote(s.wan)}] use-peer-dns={old_peer}')
        change('/ip/dns/set servers=' + ','.join(c.dns) + ' allow-remote-requests=yes',
               f'/ip/dns/set servers={ros_quote(old_dns)} allow-remote-requests={old_remote}')
        change(f'/container/add name={CONTAINER} hostname=amnezia interface={VETH} mountlists={MOUNT} envlists={ENV} root-dir={s.disk}/awg3/root layer-dir={s.disk}/awg3/layers logging=yes start-on-boot=no dns={GATEWAY} memory-high={MEMORY_HIGH} memory-max={MEMORY_MAX} file={s.disk}/awg3/awg3-arm.tar',
               '/container/remove [find where name="awg3"]')
        wait_stopped(router)
        router.run('/container/start [find where name="awg3"]')
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if router.get('/container', 'running', 'name="awg3"') == 'true':
                break
            time.sleep(1)
        else:
            raise InstallError('Container did not start within 45 seconds.')
        # AllowedIPs /1 routes + endpoint /32 must be established before LAN is moved.
        health = router.shell("chmod 600 /etc/amnezia/amneziawg/awg0.conf; sleep 3; printf 'VPN_ROUTE\\n'; ip route get 1.1.1.1; printf 'PING_RESULT\\n'; ping -c 3 -W 3 1.1.1.1; printf 'HANDSHAKE_EPOCH\\n'; awg show awg0 latest-handshakes | awk '{print $2}'")
        epochs = re.findall(r'(?m)^\s*(\d{9,12})\s*$', health)
        if not epochs or int(epochs[-1]) == 0 or 'dev awg0' not in health or '0% packet loss' not in health or '100% packet loss' in health:
            raise InstallError('AWG handshake and the route through awg0 were not confirmed.\n' + health)
        if s.bind_mode:
            old_mode = {key: router.get('/system/routerboard/mode-button', key) for key in ('enabled', 'hold-time', 'on-event')}
            restore = '/system/routerboard/mode-button/set enabled=' + ros_bool(old_mode['enabled']) + ' ' + ' '.join(key + '=' + ros_quote(old_mode[key]) for key in ('hold-time', 'on-event'))
            change('/system/routerboard/mode-button/set enabled=yes hold-time=0s..3s on-event=awg-toggle', restore)
        # The toggle handles stopping BEFORE changing start-on-boot; otherwise RouterOS restarts it.
        router.run('/system/script/run awg-toggle', timeout=120)
        if router.get('/routing/rule', 'disabled', 'comment="AWG3 switch LAN"') != 'false':
            raise InstallError('The script did not enable LAN policy. Check diagnostics.')
        if s.bind_led:
            router.run('/system/script/run awg-led')
            if router.get('/system/leds', 'type', 'leds="user-led"') != 'on':
                raise InstallError('The AWG LED did not turn on. Check diagnostics.')
        after = f'{s.disk}/after-awg-{timestamp}'
        router.run(f'/system/backup/save name={ros_quote(after)}')
        router.run(f'/export file={ros_quote(after)}')
        secure_write(work / 'installed.json', json.dumps({'version': VERSION, 'host': args.host, 'image': IMAGE_DIGEST, 'usb_backup': after}, indent=2))
        print('AWG is ON. Check the public IP on a device connected to MikroTik LAN/Wi-Fi.')
        if s.bind_mode:
            print('Mode next to USB: short press toggles VPN / normal internet. Startup usually takes 10-20 seconds.')
        if s.bind_led:
            print('USR LED: ON means container running + LAN VPN selected. OFF means disabled/stopped. Updates every 3 seconds; not a handshake monitor.')
        print('The installer PC public IP does not prove the route used by other LAN devices.')
    except BaseException:
        # Capture the failed state BEFORE rollback changes it; do not hide the original exception.
        try:
            diagnostics(router, work / 'failure-before-rollback.txt')
        except Exception:
            pass
        rollback(router, undo, work / 'failure-before-rollback.txt')
        raise
    finally:
        (work / 'awg0.conf').unlink(missing_ok=True)


def parser():
    p = argparse.ArgumentParser(description='AWG 3 on hAP ac2 / RouterOS 7.24.5; runs on a PC, not inside RouterOS.')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--diag', action='store_true', help='read-only diagnostics; no VPN config required')
    mode.add_argument('--dry-run', action='store_true', help='validate config and generate RSC without connecting to the router')
    mode.add_argument('--rollback', type=Path, help='revert changes using the rollback.json journal from this installer')
    p.add_argument('--host', help='MikroTik IP/hostname')
    p.add_argument('--port', type=int, default=22)
    p.add_argument('--user', default='admin')
    p.add_argument('--config', type=Path)
    p.add_argument('--lan', help='LAN subnet, for example 192.168.3.0/24')
    p.add_argument('--bridge', help='LAN bridge')
    p.add_argument('--wan', help='WAN DHCP interface')
    p.add_argument('--disk', help='USB partition slot')
    p.add_argument('--no-mode', action='store_true')
    p.add_argument('--no-led', action='store_true', help='preserve the current LED configuration')
    p.add_argument('--output', type=Path, help='report/backup directory; default: current directory/awg-run-TIMESTAMP')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    work = args.output or Path.cwd() / ('awg-run-' + time.strftime('%Y%m%d-%H%M%S'))
    work.mkdir(parents=True, exist_ok=True)
    report = work / 'diagnostics.txt'
    router = None
    try:
        if args.diag or args.rollback:
            args.host = args.host or ask('MikroTik IP', '192.168.3.1')
        else:
            s = Settings(args.lan or ask('LAN subnet', '192.168.3.0/24'), args.bridge or ask('LAN bridge', 'bridge'),
                         args.wan or ask('WAN DHCP interface', 'ether1'), args.disk or ask('USB partition', 'usb1-part1'), not args.no_mode, not args.no_led).validate()
            args.config = args.config or Path(ask('Path to your AWG .conf on this PC'))
            c = parse_config(args.config, resolve=not args.dry_run)
            if args.dry_run:
                secure_write(work / 'prepare.rsc', '\n'.join(command for command, _ in make_plan(s, c)) + '\n')
                secure_write(work / 'toggle.rsc', toggle_rsc(s, c))
                secure_write(work / 'diagnostics.rsc', diag_rsc())
                print(f'Config validated. Commands without private keys: {work}. No connections or changes were made.')
                return 0
            args.host = args.host or ask('MikroTik IP', '192.168.3.1')
        router = Router(args)
        if args.diag:
            diagnostics(router, report)
        elif args.rollback:
            data = json.loads(args.rollback.read_text(encoding='utf-8'))
            if data['host'] != args.host or not isinstance(data['undo'], list):
                raise InstallError('The journal belongs to another router or is invalid.')
            confirm('Run rollback commands from this local journal? Use only your own trusted journal.')
            failures = rollback(router, data['undo'], report)
            diagnostics(router, report)
            return 1 if failures else 0
        else:
            install(router, args, s, c, work)
            diagnostics(router, report)
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        message = 'Stopped by user.' if isinstance(exc, KeyboardInterrupt) else scrub(exc)
        secure_write(work / 'error.txt', message + '\n')
        print('\nERROR: ' + message, file=sys.stderr)
        if router:
            try:
                diagnostics(router, report)
            except Exception as diag_exc:
                secure_write(report, 'SSH/diagnostics unavailable: ' + scrub(diag_exc) + '\n')
                print('SSH unavailable; details saved in diagnostics.txt.', file=sys.stderr)
        else:
            secure_write(report, 'SSH not connected. Check access, IP/port, password and Paramiko.\n' + message + '\n')
        print(f'Reports: {work}', file=sys.stderr)
        return 1
    finally:
        if router:
            router.close()


if __name__ == '__main__':
    sys.exit(main())

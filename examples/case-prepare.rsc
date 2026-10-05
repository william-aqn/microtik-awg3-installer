# Reproduces the final manual case. USB/config/image/package/device-mode must be prepared first.
# Fresh installation only. Replace the example Endpoint below before import.
:local vpnEndpoint "203.0.113.10"
:local vpnPort 39423
:if ($vpnEndpoint = "203.0.113.10") do={ :error "Replace the documentation Endpoint before import" }
:if ([:len [/interface/find where name="docker-awg-veth"]] > 0) do={ :error "AWG VETH already exists; do not import twice" }
# AWG3 preparation; internet policy remains disabled until validation.
/interface/veth/add name=docker-awg-veth address=172.18.20.2/30 gateway=172.18.20.1 comment="AWG3 container"
/ip/address/add address=172.18.20.1/30 interface=docker-awg-veth comment="AWG3 container gateway"
/file/add type=directory name=usb1-part1/wg
/file/add type=directory name=usb1-part1/pull
/container/config/set tmpdir=usb1-part1/pull layer-dir=usb1-part1/awg-layers
/container/mounts/add list=awg_conf src=usb1-part1/wg dst=/etc/amnezia/amneziawg
/container/envs/add list=awg_env key=GOMEMLIMIT value=24MiB
/container/envs/add list=awg_env key=GOGC value=50
/routing/table/add name=to-awg fib
/ip/route/add dst-address=0.0.0.0/0 gateway=172.18.20.2@main routing-table=to-awg comment="AWG3 default"
/routing/rule/add src-address=192.168.3.0/24 dst-address=10.0.0.0/8 action=lookup-only-in-table table=main comment="AWG3 local networks"
/routing/rule/add src-address=192.168.3.0/24 dst-address=172.16.0.0/12 action=lookup-only-in-table table=main comment="AWG3 local networks"
/routing/rule/add src-address=192.168.3.0/24 dst-address=192.168.0.0/16 action=lookup-only-in-table table=main comment="AWG3 local networks"
/routing/rule/add src-address=192.168.3.0/24 action=lookup-only-in-table table=to-awg disabled=yes comment="AWG3 switch LAN"
/routing/rule/add dst-address=1.1.1.1/32 action=lookup-only-in-table table=to-awg disabled=yes comment="AWG3 switch DNS1"
/routing/rule/add dst-address=1.0.0.1/32 action=lookup-only-in-table table=to-awg disabled=yes comment="AWG3 switch DNS2"
/ip/firewall/filter/add chain=input action=accept in-interface=docker-awg-veth src-address=172.18.20.2 protocol=udp dst-port=53 place-before=0 comment="AWG3 container DNS UDP"
/ip/firewall/filter/add chain=input action=accept in-interface=docker-awg-veth src-address=172.18.20.2 protocol=tcp dst-port=53 place-before=0 comment="AWG3 container DNS TCP"
/ip/firewall/filter/add chain=forward action=accept in-interface=bridge src-address=192.168.3.0/24 out-interface=docker-awg-veth connection-state=new,established,related place-before=0 comment="AWG3 LAN without FastTrack"
/ip/firewall/filter/add chain=forward action=accept in-interface=docker-awg-veth out-interface=bridge dst-address=192.168.3.0/24 connection-state=established,related place-before=0 comment="AWG3 replies without FastTrack"
/ip/firewall/filter/add chain=forward action=drop in-interface=docker-awg-veth out-interface-list=WAN place-before=0 comment="AWG3 prevent unencrypted fallback"
/ip/firewall/filter/add chain=forward action=accept in-interface=docker-awg-veth out-interface-list=WAN src-address=172.18.20.2 dst-address=$vpnEndpoint protocol=udp dst-port=$vpnPort place-before=0 comment="AWG3 encrypted transport"
/ip/firewall/nat/add chain=srcnat action=masquerade out-interface=docker-awg-veth comment="AWG3 traffic to container"
/ip/firewall/mangle/add chain=forward action=change-mss out-interface=docker-awg-veth protocol=tcp tcp-flags=syn tcp-mss=1241-65535 new-mss=1240 passthrough=yes comment="AWG3 MTU1280 MSS1240"
:put "AWG3 preparation complete; LAN routing is OFF"

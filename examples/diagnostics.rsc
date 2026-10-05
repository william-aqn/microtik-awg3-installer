# Read-only diagnostics; no export, keys, environment or config file contents.
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

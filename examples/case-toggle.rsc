# DNS for LAN clients is sent through AWG when VPN is enabled.
/ip/dhcp-client/set [find where interface=ether1] use-peer-dns=no
/ip/dns/set servers=1.1.1.1,1.0.0.1
/system/script/set [find where name="awg-toggle"] policy=read,write,test source={
    :global awgBusy
    :if ($awgBusy = true) do={ :log warning "AWG3: button operation already running"; :return }
    :set awgBusy true
    :do {
        :local ct [/container/find where name="awg3"]
        :local lanRule [/routing/rule/find where comment="AWG3 switch LAN"]
        :if ([:len $ct] != 1 || [:len $lanRule] != 1) do={ :error "AWG3 configuration is incomplete" }
        :if ([/routing/rule/get $lanRule disabled] = false) do={
            /routing/rule/disable [find where comment~"^AWG3 switch"]
            :if ([/container/get $ct running] = true) do={ /container/stop $ct }
            :for attempt from=1 to=12 do={ :if ([/container/get $ct stopped] = false) do={ :delay 1s } }
            :if ([/container/get $ct stopped] = false) do={ :error "AWG3 container did not stop" }
            /container/set $ct start-on-boot=no
            /ip/firewall/connection/remove [find where src-address~"^192\\.168\\.3\\."]
            /ip/dns/cache/flush
            :log info "AWG3 OFF: normal internet"
        } else={
            :if ([/container/get $ct running] = true) do={ /container/stop $ct }
            :for attempt from=1 to=12 do={ :if ([/container/get $ct stopped] = false) do={ :delay 1s } }
            :if ([/container/get $ct stopped] = false) do={ :error "AWG3 container did not stop" }
            /container/set $ct start-on-boot=yes
            /container/start $ct
            /routing/rule/enable [find where comment="AWG3 switch DNS1"]
            /routing/rule/enable [find where comment="AWG3 switch DNS2"]
            :local ready false
            :for attempt from=1 to=20 do={
                :if ($ready = false) do={
                    :if ([/ping address=1.1.1.1 src-address=172.18.20.1 count=1] > 0) do={ :set ready true } else={ :delay 2s }
                }
            }
            :if ($ready = true) do={
                /routing/rule/enable $lanRule
                /ip/firewall/connection/remove [find where src-address~"^192\\.168\\.3\\."]
                /ip/dns/cache/flush
                :log info "AWG3 ON: LAN internet through VPN"
            } else={
                /routing/rule/disable [find where comment~"^AWG3 switch"]
                :if ([/container/get $ct running] = true) do={ /container/stop $ct }
                :for attempt from=1 to=12 do={ :if ([/container/get $ct stopped] = false) do={ :delay 1s } }
                /container/set $ct start-on-boot=no
                :log error "AWG3: tunnel check failed; VPN remains OFF"
            }
        }
    } on-error={ :log error "AWG3: toggle failed; inspect container and routing rules" }
    :set awgBusy false
}
/system/routerboard/mode-button/set enabled=yes hold-time=0s..3s on-event=awg-toggle
:put "AWG3 Mode button configured"

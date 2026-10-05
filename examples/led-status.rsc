# Fresh addition only: user-led, awg-led script and scheduler must be free.
:if ([:len [/system/leds/find where leds="user-led"]] > 0) do={ :error "user-led is already assigned" }
:if ([:len [/system/script/find where name="awg-led"]] > 0 || [:len [/system/scheduler/find where name="awg-led"]] > 0) do={ :error "awg-led already exists" }
/system/leds/add leds=user-led type=off
/system/script/add name=awg-led policy=read,write,test source={
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
/system/scheduler/add name=awg-led interval=3s start-time=00:00:00 on-event=awg-led policy=read,write,test
/system/script/run awg-led

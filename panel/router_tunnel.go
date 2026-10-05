package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func (r *Router) Configure(ctx context.Context, c VPNConfig, endpoint string) error {
	ep, e := netip.ParseAddr(endpoint)
	if e != nil || !publicIPv4(ep) {
		return errors.New("Invalid resolved endpoint")
	}
	addr, _ := netip.ParsePrefix(c.Address)
	lan, _ := netip.ParsePrefix(r.settings.LAN)
	if lan.Contains(addr.Addr()) || netip.MustParsePrefix("172.18.20.0/30").Overlaps(addr) {
		return errors.New("Tunnel address overlaps LAN or container management")
	}
	var b strings.Builder
	b.WriteString(`:if ([:len [/ip/firewall/filter/find where comment="AWGC encrypted transport"]] != 1 || [:len [/ip/firewall/nat/find where comment="AWGC endpoint NAT"]] != 1) do={ :error "Transport integration missing" };` + "\n")
	fmt.Fprintf(&b, "/ip/firewall/filter/set [find where comment=\"AWGC encrypted transport\"] dst-address=%s dst-port=%d;\n", endpoint, c.Port)
	fmt.Fprintf(&b, "/ip/firewall/nat/set [find where comment=\"AWGC endpoint NAT\"] dst-address=%s dst-port=%d;\n", endpoint, c.Port)
	fmt.Fprintf(&b, "/ip/firewall/mangle/set [find where comment=\"AWGC TCP MSS\"] new-mss=%d tcp-mss=%d-65535;\n", c.MTU-40, c.MTU-39)
	b.WriteString("/routing/rule/remove [find where comment~\"^AWGC DNS \"];\n")
	for i, dns := range c.DNS {
		fmt.Fprintf(&b, "/routing/rule/add dst-address=%s/32 action=lookup-only-in-table table=to-awg comment=\"AWGC DNS %d\";\n", dns, i+1)
	}
	b.WriteString("/ip/dns/set servers=" + strings.Join(c.DNS, ",") + ";\n")
	return r.script(ctx, "awg-control-configure", b.String())
}
func (r *Router) Gate(ctx context.Context, on bool) error {
	enabled := "enable"
	disabled := "no"
	if !on {
		enabled = "disable"
		disabled = "yes"
	}
	source := `:local entry [/ip/firewall/mangle/find where comment~"^AWG3UI entry "]; :if ([:len $entry] != 1) do={ :error "Policy entry missing" };` + "\n"
	source += "/ip/firewall/mangle/set $entry disabled=" + disabled + ";\n/routing/rule/" + enabled + " [find where comment~\"^AWGC DNS \"];\n" + flushConnections(r.settings.LAN)
	return r.script(ctx, "awg-control-gate", source)
}
func (r *Router) LED(ctx context.Context, on bool) error {
	jobs, e := r.rows(ctx, "system/script/job", "script", "script=awg-mode")
	if e != nil {
		return e
	}
	if len(jobs) > 0 {
		return nil
	}
	rows, e := r.rows(ctx, "system/leds", ".id,type", "leds=user-led")
	if e != nil {
		return e
	}
	if len(rows) != 1 {
		return nil
	}
	kind := "off"
	if on {
		kind = "on"
	}
	if rows[0]["type"] == kind {
		return nil
	}
	return r.call(ctx, "PATCH", "system/leds/"+rows[0][".id"], Row{"type": kind}, nil)
}
func (r *Router) PowerOff(ctx context.Context) error {
	rows, e := r.rows(ctx, "container", ".id,name", "name=awg-control")
	if e != nil {
		return e
	}
	if len(rows) != 1 {
		return errors.New("Unified container not found")
	}
	if e = r.call(ctx, "PATCH", "container/"+rows[0][".id"], Row{"start-on-boot": strconv.FormatBool(false)}, nil); e != nil {
		return e
	}
	return r.call(ctx, "POST", "container/stop", Row{"numbers": rows[0][".id"]}, nil)
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Row map[string]string
type Router struct {
	settings Settings
	client   *http.Client
}

func newRouter(s Settings) *Router {
	return &Router{s, &http.Client{Timeout: 65 * time.Second, Transport: &http.Transport{MaxIdleConns: 1, MaxConnsPerHost: 1}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Router redirect refused") }}}
}
func (r *Router) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, r.settings.RouterURL+"/rest/"+path, body)
	if e != nil {
		return e
	}
	req.SetBasicAuth(r.settings.RouterUser, r.settings.RouterPassword)
	req.Header.Set("Content-Type", "application/json")
	resp, e := r.client.Do(req)
	if e != nil {
		return errors.New("Router API unavailable or timed out; inspect diagnostics before retrying")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var detail struct {
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&detail)
		message := detail.Message + " " + detail.Detail
		if r.settings.RouterPassword != "" {
			message = strings.ReplaceAll(message, r.settings.RouterPassword, "<redacted>")
		}
		if len(message) > 250 {
			message = message[:250]
		}
		return fmt.Errorf("Router API %s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(message))
	}
	if out == nil {
		_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return e
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	return dec.Decode(out)
}
func (r *Router) rows(ctx context.Context, path, props string, query ...string) ([]Row, error) {
	var out []Row
	p := map[string]any{".proplist": props}
	if len(query) > 0 {
		p[".query"] = query
	}
	e := r.call(ctx, "POST", path+"/print", p, &out)
	return out, e
}
func (r *Router) script(ctx context.Context, name, source string) error {
	rows, e := r.rows(ctx, "system/script", ".id,name,comment", "name="+name)
	if e != nil {
		return e
	}
	fields := map[string]string{"name": name, "source": source, "policy": "read,write,test", "comment": Tag + "managed"}
	if len(rows) == 0 {
		e = r.call(ctx, "PUT", "system/script", fields, nil)
	} else if len(rows) == 1 && rows[0]["comment"] == Tag+"managed" {
		e = r.call(ctx, "PATCH", "system/script/"+rows[0][".id"], fields, nil)
	} else {
		return errors.New("Script name is occupied by another configuration")
	}
	if e != nil {
		return e
	}
	return r.call(ctx, "POST", "system/script/run", map[string]string{"number": name}, nil)
}
func findEntry(rows []Row) (Row, error) {
	var found Row
	for _, v := range rows {
		if strings.HasPrefix(v["comment"], Tag+"entry ") {
			if found != nil {
				return nil, errors.New("Multiple panel entry rules")
			}
			found = v
		}
	}
	if found == nil {
		return nil, errors.New("Panel router integration is missing; run setup first")
	}
	return found, nil
}
func (r *Router) preflight(ctx context.Context) (Row, error) {
	rows, e := r.rows(ctx, "system/resource", "free-memory,free-hdd-space,version,board-name")
	if e != nil {
		return nil, e
	}
	if len(rows) != 1 {
		return nil, errors.New("Cannot read router resources")
	}
	ram, _ := strconv.ParseInt(rows[0]["free-memory"], 10, 64)
	flash, _ := strconv.ParseInt(rows[0]["free-hdd-space"], 10, 64)
	if ram < 12<<20 {
		return nil, errors.New("Update refused: router has less than 12 MiB free RAM")
	}
	if flash < 160<<10 {
		return nil, errors.New("Update refused: router has less than 160 KiB free internal flash")
	}
	if rows[0]["board-name"] != "hAP ac^2" || rows[0]["version"] != "7.24.5 (stable)" && rows[0]["version"] != "7.24.5" {
		return nil, errors.New("This experimental panel targets hAP ac2 with RouterOS 7.24.5 only")
	}
	v6, e := r.rows(ctx, "ipv6/route", "dst-address,active", "dst-address=::/0")
	if e != nil {
		return nil, e
	}
	for _, v := range v6 {
		if v["active"] == "true" {
			return nil, errors.New("Active IPv6 internet detected; IPv4 policies cannot cover it")
		}
	}
	rows, e = r.rows(ctx, "ip/firewall/mangle", ".id,comment,jump-target,disabled")
	if e != nil {
		return nil, e
	}
	return findEntry(rows)
}
func mark(chain, mac, extra, table string) string {
	s := "/ip/firewall/mangle/add chain=" + chain + " action=mark-routing new-routing-mark=" + table + " passthrough=no comment=" + rq(Tag+chain)
	if mac != "" {
		s += " src-mac-address=" + mac
	}
	if extra != "" {
		s += " " + extra
	}
	return s + ";\n"
}
func policyRules(p Policy, slot string) string {
	chain := "AWG3UI-" + slot
	var b strings.Builder
	for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"} {
		b.WriteString(mark(chain, "", "dst-address="+cidr, "main"))
	}
	add := func(mac, mode string) {
		switch mode {
		case "direct":
			b.WriteString(mark(chain, mac, "", "main"))
		case "vpn":
			b.WriteString(mark(chain, mac, "", "to-awg"))
		case "geo":
			b.WriteString(mark(chain, mac, "dst-address-list=AWG3UI-ip-"+slot, "to-awg"))
			b.WriteString(mark(chain, mac, "dst-address-list=AWG3UI-dns-a", "to-awg"))
			b.WriteString(mark(chain, mac, "dst-address-list=AWG3UI-dns-b", "to-awg"))
			b.WriteString(mark(chain, mac, "src-address-list=AWG3UI-ready", "main"))
			b.WriteString(mark(chain, mac, "", "to-awg"))
		}
	}
	for _, d := range p.Devices {
		add(d.MAC, d.Mode)
	}
	add("", p.Default)
	return b.String()
}
func clearSlot(slot string) string {
	return "/ip/firewall/mangle/remove [find where chain=" + rq("AWG3UI-"+slot) + "];\n/ip/firewall/address-list/remove [find where list=" + rq("AWG3UI-ip-"+slot) + "];\n/ip/dns/static/remove [find where comment=" + rq(Tag+"dns-"+slot) + "];\n"
}
func flushConnections(lan string) string {
	p, _ := netip.ParsePrefix(lan)
	oct := strings.Split(p.Addr().String(), ".")
	prefix := strings.Join(oct[:3], `\.`) + `\.`
	return "/ip/firewall/connection/remove [find where src-address~" + rq("^"+prefix) + "];\n/ip/dns/cache/flush;\n"
}
func applyScript(s Settings, state Saved, slot string) string {
	other := "a"
	if slot == "a" {
		other = "b"
	}
	var b strings.Builder
	b.WriteString(":if ([:len [/system/script/job/find where script=\"awg-toggle\" or script=\"awg-toggle-base\" or script=\"awg-ui-guard\"]] > 0 || [:len [/system/script/job/find where script=\"awg-ui-apply\"]] > 1) do={ :error \"AWG operation is already running\" }; :local committed false;\n:do {\n")
	b.WriteString("/ip/firewall/address-list/remove [find where list=\"AWG3UI-ready\"];\n")
	b.WriteString(clearSlot(slot))
	if len(state.Bundle.IPs) > 0 {
		items := make([]string, 0, len(state.Bundle.IPs))
		for _, ip := range state.Bundle.IPs {
			items = append(items, rq(ip))
		}
		b.WriteString(":foreach ip in={" + strings.Join(items, ";") + "} do={ /ip/firewall/address-list/add list=AWG3UI-ip-" + slot + " address=$ip timeout=none-dynamic comment=" + rq(Tag+"data") + "; };\n")
	}
	if len(state.Bundle.Domains) > 0 {
		items := make([]string, 0, len(state.Bundle.Domains))
		for _, d := range state.Bundle.Domains {
			kind := "f:"
			if d.Suffix {
				kind = "s:"
			}
			items = append(items, rq(kind+d.Name))
		}
		b.WriteString(":foreach item in={" + strings.Join(items, ";") + "} do={ :local sub false; :if ([:pick $item 0 1] = \"s\") do={ :set sub true }; /ip/dns/static/add name=[:pick $item 2 [:len $item]] type=FWD match-subdomain=$sub address-list=AWG3UI-dns-" + slot + " comment=" + rq(Tag+"dns-"+slot) + "; };\n")
	}
	b.WriteString(policyRules(state.Policy, slot))
	b.WriteString("/ip/firewall/mangle/set [find where comment~\"^AWG3UI entry \"] jump-target=AWG3UI-" + slot + " comment=" + rq(Tag+"entry "+state.Revision) + "; :set committed true;\n")
	b.WriteString(clearSlot(other))
	b.WriteString("/ip/firewall/address-list/remove [find where list=\"AWG3UI-dns-a\" or list=\"AWG3UI-dns-b\"];\n")
	b.WriteString(flushConnections(s.LAN))
	b.WriteString("/ip/firewall/address-list/add list=AWG3UI-ready address=" + s.LAN + " timeout=none-dynamic comment=" + rq(Tag+"ready") + ";\n")
	b.WriteString("} on-error={ :if ($committed = false) do={ " + clearSlot(slot) + " }; :log error \"AWG3UI: apply failed; Geo stays on VPN until recovery\"; :error \"Panel apply failed\" };\n")
	return b.String()
}
func (r *Router) toggle(ctx context.Context) error {
	before, e := r.rows(ctx, "routing/rule", "disabled", "comment=AWG3 switch LAN")
	if e != nil {
		return e
	}
	if len(before) != 1 {
		return errors.New("AWG switch missing")
	}
	// Run independently of REST's 60-second command deadline. Native script jobs
	// also serialize the physical button against panel operations across users.
	if e = r.call(ctx, "POST", "execute", Row{"script": "/system/script/run awg-toggle"}, nil); e != nil {
		return e
	}
	deadline := time.NewTimer(100 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("Toggle is still running; inspect diagnostics before retrying")
		case <-tick.C:
			jobs, e := r.rows(ctx, "system/script/job", "script", "script=awg-toggle", "script=awg-toggle-base", "#|")
			if e != nil {
				return e
			}
			if len(jobs) > 0 {
				continue
			}
			after, e := r.rows(ctx, "routing/rule", "disabled", "comment=AWG3 switch LAN")
			if e != nil {
				return e
			}
			if len(after) != 1 || after[0]["disabled"] == before[0]["disabled"] {
				return errors.New("VPN did not reach the requested state; inspect tunnel diagnostics")
			}
			return nil
		}
	}
}
func (r *Router) apply(ctx context.Context, state Saved) error {
	state.Policy = state.Policy.Clone()
	if e := state.Policy.Validate(); e != nil {
		return e
	}
	if e := state.Bundle.Validate(); e != nil {
		return e
	}
	entry, e := r.preflight(ctx)
	if e != nil {
		return e
	}
	// Existing exact/suffix/regexp overrides can prevent the panel FWD record
	// from ever observing DNS answers. Refuse ambiguous overlap explicitly.
	dns, e := r.rows(ctx, "ip/dns/static", "name,regexp,match-subdomain,comment,disabled")
	if e != nil {
		return e
	}
	for _, row := range dns {
		if row["disabled"] == "true" || strings.HasPrefix(row["comment"], Tag) {
			continue
		}
		for _, d := range state.Bundle.Domains {
			name := strings.ToLower(row["name"])
			if row["regexp"] != "" || name == d.Name || (d.Suffix && strings.HasSuffix(name, "."+d.Name)) || (row["match-subdomain"] == "true" && strings.HasSuffix(d.Name, "."+name)) {
				return errors.New("Selected GeoSite overlaps an existing DNS override. Review IP > DNS > Static before applying")
			}
		}
	}
	slot := "a"
	if entry["jump-target"] == "AWG3UI-a" {
		slot = "b"
	}
	source := applyScript(r.settings, state, slot)
	if len(source) > 60000 {
		return errors.New("Policy script exceeds 60 KB flash budget; reduce device overrides or domain names")
	}
	return r.script(ctx, "awg-ui-apply", source)
}
func (r *Router) diagnostics(ctx context.Context) (map[string]any, error) {
	out := map[string]any{"panel_version": Version, "time": time.Now().UTC().Format(time.RFC3339)}
	checks := []struct {
		name, path, props string
		query             []string
	}{
		{"resource", "system/resource", "version,board-name,free-memory,free-hdd-space,uptime,cpu-load", nil},
		{"containers", "container", "name,running,stopped,error,memory-current", nil},
		{"routing", "routing/rule", "comment,disabled,table,src-address,dst-address", nil},
		{"mangle", "ip/firewall/mangle", "comment,chain,jump-target,disabled,packets,bytes", nil},
		{"ready", "ip/firewall/address-list", "list,address", []string{"list=AWG3UI-ready"}},
	}
	for _, c := range checks {
		rows, e := r.rows(ctx, c.path, c.props, c.query...)
		if e != nil {
			out[c.name] = e.Error()
			continue
		}
		if c.name == "mangle" || c.name == "routing" {
			kept := []Row{}
			for _, row := range rows {
				if strings.HasPrefix(row["comment"], "AWG3") {
					kept = append(kept, row)
				}
			}
			rows = kept
		}
		out[c.name] = rows
	}
	return out, nil
}

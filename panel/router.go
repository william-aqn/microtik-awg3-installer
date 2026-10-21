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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Row map[string]string
type Router struct {
	settings           Settings
	client             *http.Client
	scriptMu           sync.Mutex
	scriptDir          string
	geo                *GeoDNS
	dnsRAM             *dnsRegistrar
	trafficMu          sync.RWMutex
	trafficInitialized bool
	trafficError       error
}

func newRouter(s Settings) *Router {
	// List updates and DNS learning must not monopolize route-health reads.
	r := &Router{settings: s, client: &http.Client{Timeout: 65 * time.Second, Transport: &http.Transport{MaxIdleConns: 3, MaxConnsPerHost: 3}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Router redirect refused") }}}
	r.dnsRAM = &dnsRegistrar{router: r, items: map[string]dnsLease{}}
	r.geo = newGeoDNS(s.Gateway, r.dnsRAM.learn)
	if s.DataDir != "" {
		r.geo.aliasPath = filepath.Join(s.DataDir, "dns-aliases.json")
		r.dnsRAM.path = filepath.Join(s.DataDir, "dns-routes.json")
	}
	return r
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
	r.scriptMu.Lock()
	defer r.scriptMu.Unlock()
	if len(source) > 48000 || !ifaceName.MatchString(name) {
		return errors.New("Router script exceeds the 48 KB batch limit")
	}
	rows, e := r.rows(ctx, "system/script", ".id,name,comment,source", "name="+name)
	if e != nil {
		return e
	}
	if len(rows) > 1 || (len(rows) == 1 && rows[0]["comment"] != Tag+"managed") {
		return errors.New("Script name is occupied by another configuration")
	}
	if r.scriptDir == "" {
		mounts, err := r.rows(ctx, "container/mounts", "list,src,dst", "list=awg_control_mount", "dst="+r.settings.DataDir)
		if err != nil {
			return err
		}
		if len(mounts) != 1 || r.settings.DataDir == "" {
			return errors.New("Cannot locate the AWG Control USB mount")
		}
		src := strings.TrimPrefix(mounts[0]["src"], "/")
		if !regexp.MustCompile(`^usb[A-Za-z0-9_-]*/awg-control-data$`).MatchString(src) {
			return errors.New("Router batch files must use the managed external USB directory")
		}
		r.scriptDir = src
	}
	file := "router-" + name + ".rsc"
	if e = writeData(filepath.Join(r.settings.DataDir, file), []byte(source)); e != nil {
		return errors.New("Cannot write the router command batch on USB")
	}
	// Keep only a small, stable loader in RouterOS configuration. Rewriting a
	// large script for every batch can fill the 16 MiB configuration storage.
	loader := "/import file-name=" + rq(r.scriptDir+"/"+file)
	fields := map[string]string{"name": name, "source": loader, "policy": "read,write,test", "comment": Tag + "managed"}
	if len(rows) == 0 {
		e = r.call(ctx, "PUT", "system/script", fields, nil)
	} else if rows[0]["source"] != loader {
		e = r.call(ctx, "PATCH", "system/script/"+rows[0][".id"], fields, nil)
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
	// Earlier builds can grow the flash configuration store even for dynamic
	// lists. Keep the tested version boundary until other patched releases pass.
	if rows[0]["board-name"] != "hAP ac^2" || rows[0]["version"] != "7.23.8 (long-term)" && rows[0]["version"] != "7.23.8" {
		return nil, errors.New("USB Geo requires the tested hAP ac2 / RouterOS 7.23.8 long-term with the flash-store fix; see GOTCHAS.md")
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
			b.WriteString(mark(chain, mac, "dst-address-list="+geoDNSList, "to-awg"))
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
	return "/ip/firewall/mangle/remove [find where chain=" + rq("AWG3UI-"+slot) + "];\n/ip/firewall/address-list/remove [find where list=" + rq("AWG3UI-ip-"+slot) + "];\n"
}
func flushConnections(lan string) string {
	p, _ := netip.ParsePrefix(lan)
	oct := strings.Split(p.Addr().String(), ".")
	prefix := strings.Join(oct[:3], `\.`) + `\.`
	return "/ip/firewall/connection/remove [find where src-address~" + rq("^"+prefix) + "];\n/ip/dns/cache/flush;\n"
}
func applyScript(s Settings, state Saved, slot string) string {
	return beginPolicy(slot) + ipBatch(state.Bundle.IPs, slot) + commitPolicy(s, state, slot)
}

const policyBatchSize = 512
const domainBatchSize = 64

var routerRecordID = regexp.MustCompile(`^\*[0-9A-Fa-f]+$`)

func policyGuard() string {
	return policyJobGuard() +
		":if ([/system/resource/get free-memory] < 12582912 || [/system/resource/get free-hdd-space] < 131072) do={ :error \"Policy update stopped: low router memory or flash; Geo remains on VPN\" };\n"
}

func policyJobGuard() string {
	return ":if ([:len [/system/script/job/find where script=\"awg-ui-guard\"]] > 0 || [:len [/system/script/job/find where script=\"awg-ui-apply\"]] > 1) do={ :error \"AWG operation is already running\" };\n"
}

func beginPolicy(slot string) string {
	var b strings.Builder
	b.WriteString(policyGuard())
	b.WriteString("/ip/firewall/address-list/remove [find where list=\"AWG3UI-ready\"];\n")
	b.WriteString("/ip/firewall/mangle/remove [find where chain=" + rq("AWG3UI-"+slot) + "];\n")
	return b.String()
}

// DNS removal can exceed the RouterOS REST command deadline just like adding
// records. Remove bounded ID batches, leaving the committed USB snapshot intact.
func (r *Router) pruneSlot(ctx context.Context, slot string, inactiveOnly bool, report func(string)) error {
	guard := policyJobGuard()
	if inactiveOnly {
		guard += ":if ([:len [/ip/firewall/mangle/find where comment~\"^AWG3UI entry \" and jump-target=" + rq("AWG3UI-"+slot) + "]] > 0) do={ :error \"Slot is active; cleanup refused\" };\n"
	} else {
		guard += ":if ([:len [/ip/firewall/address-list/find where list=\"AWG3UI-ready\"]] > 0) do={ :error \"Geo is ready; cleanup refused\" };\n"
	}
	rows, err := r.rows(ctx, "ip/firewall/address-list", ".id", "list=AWG3UI-ip-"+slot)
	if err != nil {
		return err
	}
	return r.removeRows(ctx, "ip/firewall/address-list", rows, policyBatchSize, guard, report)
}

func (r *Router) removeRows(ctx context.Context, path string, rows []Row, batch int, guard string, report func(string)) error {
	for start := 0; start < len(rows); start += batch {
		end := min(start+batch, len(rows))
		ids := make([]string, 0, end-start)
		for _, row := range rows[start:end] {
			if !routerRecordID.MatchString(row[".id"]) {
				return errors.New("Invalid router record ID; cleanup refused")
			}
			ids = append(ids, rq(row[".id"]))
		}
		report(fmt.Sprintf("Applying policy: clearing %s (%d / %d); Geo temporarily uses VPN", path, start, len(rows)))
		source := guard + ":foreach id in={" + strings.Join(ids, ";") + "} do={ /" + path + "/remove $id };\n"
		if err := r.script(ctx, "awg-ui-apply", source); err != nil {
			return err
		}
	}
	return nil
}

func ipBatch(ips []string, slot string) string {
	var b strings.Builder
	if len(ips) > 0 {
		items := make([]string, 0, len(ips))
		for _, ip := range ips {
			items = append(items, rq(ip))
		}
		b.WriteString(":foreach ip in={" + strings.Join(items, ";") + "} do={ /ip/firewall/address-list/add list=AWG3UI-ip-" + slot + " address=$ip dynamic=yes comment=" + rq(Tag+"data") + "; };\n")
	}
	return b.String()
}

func commitPolicy(s Settings, state Saved, slot string) string {
	other := "a"
	if slot == "a" {
		other = "b"
	}
	var b strings.Builder
	b.WriteString(policyGuard())
	b.WriteString(fmt.Sprintf(":if ([:len [/ip/firewall/address-list/find where list=%s]] != %d || [:len [/ip/dns/static/find where comment~\"^AWG3UI dns-\"]] != 0) do={ :error \"Staged policy is incomplete; Geo remains on VPN\" };\n", rq("AWG3UI-ip-"+slot), len(state.Bundle.IPs)))
	b.WriteString(policyRules(state.Policy, slot))
	b.WriteString("/ip/firewall/mangle/set [find where comment~\"^AWG3UI entry \"] jump-target=AWG3UI-" + slot + " comment=" + rq(Tag+"entry "+state.Revision) + ";\n")
	b.WriteString(clearSlot(other))
	// Keep learned RAM addresses across updates and container restarts. Clients
	// can still hold DNS answers; every learned address expires automatically.
	b.WriteString(flushConnections(s.LAN))
	b.WriteString("/ip/firewall/address-list/add list=AWG3UI-ready address=" + s.LAN + " dynamic=yes comment=" + rq(Tag+"ready") + ";\n")
	return b.String()
}

func coveredStaticA(row Row, bundle Bundle) bool {
	// Exact A overrides (for example pinned DNS bootstrap addresses) can skip
	// container-side DNS learning. They are safe only when that fixed address is already routed
	// by the selected IP list. Keep the original record and its bootstrap role.
	if row["type"] != "A" || row["regexp"] != "" || row["match-subdomain"] == "true" {
		return false
	}
	address, e := netip.ParseAddr(row["address"])
	if e != nil || !address.Is4() {
		return false
	}
	for _, item := range bundle.IPs {
		prefix, e := netip.ParsePrefix(item)
		if e == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (r *Router) apply(ctx context.Context, state Saved, progress ...func(string)) (result error) {
	report := func(message string) {
		for _, callback := range progress {
			callback(message)
		}
	}
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
	if e = r.dnsRAM.seed(ctx); e != nil {
		return e
	}
	// Existing exact/suffix/regexp overrides can prevent the container DNS
	// observer from ever seeing those answers. Refuse ambiguous overlap explicitly.
	dns, e := r.rows(ctx, "ip/dns/static", ".id,name,type,address,regexp,match-subdomain,address-list,comment,disabled")
	if e != nil {
		return e
	}
	for _, row := range dns {
		if row["disabled"] == "true" || strings.HasPrefix(row["comment"], Tag) || coveredStaticA(row, state.Bundle) {
			continue
		}
		for _, d := range state.Bundle.Domains {
			if d.Regexp {
				pattern, _ := regexp.CompilePOSIX(d.Name) // Bundle.Validate checked it.
				if row["regexp"] != "" || row["match-subdomain"] == "true" || pattern.MatchString(strings.ToLower(row["name"])) {
					return errors.New("GeoSite regexp rules may overlap an existing DNS override; review IP > DNS > Static before applying")
				}
				continue
			}
			name := strings.ToLower(row["name"])
			if row["regexp"] != "" || name == d.Name || (d.Suffix && strings.HasSuffix(name, "."+d.Name)) || (row["match-subdomain"] == "true" && strings.HasSuffix(d.Name, "."+name)) {
				return errors.New("Selected Geo domain overlaps an existing DNS override. Review IP > DNS > Static before applying")
			}
		}
	}
	slot := "a"
	if entry["jump-target"] == "AWG3UI-a" {
		slot = "b"
	}
	var obsoleteDNS []Row
	for _, row := range dns {
		if strings.HasPrefix(row["comment"], Tag+"dns-") {
			obsoleteDNS = append(obsoleteDNS, row)
		}
	}
	defer func() {
		if result == nil {
			return
		}
		// A failed batch must not consume staging memory indefinitely. Never
		// remove the slot if the commit already switched the live entry to it.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		entries, err := r.rows(cleanup, "ip/firewall/mangle", ".id", "comment="+Tag+"entry "+state.Revision, "jump-target=AWG3UI-"+slot)
		if err == nil && len(entries) > 0 {
			return
		}
		if err == nil {
			err = r.pruneSlot(cleanup, slot, true, report)
		}
		if err != nil {
			result = fmt.Errorf("%w; staging cleanup failed: %v", result, err)
		}
	}()
	report("Applying policy: releasing previous lists; Geo temporarily uses VPN")
	if e = r.script(ctx, "awg-ui-apply", beginPolicy(slot)); e != nil {
		return e
	}
	// Geo is fail-closed while both old and stale staging data are released.
	// Do not hold two complete policy copies in the router's limited RAM.
	for _, old := range []string{"a", "b"} {
		if e = r.pruneSlot(ctx, old, false, report); e != nil {
			return fmt.Errorf("Previous-list cleanup: %w. Geo remains on VPN; retry Apply", e)
		}
	}
	if e = r.removeRows(ctx, "ip/dns/static", obsoleteDNS, domainBatchSize, policyJobGuard(), report); e != nil {
		return fmt.Errorf("DNS cleanup: %w. Geo remains on VPN; retry Apply", e)
	}
	// Measure after releasing the old lists. Do not lower the memory reserve
	// merely because an earlier full copy was still consuming it.
	resources, e := r.rows(ctx, "system/resource", "free-memory")
	if e != nil || len(resources) != 1 {
		return errors.New("Cannot check staging memory; Geo remains on VPN until Apply succeeds")
	}
	free, _ := strconv.ParseInt(resources[0]["free-memory"], 10, 64)
	required := int64(14<<20) + int64(len(state.Bundle.IPs))*256 + int64(len(state.Bundle.Domains))*1024
	if free < required {
		return fmt.Errorf("Policy needs %.1f MiB free RAM for staging; router has %.1f MiB. Geo remains on VPN; choose fewer rules and apply", float64(required)/(1<<20), float64(free)/(1<<20))
	}
	for start := 0; start < len(state.Bundle.IPs); start += policyBatchSize {
		end := min(start+policyBatchSize, len(state.Bundle.IPs))
		report(fmt.Sprintf("Applying IPv4 prefixes: %d / %d; Geo temporarily uses VPN", start, len(state.Bundle.IPs)))
		if e = r.script(ctx, "awg-ui-apply", policyGuard()+ipBatch(state.Bundle.IPs[start:end], slot)); e != nil {
			return fmt.Errorf("IPv4 batch %d: %w. Geo remains on VPN; retry Apply", start/policyBatchSize+1, e)
		}
	}
	if e = r.geo.setDomains(state.Bundle.Domains); e != nil {
		return e
	}
	report("Applying completed lists and verifying counts; Geo temporarily uses VPN")
	return r.script(ctx, "awg-ui-apply", commitPolicy(r.settings, state, slot))
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
		{"routes", "ip/route", "comment,routing-table,dst-address,gateway,immediate-gw,distance,disabled,active,blackhole", []string{"routing-table=to-awg"}},
		{"mangle", "ip/firewall/mangle", ".id,comment,chain,action,jump-target,new-routing-mark,src-mac-address,src-address-list,dst-address-list,dst-address,disabled,packets,bytes", nil},
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
				if strings.HasPrefix(row["comment"], "AWG3") || strings.HasPrefix(row["comment"], "AWGC ") {
					kept = append(kept, row)
				}
			}
			rows = kept
		}
		out[c.name] = rows
	}
	return out, nil
}

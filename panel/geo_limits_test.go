package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestGeoRequiresPatchedRouterOS(t *testing.T) {
	for _, tc := range []struct {
		version string
		ok      bool
	}{
		{"7.23.8", true},
		{"7.23.8 (long-term)", true},
		{"7.23.7 (long-term)", false},
		{"7.24.5 (stable)", false},
		{"7.26beta3 (testing)", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var out any = []Row{}
				switch req.URL.Path {
				case "/rest/system/resource/print":
					out = []Row{{"free-memory": "41943040", "free-hdd-space": "524288", "board-name": "hAP ac^2", "version": tc.version}}
				case "/rest/ip/firewall/mangle/print":
					out = []Row{{"comment": Tag + "entry current", "jump-target": "AWG3UI-a"}}
				case "/rest/ipv6/route/print":
				default:
					t.Errorf("Unexpected request during preflight: %s", req.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			_, err := newRouter(Settings{RouterURL: server.URL}).preflight(context.Background())
			if (err == nil) != tc.ok {
				t.Fatalf("preflight error = %v, want accepted = %v", err, tc.ok)
			}
			if !tc.ok && !strings.Contains(err.Error(), "flash-store fix") {
				t.Fatalf("Missing actionable version error: %v", err)
			}
		})
	}
}

func TestExpandedPolicySnapshotFitsAndRestores(t *testing.T) {
	state := Saved{Policy: defaultPolicy(), Revision: "large"}
	for i := 0; i < MaxIPs; i++ {
		ip := fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
		state.Bundle.IPs = append(state.Bundle.IPs, ip)
		state.Policy.CustomIPs = append(state.Policy.CustomIPs, ip)
	}
	for i := 0; i < MaxDomains; i++ {
		name := fmt.Sprintf("d%d.%s.example", i, strings.Repeat("x", 60))
		state.Bundle.Domains = append(state.Bundle.Domains, Domain{Name: name, Suffix: true})
		state.Policy.CustomDomains = append(state.Policy.CustomDomains, name)
	}
	if e := state.Policy.Validate(); e != nil {
		t.Fatal(e)
	}
	if e := state.Bundle.Validate(); e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(state.Policy)
	if len(data) > MaxPolicyBytes {
		t.Fatal("Maximum policy cannot be submitted")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if e := writeJSON(path, state); e != nil {
		t.Fatal(e)
	}
	var loaded Saved
	if e := readJSON(path, &loaded); e != nil {
		t.Fatal(e)
	}
	if len(loaded.Bundle.IPs) != MaxIPs || len(loaded.Bundle.Domains) != MaxDomains {
		t.Fatal("Snapshot truncated")
	}
}

func TestGeoRegexpTranslationAndMatching(t *testing.T) {
	cases := []struct{ pattern, yes, no string }{
		{`.+\.awsdns-[0-9][0-9]\.(co\.uk|com|net|org)$`, "ns.awsdns-42.org", "ns.awsdns-123.org"},
		{`^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`, "chatgpt-async-webps-prod-abc-123.webpubsub.azure.com", "other.azure.com"},
		{`(\w+)-static-[0-9]+\.cdntogo\.net$`, "abc-static-23.cdntogo.net", "abc-static-x.cdntogo.net"},
		{`^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$`, "rr3---sn-ni5abc12.googlevideo.com", "rr3---sn-other.googlevideo.com"},
	}
	for _, c := range cases {
		translated, e := geoRegexp(c.pattern)
		if e != nil {
			t.Fatal(e)
		}
		r, e := regexp.CompilePOSIX(translated)
		if e != nil || !r.MatchString(c.yes) || r.MatchString(c.no) {
			t.Fatalf("Changed matching semantics: %s", translated)
		}
		b := Bundle{Domains: []Domain{{Name: translated, Regexp: true}}}
		if e := b.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	for _, pattern := range []string{`(?i)example`, `a\b`, `[\d]`, `[[:space:]]`, `\p{L}`, `a+?`, `(?=a)`, "a\n", `\1`, strings.Repeat("a", 513)} {
		if _, e := geoRegexp(pattern); e == nil {
			t.Fatalf("Unsupported expression accepted: %q", pattern)
		}
	}
}

func TestGeoLargePolicyBatchesAndFailure(t *testing.T) {
	for _, scenario := range []string{"success", "reused-dns", "reclaimed-memory", "failed-batch", "low-memory", "insufficient-stage"} {
		t.Run(scenario, func(t *testing.T) {
			state := Saved{Policy: defaultPolicy(), Revision: "test-revision"}
			for i := 0; i < 22000; i++ {
				state.Bundle.IPs = append(state.Bundle.IPs, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
			}
			for i := 0; i < 1300; i++ {
				state.Bundle.Domains = append(state.Bundle.Domains, Domain{Name: fmt.Sprintf("d%d.example", i), Suffix: true})
			}
			state.Bundle.Domains = append(state.Bundle.Domains, Domain{Name: `^regexp[0-9]+\.example$`, Regexp: true})
			var source string
			var loader string
			dataDir := t.TempDir()
			var runs []string
			ipRuns, ipCount, domainCount, removed := 0, 0, 0, 0
			loaderWrites := 0
			committed := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body map[string]any
				_ = json.NewDecoder(req.Body).Decode(&body)
				var out any = []Row{}
				switch req.URL.Path {
				case "/rest/container/mounts/print":
					out = []Row{{"list": "awg_control_mount", "src": "usb1-part1/awg-control-data", "dst": dataDir}}
				case "/rest/system/resource/print":
					ram := "41943040"
					if scenario == "low-memory" {
						ram = "11534336"
					}
					if scenario == "insufficient-stage" || (scenario == "reclaimed-memory" && len(runs) == 0) {
						ram = "16777216"
					}
					out = []Row{{"free-memory": ram, "free-hdd-space": "524288", "board-name": "hAP ac^2", "version": "7.23.8"}}
				case "/rest/ip/firewall/mangle/print":
					if body[".proplist"] != ".id" {
						out = []Row{{"comment": Tag + "entry old", "jump-target": "AWG3UI-a"}}
					}
				case "/rest/ip/firewall/address-list/print":
					query, _ := body[".query"].([]any)
					if len(query) == 1 && query[0] == "list="+geoDNSList {
						out = []Row{}
						break
					}
					var ids []Row
					for i := 0; i < 1025; i++ {
						ids = append(ids, Row{".id": fmt.Sprintf("*%X", i+1)})
					}
					out = ids
				case "/rest/ip/dns/static/print":
					if body[".proplist"] == ".id" {
						out = []Row{}
					} else {
						rows := []Row{{"name": "router.lan", "type": "A", "address": "192.168.3.1"}, {"name": "d1.example", "type": "A", "address": "10.0.0.10"}}
						for i := 0; i < 129; i++ {
							rows = append(rows, Row{".id": fmt.Sprintf("*%X", i+1), "name": fmt.Sprintf("old%d.test", i), "type": "FWD", "comment": Tag + "dns-a", "address-list": "AWG3UI-dns-a"})
						}
						if scenario == "reused-dns" {
							rows = rows[:2]
							for i, d := range state.Bundle.Domains {
								row := Row{".id": fmt.Sprintf("*%X", i+1), "type": "FWD", "comment": Tag + "dns-previous", "address-list": "AWG3UI-dns-a"}
								if d.Regexp {
									row["regexp"] = d.Name
								} else {
									row["name"] = d.Name
									row["match-subdomain"] = "true"
								}
								rows = append(rows, row)
							}
						}
						out = rows
					}
				case "/rest/system/script/print":
					out = []Row{{".id": "*1", "comment": Tag + "managed", "source": loader}}
				case "/rest/system/script/*1":
					loader = body["source"].(string)
					loaderWrites++
					if len(loader) > 200 || !strings.Contains(loader, "/import file-name=") {
						t.Error("Batch contents leaked into persistent script")
					}
				case "/rest/system/script/run":
					data, err := os.ReadFile(filepath.Join(dataDir, "router-awg-ui-apply.rsc"))
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					source = string(data)
					if len(source) > 48000 {
						t.Error("Oversized USB batch")
					}
					runs = append(runs, source)
					if strings.Contains(source, ":foreach ip") {
						wantRemoved := 2*1025 + 129
						if scenario == "reused-dns" {
							wantRemoved = 2*1025 + len(state.Bundle.Domains)
						}
						if removed != wantRemoved {
							t.Error("Staging started before previous lists were released")
						}
						ipRuns++
						ipCount += strings.Count(source, "/24\"")
						if scenario == "failed-batch" && ipRuns == 2 {
							w.WriteHeader(400)
							_, _ = w.Write([]byte(`{"message":"injected failure"}`))
							return
						}
					}
					if strings.Contains(source, ":foreach id") {
						count := strings.Count(source, `"*`)
						limit := policyBatchSize
						if strings.Contains(source, "/ip/dns/static/remove $id") {
							limit = domainBatchSize
						}
						if count > limit || committed {
							t.Error("Unbounded or late cleanup")
						}
						removed += count
					}
					committed = committed || strings.Contains(source, "add list=AWG3UI-ready")
					domainCount += strings.Count(source, ".example\"")
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer server.Close()
			r := newRouter(Settings{RouterURL: server.URL, LAN: "192.168.3.0/24", DataDir: dataDir})
			e := r.apply(context.Background(), state)
			switch scenario {
			case "success", "reused-dns", "reclaimed-memory":
				wantedDomains := 0
				if e != nil || ipCount != len(state.Bundle.IPs) || domainCount != wantedDomains || ipRuns < 2 {
					t.Fatalf("Incomplete transfer %d/%d: %v", ipCount, domainCount, e)
				}
				if loaderWrites != 1 {
					t.Fatal("Persistent loader was rewritten for each batch")
				}
				if !strings.Contains(runs[0], `remove [find where list="AWG3UI-ready"]`) || !strings.Contains(runs[len(runs)-1], `add list=AWG3UI-ready`) {
					t.Fatal("Readiness must bracket all batches")
				}
			case "failed-batch":
				if e == nil || !strings.Contains(e.Error(), "batch 2") {
					t.Fatal(e)
				}
				for _, run := range runs {
					if strings.Contains(run, "add list=AWG3UI-ready") {
						t.Fatal("Failed policy committed")
					}
				}
				if !strings.Contains(runs[len(runs)-1], `Slot is active; cleanup refused`) {
					t.Fatal("Missing inactive-slot cleanup")
				}
			case "low-memory":
				if e == nil || len(runs) != 0 {
					t.Fatal("Low-memory update touched router policy", e)
				}
			case "insufficient-stage":
				if e == nil || !strings.Contains(e.Error(), "Geo remains on VPN") {
					t.Fatal(e)
				}
				for _, run := range runs {
					if strings.Contains(run, "add list=AWG3UI-ready") {
						t.Fatal("Low-memory policy committed")
					}
				}
			}
		})
	}
}

func TestPinnedDNSRequiresIPCoverage(t *testing.T) {
	b := Bundle{IPs: []string{"8.8.8.0/24"}}
	row := Row{"name": "dns.google", "type": "A", "address": "8.8.8.8"}
	if !coveredStaticA(row, b) {
		t.Fatal("Pinned address already covered by IP rules")
	}
	for key, value := range map[string]string{"type": "CNAME", "address": "8.8.4.4", "match-subdomain": "true", "regexp": ".*"} {
		changed := Row{}
		for k, v := range row {
			changed[k] = v
		}
		changed[key] = value
		if coveredStaticA(changed, b) {
			t.Fatalf("Ambiguous override accepted: %s", key)
		}
	}
}

func TestStatusDoesNotScanLargeFirewallLists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "firewall") {
			t.Error("Frequent UI status must not scan the large firewall table")
		}
		_ = json.NewEncoder(w).Encode([]Row{})
	}))
	defer server.Close()
	a := testApp()
	a.router = newRouter(Settings{RouterURL: server.URL})
	w := httptest.NewRecorder()
	a.status(w, httptest.NewRequest("GET", "/api/state", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestRouteReadCanProceedDuringBackgroundListScan(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "address-list") {
			close(started)
			<-release
		}
		_ = json.NewEncoder(w).Encode([]Row{})
	}))
	defer server.Close()
	defer close(release)
	r := newRouter(Settings{RouterURL: server.URL})
	finished := make(chan error, 1)
	go func() {
		_, e := r.rows(context.Background(), "ip/firewall/address-list", ".id")
		finished <- e
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("Background scan did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := r.rows(ctx, "ip/route", ".id"); e != nil {
		t.Fatal("Route health was blocked by the background list scan", e)
	}
	release <- struct{}{}
	if e := <-finished; e != nil {
		t.Fatal(e)
	}
}

func TestScriptBatchesRefuseInternalStorage(t *testing.T) {
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var out any = []Row{}
		if r.URL.Path == "/rest/container/mounts/print" {
			out = []Row{{"src": "flash/awg-control-data"}}
		}
		if r.Method == "PUT" || r.Method == "PATCH" || strings.HasSuffix(r.URL.Path, "/run") {
			mutated = true
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	dir := t.TempDir()
	r := newRouter(Settings{RouterURL: server.URL, DataDir: dir})
	if e := r.script(context.Background(), "awg-ui-apply", ":put 1"); e == nil || mutated {
		t.Fatal("Internal-storage batch was accepted", e)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("Batch written before USB validation")
	}
}

func TestGeoFailureSurvivesSuccessfulConnectionAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]Row{{"free-memory": "33554432", "free-hdd-space": "20480"}})
	}))
	defer server.Close()
	a := testApp()
	a.router = newRouter(Settings{RouterURL: server.URL})
	if e := a.applyPolicy(context.Background(), Saved{Policy: defaultPolicy()}); e == nil {
		t.Fatal("Low-flash failure was not reported")
	}
	a.demo = true
	if e := a.queueTunnel("connect", Profile{}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		busy := a.busy
		a.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Connection action did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	w := httptest.NewRecorder()
	a.status(w, httptest.NewRequest("GET", "/api/state", nil))
	var state map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &state); e != nil {
		t.Fatal(e)
	}
	geoError, _ := state["geo_error"].(string)
	if state["error"] != "" || !strings.Contains(geoError, "internal flash") {
		t.Fatal("Successful Connect hid the outstanding Geo failure", state)
	}
}

func TestStatusDoesNotSerializeCompiledListsEveryPoll(t *testing.T) {
	a := testApp()
	a.demo = true
	a.state.Bundle.IPs = make([]string, MaxIPs)
	a.state.Bundle.Domains = make([]Domain, MaxDomains)
	w := httptest.NewRecorder()
	a.status(w, httptest.NewRequest("GET", "/api/state", nil))
	var state struct {
		Bundle struct {
			IPs     int `json:"ip_count"`
			Domains int `json:"domain_count"`
		} `json:"bundle"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &state); e != nil {
		t.Fatal(e)
	}
	if state.Bundle.IPs != MaxIPs || state.Bundle.Domains != MaxDomains || w.Body.Len() > 8192 {
		t.Fatal("Polling lost counts or copied the full compiled lists")
	}
}

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCustomOnlyPolicyAndNormalization(t *testing.T) {
	p := defaultPolicy()
	p.Default = "geo"
	p.CustomDomains = []string{" Example.COM. ", "full:Exact.Example.net", "domain:video.example.org"}
	p.CustomIPs = []string{"203.0.113.17/24", "198.51.100.7"}
	b, e := compileSources(context.Background(), p, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(b.IPs, []string{"198.51.100.7/32", "203.0.113.0/24"}) || len(b.Domains) != 3 {
		t.Fatalf("%+v", b)
	}
	if b.Domains[0].Name != "exact.example.net" || b.Domains[0].Suffix {
		t.Fatal(b.Domains)
	}
	if p.CustomIPs[0] != "203.0.113.17/24" || p.CustomDomains[0] != " Example.COM. " {
		t.Fatal("Compiler mutated saved policy")
	}
}

func TestCustomListSyntaxAndLineErrors(t *testing.T) {
	ips, domains := map[string]bool{}, map[string]Domain{}
	e := readCustomList(strings.NewReader("\uFEFF# My rules\r\nExample.COM # comment\nfull:example.com\nfull:a.example.com\n203.0.113.7/24\n203.0.113.0/24\n198.51.100.7\n"), ips, domains)
	if e != nil || len(ips) != 2 || !reflect.DeepEqual(sortedDomains(domains), []Domain{{"example.com", true}}) {
		t.Fatalf("%v %v %v", e, ips, domains)
	}
	for _, rule := range []string{"<html>404</html>", "regexp:.*", "keyword:video", "*.example.com", "||example.com^", "127.0.0.1 example.com", "https://example.com/path", "[Interface]", "2001:db8::/32", "999.1.2.3", "bad; /system/reset", "xn--bad_.com"} {
		e = readCustomList(strings.NewReader("# comment\n"+rule), map[string]bool{}, map[string]Domain{})
		if e == nil || !strings.Contains(e.Error(), "Line 2") {
			t.Errorf("Accepted %q or missing line: %v", rule, e)
		}
	}
	for _, text := range []string{"# comment\n", strings.Repeat("x", MaxSourceLine+1)} {
		if readCustomList(strings.NewReader(text), map[string]bool{}, map[string]Domain{}) == nil {
			t.Fatal("Accepted empty or oversized line")
		}
	}
}

func TestCustomValidationAndSourceChanges(t *testing.T) {
	old := defaultPolicy()
	for _, change := range []func(*Policy){
		func(p *Policy) { p.CustomDomains = []string{"example.com"} },
		func(p *Policy) { p.CustomIPs = []string{"203.0.113.0/24"} },
		func(p *Policy) { p.CustomURLs = []string{"https://example.com/list.txt"} },
	} {
		p := old.Clone()
		change(&p)
		if p.Validate() != nil || sameSources(old, p) {
			t.Fatal("Custom edit does not trigger compilation")
		}
	}
	for _, change := range []func(*Policy){
		func(p *Policy) { p.CustomDomains = []string{"https://example.com"} },
		func(p *Policy) { p.CustomIPs = []string{"::1"} },
		func(p *Policy) { p.CustomDomains = make([]string, MaxDomains+1) },
		func(p *Policy) { p.CustomIPs = make([]string, MaxIPs+1) },
		func(p *Policy) { p.CustomURLs = make([]string, MaxSources); p.GeoIP = []string{"telegram"} },
	} {
		p := old.Clone()
		change(&p)
		if p.Validate() == nil {
			t.Fatal("Invalid custom policy accepted")
		}
	}
}

func TestCustomAndBuiltinUnion(t *testing.T) {
	p := defaultPolicy()
	p.Default = "geo"
	p.GeoIP = []string{"telegram"}
	p.GeoSite = []string{"youtube"}
	p.CustomIPs = []string{"203.0.113.7/24"}
	p.CustomDomains = []string{"full:example.com"}
	p.CustomURLs = []string{"https://example.org/rules.txt"}
	dlc := category("YOUTUBE", domain(2, "example.com"), domain(3, "exact.example.net"))
	sum := sha256.Sum256(dlc)
	fetch := func(_ context.Context, url, path string, _ int64) error {
		data := []byte("203.0.113.0/24\n198.51.100.1\n")
		if url == dlcURL {
			data = dlc
		}
		if strings.HasSuffix(url, ".sha256sum") {
			data = []byte(hex.EncodeToString(sum[:]))
		}
		return os.WriteFile(path, data, 0600)
	}
	fetchCustom := func(_ context.Context, _, path string) error {
		return os.WriteFile(path, []byte("example.com\nfull:child.example.com\n203.0.113.0/24\n198.51.100.2\n"), 0600)
	}
	b, e := compileSourcesWith(context.Background(), p, t.TempDir(), fetch, fetchCustom)
	if e != nil || len(b.IPs) != 3 || !reflect.DeepEqual(b.Domains, []Domain{{"exact.example.net", false}, {"example.com", true}}) {
		t.Fatalf("%+v %v", b, e)
	}
	state := Saved{Policy: p, Bundle: b, Revision: "custom"}
	script := applyScript(Settings{LAN: "192.168.3.0/24"}, state, "a")
	if strings.Count(script, `"s:example.com"`) != 1 || strings.Contains(script, `"f:example.com"`) {
		t.Fatal("Duplicate RouterOS FWD names")
	}
	if routeFor(t, policyRules(p, "a"), "unknown", "198.51.100.2", true, map[string][]string{"AWG3UI-ip-a": b.IPs}) != "to-awg" {
		t.Fatal("Custom subnet did not use VPN")
	}
	if routeFor(t, policyRules(p, "a"), "unknown", "8.8.8.8", true, map[string][]string{"AWG3UI-ip-a": b.IPs}) != "main" {
		t.Fatal("Nonmatching destination should use WAN")
	}
}

func TestCustomCombinedBudgetAndDownloadFailure(t *testing.T) {
	p := defaultPolicy()
	p.CustomDomains = []string{"existing.example"}
	p.CustomIPs = []string{"203.0.113.0/24"}
	p.CustomURLs = []string{"https://example.org/rules.txt"}
	var domains, ips strings.Builder
	for i := 0; i < MaxDomains; i++ {
		fmt.Fprintf(&domains, "d%d.example\n", i)
	}
	for i := 0; i < MaxIPs; i++ {
		fmt.Fprintf(&ips, "10.0.%d.%d\n", i/256, i%256)
	}
	for _, text := range []string{domains.String(), ips.String(), "<html>error</html>"} {
		fetch := func(_ context.Context, _, path string) error { return os.WriteFile(path, []byte(text), 0600) }
		_, e := compileSourcesWith(context.Background(), p, t.TempDir(), nil, fetch)
		if e == nil || !strings.Contains(e.Error(), "Custom list 1") {
			t.Fatal("Combined limits/invalid file not rejected", e)
		}
	}
	_, e := compileSourcesWith(context.Background(), p, t.TempDir(), nil, func(context.Context, string, string) error { return errors.New("Unavailable") })
	if e == nil || !strings.Contains(e.Error(), "Custom list 1") {
		t.Fatal("Download failure not propagated")
	}
}

func TestCustomURLAndDNSGuards(t *testing.T) {
	for _, raw := range []string{"https://example.com/rules.txt?revision=1", "https://raw.githubusercontent.com/user/repo/main/rules.txt", "https://1.1.1.1/list"} {
		if e := validateCustomURL(raw); e != nil {
			t.Errorf("%s: %v", raw, e)
		}
	}
	for _, raw := range []string{"http://example.com/list", "file:///etc/passwd", "https://user:secret@example.com/list", "https://example.com:80/list", "https://example.com/#fragment", "https://localhost/list", "https://router.local/list", "https://foo.home.arpa/list", "https://127.0.0.1/list", "https://172.18.20.1/list", "https://169.254.169.254/", "https://100.64.0.1/", "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://example.com/" + strings.Repeat("x", MaxSourceURL)} {
		if validateCustomURL(raw) == nil {
			t.Errorf("Unsafe URL accepted: %s", raw)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.18.20.1", "192.168.1.135", "169.254.169.254", "100.64.0.1", "198.18.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "192.0.2.1", "::1", "::ffff:127.0.0.1"} {
		lookup := func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr(ip)}, nil
		}
		conn, e := dialSource(lookup)(context.Background(), "tcp", "public.example:443")
		if conn != nil {
			conn.Close()
		}
		if e == nil || !strings.Contains(e.Error(), "reserved") {
			t.Fatalf("Unsafe DNS answer accepted: %s %v", ip, e)
		}
	}
	c := customSourceClient()
	for _, target := range []string{"http://example.com/list", "https://127.0.0.1/list"} {
		r, _ := http.NewRequest("GET", target, nil)
		if c.CheckRedirect(r, []*http.Request{{}}) == nil {
			t.Fatal("Unsafe redirect accepted")
		}
	}
	r, _ := http.NewRequest("GET", "https://example.com/list", nil)
	if c.CheckRedirect(r, make([]*http.Request, MaxSourceRedirects)) == nil {
		t.Fatal("Redirect loop accepted")
	}
}

func TestCustomStreamingDownloadLimits(t *testing.T) {
	for _, mode := range []string{"good", "status", "empty", "large", "chunked"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "status":
					w.WriteHeader(404)
				case "large":
					w.Header().Set("Content-Length", "1000")
				case "chunked":
					w.(http.Flusher).Flush()
					fmt.Fprint(w, strings.Repeat("x", 65))
				case "good":
					fmt.Fprint(w, "example.com\n203.0.113.0/24\n")
				}
			}))
			defer s.Close()
			e := downloadWithClient(context.Background(), s.Client(), s.URL, filepath.Join(t.TempDir(), "list.txt"), 64)
			if (e == nil) != (mode == "good") {
				t.Fatalf("%s: %v", mode, e)
			}
		})
	}
}

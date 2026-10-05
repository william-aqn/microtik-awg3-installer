package main

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func field(n uint64, b []byte) []byte {
	out := binary.AppendUvarint(nil, n<<3|2)
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}
func domain(typ byte, name string) []byte { return append([]byte{8, typ}, field(2, []byte(name))...) }
func category(name string, domains ...[]byte) []byte {
	var b []byte
	for _, d := range domains {
		b = append(b, field(2, d)...)
	}
	b = append(b, field(1, []byte(name))...)
	return field(1, b)
}
func TestGeoSiteFieldOrderAndSelection(t *testing.T) {
	data := append(category("HUGE-UNSELECTED", domain(0, "keyword")), category("YOUTUBE", domain(2, "youtube.com"), domain(3, "exact.example"))...)
	got, e := readGeoSite(bytes.NewReader(data), []string{"youtube"})
	if e != nil {
		t.Fatal(e)
	}
	want := []Domain{{"exact.example", false}, {"youtube.com", true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}
func TestGeoSiteUnsupportedDoesNotSilentlyDropRules(t *testing.T) {
	for _, typ := range []byte{0, 1, 4} {
		_, e := readGeoSite(bytes.NewReader(category("X", domain(typ, "example.com"))), []string{"x"})
		if e == nil {
			t.Fatalf("accepted type %d", typ)
		}
	}
}
func TestGeoSiteMissingAndCorrupt(t *testing.T) {
	for _, data := range [][]byte{category("X", domain(2, "example.com")), {10, 128}, {10, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}, {0}, {10, 3, 18, 10, 0}} {
		if _, e := readGeoSite(bytes.NewReader(data), []string{"missing"}); e == nil {
			t.Fatal("accepted corrupt or missing category")
		}
	}
}
func TestGeoSiteDomainLimit(t *testing.T) {
	var all [][]byte
	for i := 0; i <= MaxDomains; i++ {
		all = append(all, domain(2, fmt.Sprintf("d%d.example", i)))
	}
	if _, e := readGeoSite(bytes.NewReader(category("X", all...)), []string{"x"}); e == nil {
		t.Fatal("domain budget bypass")
	}
}
func TestPrefixValidationAndIPv6(t *testing.T) {
	out := map[string]bool{}
	skip := 0
	e := readPrefixes(strings.NewReader("# test\n1.2.3.4\n1.2.3.4/32\n8.8.8.9/24\n2001:db8::/32\n"), out, &skip)
	if e != nil || skip != 1 || len(out) != 2 || !out["8.8.8.0/24"] {
		t.Fatalf("%v %+v %d", e, out, skip)
	}
	if readPrefixes(strings.NewReader("<html>error</html>"), out, &skip) == nil {
		t.Fatal("accepted HTML")
	}
}
func TestPrefixBudget(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxIPs; i++ {
		fmt.Fprintf(&b, "10.0.%d.%d\n", i/256, i%256)
	}
	skip := 0
	if readPrefixes(strings.NewReader(b.String()), map[string]bool{}, &skip) == nil {
		t.Fatal("IP budget bypass")
	}
}
func TestPolicyValidation(t *testing.T) {
	p := defaultPolicy()
	p.Devices = []Device{{"02:aa:00:00:00:01", "test", "geo"}}
	p.GeoIP = []string{"telegram"}
	if e := p.Validate(); e != nil || p.Devices[0].MAC != "02:AA:00:00:00:01" {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.Default = "unknown" }, func(p *Policy) { p.GeoIP = []string{"../../secret"} }, func(p *Policy) { p.GeoSite = []string{"x; /system/reset"} }, func(p *Policy) { p.Antifilter = []string{"https://evil.test"} }, func(p *Policy) { p.Devices = []Device{{"FF:FF:FF:FF:FF:FF", "x", "direct"}} }, func(p *Policy) {
		p.Devices = []Device{{"02:00:00:00:00:01", "x", "vpn"}, {"02:00:00:00:00:01", "y", "geo"}}
	}} {
		p := defaultPolicy()
		mutate(&p)
		if p.Validate() == nil {
			t.Fatal("unsafe policy accepted")
		}
	}
}

// Interpret the generated routing conditions independently of RouterOS. These
// cases cover direct precedence, shared destination lists, private exclusions,
// unknown devices, and the fail-closed period before volatile lists are ready.
func routeFor(t *testing.T, script, mac, ip string, ready bool, lists map[string][]string) string {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	for _, line := range strings.Split(script, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		row := map[string]string{}
		for _, f := range fields {
			if k, v, ok := strings.Cut(f, "="); ok {
				row[k] = strings.Trim(v, ";\"")
			}
		}
		if m := row["src-mac-address"]; m != "" && m != mac {
			continue
		}
		if p := row["dst-address"]; p != "" && !netip.MustParsePrefix(p).Contains(addr) {
			continue
		}
		if row["src-address-list"] != "" && !ready {
			continue
		}
		if list := row["dst-address-list"]; list != "" {
			match := false
			for _, p := range lists[list] {
				if netip.MustParsePrefix(p).Contains(addr) {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		return row["new-routing-mark"]
	}
	return "none"
}
func TestPolicyRoutingSemantics(t *testing.T) {
	p := defaultPolicy()
	p.Default = "geo"
	p.Devices = []Device{{"02:00:00:00:00:01", "direct", "direct"}, {"02:00:00:00:00:02", "vpn", "vpn"}}
	script := policyRules(p, "a")
	lists := map[string][]string{"AWG3UI-ip-a": {"1.1.1.0/24"}, "AWG3UI-dns-b": {"8.8.8.8/32"}}
	cases := []struct {
		mac, ip string
		ready   bool
		want    string
	}{{p.Devices[0].MAC, "1.1.1.1", true, "main"}, {p.Devices[1].MAC, "9.9.9.9", true, "to-awg"}, {"unknown", "1.1.1.1", true, "to-awg"}, {"unknown", "8.8.8.8", true, "to-awg"}, {"unknown", "9.9.9.9", true, "main"}, {"unknown", "9.9.9.9", false, "to-awg"}, {p.Devices[0].MAC, "9.9.9.9", false, "main"}, {p.Devices[1].MAC, "192.168.3.30", true, "main"}}
	for _, c := range cases {
		if got := routeFor(t, script, c.mac, c.ip, c.ready, lists); got != c.want {
			t.Fatalf("%+v got %s", c, got)
		}
	}
}
func TestApplyKeepsGeoClosedUntilCommitAndCleanup(t *testing.T) {
	s := Settings{LAN: "192.168.3.0/24"}
	state := Saved{Policy: defaultPolicy(), Bundle: Bundle{IPs: []string{"1.1.1.0/24"}}, Revision: "1234"}
	src := applyScript(s, state, "b")
	guard := strings.Index(src, `remove [find where list="AWG3UI-ready"]`)
	stage := strings.Index(src, `"1.1.1.0/24"`)
	commit := strings.Index(src, `jump-target=AWG3UI-b`)
	ready := strings.Index(src, `add list=AWG3UI-ready`)
	if !(guard >= 0 && stage > guard && commit > stage && ready > commit) {
		t.Fatal("invalid transaction ordering")
	}
	if !strings.Contains(src, "timeout=none-dynamic") || !strings.Contains(src, `/system/script/job/find`) {
		t.Fatal("volatile data or cross-user serialization missing")
	}
	if strings.Contains(src, "PrivateKey") || strings.Contains(src, "/user/") {
		t.Fatal("unrelated sensitive mutation")
	}
}
func testApp() *App {
	salt := []byte("0123456789abcdef")
	hash, _ := pbkdf2.Key(sha256.New, "testing-panel-password", salt, 100000, 32)
	return &App{s: Settings{Hosts: []string{"router.test"}, PasswordSalt: hex.EncodeToString(salt), PasswordHash: hex.EncodeToString(hash)}, sessions: map[string]time.Time{}, state: Saved{Policy: defaultPolicy()}}
}
func request(a *App, method, path, body, host, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	r.Header.Set("Origin", origin)
	r.Header.Set("X-AWG-Request", "1")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.serve(w, r)
	return w
}
func TestAuthenticationAndCSRF(t *testing.T) {
	a := testApp()
	if w := request(a, "GET", "/api/state", "", "router.test", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(a, "POST", "/api/login", `{"password":"testing-panel-password"}`, "router.test", "http://evil.test", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(a, "GET", "/", "", "evil.test", "", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := request(a, "POST", "/api/login", `{"password":"testing-panel-password"}`, "router.test", "http://router.test", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	if w = request(a, "POST", "/api/apply", `{"default":"bogus"}`, "router.test", "http://router.test", cookies[0]); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = request(a, "GET", "/api/toggle", "", "router.test", "", cookies[0]); w.Code != 405 {
		t.Fatal("GET mutated state")
	}
}
func TestLoginRateLimit(t *testing.T) {
	a := testApp()
	for i := 0; i < 6; i++ {
		w := request(a, "POST", "/api/login", `{"password":"wrong"}`, "router.test", "http://router.test", nil)
		if i == 5 && w.Code != 429 {
			t.Fatal(w.Code)
		}
	}
}
func TestStaticFilesCannotReadPrivateData(t *testing.T) {
	a := testApp()
	for _, path := range []string{"/settings.json", "/data/settings.json", "/../main.go"} {
		w := request(a, "GET", path, "", "router.test", "", nil)
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
}
func TestRouterTransportNoRedirectOrPasswordLeak(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://example.com", 302) }))
	defer server.Close()
	r := newRouter(Settings{RouterURL: server.URL, RouterUser: "test", RouterPassword: "never-print-this"})
	e := r.call(context.Background(), "POST", "system/resource/print", Row{}, nil)
	if e == nil || strings.Contains(e.Error(), "never-print") {
		t.Fatal(e)
	}
}
func TestStateAtomicWriteAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := Saved{Policy: defaultPolicy()}
	if e := writeJSON(path, state); e != nil {
		t.Fatal(e)
	}
	var got Saved
	if e := readJSON(path, &got); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(state, got) {
		t.Fatal("roundtrip mismatch")
	}
	if e := writeJSON(path, state); e != nil {
		t.Fatal("cannot replace state", e)
	}
	if e := os.WriteFile(path, []byte(`{"unexpected":"value"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if readJSON(path, &got) == nil {
		t.Fatal("accepted unknown keys")
	}
}
func TestDiagnosticWhitelist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		props := fmt.Sprint(body[".proplist"])
		if strings.Contains(props, "source") || strings.Contains(props, "password") || strings.Contains(props, "environment") {
			t.Errorf("sensitive diagnostic request %s", props)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	}))
	defer server.Close()
	r := newRouter(Settings{RouterURL: server.URL})
	if _, e := r.diagnostics(context.Background()); e != nil {
		t.Fatal(e)
	}
}

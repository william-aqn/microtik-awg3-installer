package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func dnsRR(t *testing.T, value string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(value)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestGeoDNSUsesOnlyRelatedAnswerAddresses(t *testing.T) {
	m, err := compileDomainMatcher([]Domain{{Name: "selected.test", Suffix: true}, {Name: `^r[0-9]+\.video\.test$`, Regexp: true}})
	if err != nil {
		t.Fatal(err)
	}
	response := &dns.Msg{Answer: []dns.RR{
		dnsRR(t, "www.selected.test. 600 IN CNAME edge.cdn.test."),
		dnsRR(t, "edge.cdn.test. 600 IN A 8.8.8.8"),
		dnsRR(t, "unrelated.test. 600 IN A 9.9.9.9"),
	}, Extra: []dns.RR{dnsRR(t, "www.selected.test. 600 IN A 1.1.1.1")}}
	ips, aliases := geoAnswerRoutes(m, "WWW.Selected.Test.", response, false)
	if len(ips) != 1 || ips["8.8.8.8"] != 300 || len(aliases) != 1 || aliases["edge.cdn.test"] != 300 {
		t.Fatal("Incorrect CNAME or unrelated-address handling", ips, aliases)
	}
	response = &dns.Msg{Answer: []dns.RR{dnsRR(t, "r123.video.test. 60 IN HTTPS 1 alternate.test. ipv4hint=8.8.4.4,1.0.0.1")}}
	ips, aliases = geoAnswerRoutes(m, "r123.video.test.", response, false)
	if len(ips) != 2 || aliases["alternate.test"] != 60 {
		t.Fatal("HTTPS hints or service target were lost", ips, aliases)
	}
	ips, _ = geoAnswerRoutes(m, "unselected.test.", response, false)
	if len(ips) != 0 {
		t.Fatal("An unrelated question learned routes")
	}
}

func TestGeoDNSForwardsUDPAndTCPOnlyAfterLearning(t *testing.T) {
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up := &dns.Server{PacketConn: upstream, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 900}, A: net.ParseIP("8.8.8.8")}}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = up.ActivateAndServe() }()
	t.Cleanup(func() { _ = up.Shutdown() })
	var learned atomic.Int32
	var reject atomic.Bool
	g := newGeoDNS("127.0.0.1", func(_ context.Context, ip string, ttl uint32) error {
		if ip != "8.8.8.8" || ttl != 300 {
			t.Error("Unexpected learned record", ip, ttl)
		}
		if reject.Load() {
			return errors.New("injected router failure")
		}
		learned.Add(1)
		return nil
	})
	g.upstreams = []string{upstream.LocalAddr().String()}
	_ = g.setDomains([]Domain{{Name: "selected.test", Suffix: true}})
	if err := g.start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.close)
	for _, protocol := range []string{"udp", "tcp"} {
		q := new(dns.Msg)
		q.SetQuestion("www.selected.test.", dns.TypeA)
		before := learned.Load()
		response, _, err := (&dns.Client{Net: protocol, Timeout: time.Second}).Exchange(q, g.servers[0].PacketConn.LocalAddr().String())
		if err != nil || response.Rcode != dns.RcodeSuccess || learned.Load() != before+1 || len(response.Answer) != 1 || response.Answer[0].Header().Ttl != 300 {
			t.Fatal("DNS response escaped before routing or lost its TTL", protocol, response, err)
		}
	}
	reject.Store(true)
	q := new(dns.Msg)
	q.SetQuestion("selected.test.", dns.TypeA)
	response, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, g.servers[0].PacketConn.LocalAddr().String())
	if err != nil || response.Rcode != dns.RcodeServerFailure || len(response.Answer) != 0 {
		t.Fatal("Routing failure leaked a usable answer", response, err)
	}
	q.SetQuestion("direct.test.", dns.TypeA)
	response, _, err = (&dns.Client{Timeout: time.Second}).Exchange(q, g.servers[0].PacketConn.LocalAddr().String())
	if err != nil || response.Rcode != dns.RcodeSuccess {
		t.Fatal("Unselected question should not need a Geo route", response, err)
	}
}

func TestDNSRegistrarUsesRAMAndBoundsGrowth(t *testing.T) {
	var mu sync.Mutex
	adds, updates := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if req.URL.Path == "/rest/ip/firewall/address-list/print" {
			_ = json.NewEncoder(w).Encode([]Row{})
			return
		}
		var row Row
		_ = json.NewDecoder(req.Body).Decode(&row)
		if req.Method == "POST" && req.URL.Path == "/rest/ip/firewall/address-list/add" {
			adds++
			if row["dynamic"] != "true" || row["timeout"] != "360s" || row["list"] != geoDNSList {
				t.Error("A learned DNS route would be persistent", row)
			}
			_ = json.NewEncoder(w).Encode(Row{"ret": "*1"})
		} else if req.Method == "POST" && req.URL.Path == "/rest/ip/firewall/address-list/set" {
			updates++
			if row["numbers"] != "*1" || len(row) != 2 {
				t.Error("Refresh was not scoped to the learned record", row)
			}
			_ = json.NewEncoder(w).Encode([]Row{})
		} else {
			t.Error("Unexpected route mutation", req.Method)
		}
	}))
	defer server.Close()
	d := newRouter(Settings{RouterURL: server.URL}).dnsRAM
	ctx := context.Background()
	if err := d.seed(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := d.learn(ctx, "8.8.8.8", 300); err != nil {
			t.Fatal(err)
		}
	}
	d.items["8.8.8.8"] = dnsLease{id: "*1", expires: time.Now().Add(time.Second), refresh: true}
	if err := d.learn(ctx, "8.8.8.8", 300); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if adds != 1 || updates != 1 {
		t.Error("Repeated answers rewrote the route unnecessarily", adds, updates)
	}
	mu.Unlock()
	for i := 0; i < MaxDNSIPs; i++ {
		d.items[time.Unix(int64(i), 0).String()] = dnsLease{expires: time.Now().Add(time.Minute)}
	}
	if err := d.learn(ctx, "9.9.9.9", 300); err == nil {
		t.Fatal("Learned-address limit was bypassed")
	}
}

func TestDNSRegistrarRecreatesOnlyMissingRecords(t *testing.T) {
	for _, tc := range []struct {
		name, detail string
		code         int
		recreate     bool
	}{
		{"expired", "no such item (4)", 400, true},
		{"not-found", "Not Found", 404, true},
		{"denied", "not enough permissions", 403, false},
		{"invalid", "invalid timeout", 400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adds := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "POST" {
					t.Error("Slow REST record operation was used")
				}
				switch req.URL.Path {
				case "/rest/ip/firewall/address-list/set":
					w.WriteHeader(tc.code)
					_ = json.NewEncoder(w).Encode(Row{"detail": tc.detail})
				case "/rest/ip/firewall/address-list/add":
					adds++
					_ = json.NewEncoder(w).Encode(Row{"ret": "*2"})
				default:
					t.Error("Unexpected table scan", req.URL.Path)
				}
			}))
			defer server.Close()
			d := newRouter(Settings{RouterURL: server.URL}).dnsRAM
			d.ready = true
			d.items["8.8.8.8"] = dnsLease{id: "*1", expires: time.Now().Add(time.Second), refresh: true}
			err := d.learn(context.Background(), "8.8.8.8", 300)
			if (err == nil) != tc.recreate || (adds == 1) != tc.recreate {
				t.Fatalf("learn error=%v, adds=%d, want recreate=%v", err, adds, tc.recreate)
			}
			if tc.recreate && d.items["8.8.8.8"].id != "*2" {
				t.Fatal("The replacement ID was not saved")
			}
		})
	}
}

func TestDNSAliasesSurviveRestartOnUSB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-aliases.json")
	g := newGeoDNS("", nil)
	g.aliasPath = path
	if err := g.rememberAliases(map[string]uint32{"target.cdn.test": 300}); err != nil {
		t.Fatal(err)
	}
	restarted := newGeoDNS("", nil)
	restarted.aliasPath = path
	if err := restarted.loadAliases(); err != nil {
		t.Fatal(err)
	}
	if restarted.aliases["target.cdn.test"] <= time.Now().Unix() {
		t.Fatal("A cached HTTPS/CNAME target lost its policy on restart")
	}
}

func TestDNSAliasWriteFailureCannotBypassRetry(t *testing.T) {
	g := newGeoDNS("", nil)
	g.aliasPath = t.TempDir() // A directory cannot be replaced with the cache file.
	for i := 0; i < 2; i++ {
		if err := g.rememberAliases(map[string]uint32{"target.test": 300}); err == nil {
			t.Fatal("USB failure was ignored on retry")
		}
		if len(g.aliases) != 0 {
			t.Fatal("Unpersisted aliases became usable")
		}
	}
}

func TestDNSRouteCacheRestoresColdRAMAndRetriesUSBFailure(t *testing.T) {
	var adds atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/rest/ip/firewall/address-list/print" {
			_ = json.NewEncoder(w).Encode([]Row{})
		} else {
			if req.Method != "POST" {
				t.Error("DNS learning used a table-scanning REST method", req.Method)
			}
			if req.URL.Path == "/rest/ip/firewall/address-list/add" {
				adds.Add(1)
			}
			_ = json.NewEncoder(w).Encode(Row{"ret": "*1"})
		}
	}))
	defer server.Close()
	s := Settings{RouterURL: server.URL, DataDir: t.TempDir()}
	d := newRouter(s).dnsRAM
	ctx := context.Background()
	if err := d.seed(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.learn(ctx, "8.8.8.8", 300); err != nil {
		t.Fatal(err)
	}
	restarted := newRouter(s).dnsRAM
	if err := restarted.seed(ctx); err != nil {
		t.Fatal(err)
	}
	if adds.Load() != 2 || !restarted.ready || len(restarted.items) != 1 {
		t.Fatal("A reboot lost a still-cached client's route")
	}
	bad := filepath.Join(t.TempDir(), "blocked")
	if err := os.Mkdir(bad, 0700); err != nil {
		t.Fatal(err)
	}
	d.path = bad
	for i := 0; i < 2; i++ {
		if err := d.learn(ctx, "9.9.9.9", 300); err == nil {
			t.Fatal("An unpersisted route released a DNS answer")
		}
	}
	if adds.Load() != 3 {
		t.Fatal("A failed USB write duplicated a RAM route")
	}
}

func TestGeoDNSRetriesTruncatedUpstreamOverTCP(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	var tcpQueries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(q)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			response.Truncated = true
		} else {
			tcpQueries.Add(1)
			response.Answer = []dns.RR{dnsRR(t, "selected.test. 60 IN A 8.8.4.4")}
		}
		_ = w.WriteMsg(response)
	})
	for _, up := range []*dns.Server{{PacketConn: udp, Handler: handler}, {Listener: tcp, Handler: handler}} {
		go func() { _ = up.ActivateAndServe() }()
		t.Cleanup(func() { _ = up.Shutdown() })
	}
	var learned atomic.Int32
	g := newGeoDNS("127.0.0.1", func(context.Context, string, uint32) error { learned.Add(1); return nil })
	g.upstreams = []string{udp.LocalAddr().String()}
	_ = g.setDomains([]Domain{{Name: "selected.test", Suffix: true}})
	if err := g.start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.close)
	q := new(dns.Msg)
	q.SetQuestion("selected.test.", dns.TypeA)
	response, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, g.servers[0].PacketConn.LocalAddr().String())
	if err != nil || response.Truncated || response.Rcode != dns.RcodeSuccess || learned.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatal("Truncated upstream response was not resolved safely over TCP", response, err)
	}
	private := newGeoDNS("192.0.2.1", nil)
	if err := private.start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(private.close)
	response, _, err = (&dns.Client{Timeout: time.Second}).Exchange(q, private.servers[0].PacketConn.LocalAddr().String())
	if err != nil || response.Rcode != dns.RcodeRefused || learned.Load() != 1 {
		t.Fatal("DNS accepted a client other than the router", response, err)
	}
}

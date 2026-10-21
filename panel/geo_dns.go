package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const geoDNSListen = "172.18.20.2:53"
const geoDNSList = "AWG3UI-dns-live"
const geoDNSTTL = 300

type domainMatcher struct {
	exact, suffix map[string]bool
	patterns      []*regexp.Regexp
}

func compileDomainMatcher(domains []Domain) (*domainMatcher, error) {
	if err := (Bundle{Domains: domains}).Validate(); err != nil {
		return nil, err
	}
	m := &domainMatcher{exact: map[string]bool{}, suffix: map[string]bool{}}
	for _, d := range domains {
		if d.Regexp {
			r, err := regexp.CompilePOSIX(d.Name)
			if err != nil {
				return nil, errors.New("Invalid Geo domain expression")
			}
			m.patterns = append(m.patterns, r)
		} else if d.Suffix {
			m.suffix[d.Name] = true
		} else {
			m.exact[d.Name] = true
		}
	}
	return m, nil
}

func dnsName(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }
func (m *domainMatcher) matches(name string) bool {
	name = dnsName(name)
	if m.exact[name] {
		return true
	}
	for part := name; part != ""; {
		if m.suffix[part] {
			return true
		}
		_, part, _ = strings.Cut(part, ".")
	}
	for _, r := range m.patterns {
		if r.MatchString(name) {
			return true
		}
	}
	return false
}

// Only addresses reachable from the question through its CNAME chain belong
// to an answer. Unrelated additional records must not poison routing lists.
func geoAnswerRoutes(m *domainMatcher, question string, response *dns.Msg, force bool) (map[string]uint32, map[string]uint32) {
	names := map[string]bool{dnsName(question): true}
	for pass := 0; pass < 16; pass++ {
		changed := false
		for _, record := range response.Answer {
			if c, ok := record.(*dns.CNAME); ok && names[dnsName(c.Hdr.Name)] && !names[dnsName(c.Target)] {
				names[dnsName(c.Target)] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	selected := force
	for name := range names {
		selected = selected || m.matches(name)
	}
	addresses := map[string]uint32{}
	aliases := map[string]uint32{}
	if !selected {
		return addresses, aliases
	}
	alias := func(name string, ttl uint32) {
		name = dnsName(name)
		if validDomain(name) && !m.matches(name) {
			aliases[name] = max(aliases[name], min(ttl, geoDNSTTL))
		}
	}
	add := func(ip net.IP, ttl uint32) {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !publicIPv4(addr.Unmap()) {
			return
		}
		key := addr.Unmap().String()
		addresses[key] = max(addresses[key], min(ttl, geoDNSTTL))
	}
	for _, record := range response.Answer {
		if !names[dnsName(record.Header().Name)] {
			continue
		}
		switch rr := record.(type) {
		case *dns.CNAME:
			alias(rr.Target, rr.Hdr.Ttl)
		case *dns.A:
			add(rr.A, rr.Hdr.Ttl)
		case *dns.HTTPS:
			alias(rr.Target, rr.Hdr.Ttl)
			for _, value := range rr.Value {
				if hint, ok := value.(*dns.SVCBIPv4Hint); ok {
					for _, ip := range hint.Hint {
						add(ip, rr.Hdr.Ttl)
					}
				}
			}
		case *dns.SVCB:
			alias(rr.Target, rr.Hdr.Ttl)
			for _, value := range rr.Value {
				if hint, ok := value.(*dns.SVCBIPv4Hint); ok {
					for _, ip := range hint.Hint {
						add(ip, rr.Hdr.Ttl)
					}
				}
			}
		}
	}
	return addresses, aliases
}

type dnsLease struct {
	id      string
	expires time.Time
	refresh bool
}

// Learned addresses have timeouts and live only in RouterOS RAM. Rule names
// and the compiled source snapshot stay in the container's USB data directory.
type dnsRegistrar struct {
	mu     sync.Mutex
	router *Router
	items  map[string]dnsLease
	ready  bool
	path   string
}

func (d *dnsRegistrar) seed(ctx context.Context) error {
	d.mu.Lock()
	ready := d.ready
	d.mu.Unlock()
	if ready {
		return nil
	}
	rows, err := d.router.rows(ctx, "ip/firewall/address-list", ".id,address,dynamic", "list="+geoDNSList)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ready {
		return nil
	}
	if len(rows) > MaxDNSIPs {
		return errors.New("Too many learned Geo DNS addresses; inspect diagnostics")
	}
	for _, row := range rows {
		addr, err := netip.ParseAddr(strings.TrimSuffix(row["address"], "/32"))
		if err != nil || !publicIPv4(addr) || !routerRecordID.MatchString(row[".id"]) || row["dynamic"] != "true" {
			return errors.New("Unexpected persistent or invalid record in the Geo DNS RAM list")
		}
		d.items[addr.String()] = dnsLease{id: row[".id"], expires: time.Now().Add((geoDNSTTL + 60) * time.Second), refresh: true}
	}
	// Clients can keep DNS answers across a router reboot. Restore their still
	// valid routes from USB before Geo becomes ready, even if RouterOS lost RAM.
	if d.path != "" {
		var saved map[string]int64
		if err := readJSON(d.path, &saved); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("Cannot read DNS route cache from USB")
		}
		if len(saved) > MaxDNSIPs {
			return errors.New("DNS route cache exceeds its RAM budget")
		}
		now := time.Now().Unix()
		for ip, expiry := range saved {
			addr, err := netip.ParseAddr(ip)
			if err != nil || !publicIPv4(addr) || addr.String() != ip {
				return errors.New("Invalid DNS route cache on USB")
			}
			if expiry > now {
				ttl := uint32(max(0, min(expiry-now-60, geoDNSTTL)))
				if err := d.learnLocked(ctx, ip, ttl, false); err != nil {
					return fmt.Errorf("Cannot restore DNS RAM route: %w", err)
				}
			}
		}
		if err := d.saveLocked(); err != nil {
			return err
		}
	}
	d.ready = true
	return nil
}

func (d *dnsRegistrar) saveLocked() error {
	if d.path == "" {
		return nil
	}
	saved := make(map[string]int64, len(d.items))
	for ip, lease := range d.items {
		saved[ip] = lease.expires.Unix()
	}
	if err := writeJSON(d.path, saved); err != nil {
		return errors.New("Cannot save DNS route cache on USB")
	}
	return nil
}

func (d *dnsRegistrar) learn(ctx context.Context, address string, ttl uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.ready {
		return errors.New("Geo DNS RAM state is not restored yet")
	}
	return d.learnLocked(ctx, address, ttl, true)
}

func (d *dnsRegistrar) learnLocked(ctx context.Context, address string, ttl uint32, persist bool) error {
	now := time.Now()
	for ip, item := range d.items {
		if !now.Before(item.expires) {
			delete(d.items, ip)
		}
	}
	want := time.Duration(min(ttl, geoDNSTTL)+60) * time.Second
	store := func(id string) error {
		d.items[address] = dnsLease{id: id, expires: now.Add(want), refresh: true}
		if persist {
			if err := d.saveLocked(); err != nil {
				return err // A retry must save again before releasing the answer.
			}
		}
		d.items[address] = dnsLease{id: id, expires: now.Add(want)}
		return nil
	}
	old, exists := d.items[address]
	if exists && !old.refresh && old.expires.Sub(now) > time.Duration(ttl+5)*time.Second {
		return nil
	}
	fields := Row{"timeout": fmt.Sprintf("%ds", int(want/time.Second))}
	if exists {
		change := Row{"numbers": old.id, "timeout": fields["timeout"]}
		if err := d.router.call(ctx, "POST", "ip/firewall/address-list/set", change, nil); err == nil {
			return store(old.id)
		} else if !strings.Contains(err.Error(), "HTTP 404") && !(strings.Contains(err.Error(), "HTTP 400") && strings.Contains(err.Error(), "no such item")) {
			return err
		}
	}
	if !exists && len(d.items) >= MaxDNSIPs {
		return errors.New("Geo DNS RAM address limit reached; choose fewer domains")
	}
	fields["list"], fields["address"], fields["comment"] = geoDNSList, address, Tag+"DNS RAM"
	fields["dynamic"] = "true"
	var row Row
	// REST PUT/PATCH returns the complete record and scans the large table.
	// Console add/set commands return only the ID/acknowledgement (milliseconds
	// instead of seconds per DNS address on the tested hAP ac2).
	if err := d.router.call(ctx, "POST", "ip/firewall/address-list/add", fields, &row); err != nil {
		return err
	}
	if !routerRecordID.MatchString(row["ret"]) {
		return errors.New("Router did not confirm the temporary DNS address")
	}
	return store(row["ret"])
}

type GeoDNS struct {
	mu        sync.RWMutex
	matcher   *domainMatcher
	upstreams []string
	lastError string
	queries   uint64
	learned   uint64
	semaphore chan struct{}
	allowed   string
	register  func(context.Context, string, uint32) error
	servers   []*dns.Server
	aliases   map[string]int64
	aliasPath string
}

func newGeoDNS(allowed string, register func(context.Context, string, uint32) error) *GeoDNS {
	m, _ := compileDomainMatcher(nil)
	return &GeoDNS{allowed: allowed, register: register, matcher: m, semaphore: make(chan struct{}, 16), aliases: map[string]int64{}}
}

func (g *GeoDNS) loadAliases() error {
	if g.aliasPath == "" {
		return nil
	}
	var aliases map[string]int64
	if err := readJSON(g.aliasPath, &aliases); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("Cannot read DNS alias cache from USB")
	}
	if len(aliases) > MaxDomains {
		return errors.New("DNS alias cache exceeds its RAM budget")
	}
	now := time.Now().Unix()
	for name, expiry := range aliases {
		if !validDomain(name) || name != dnsName(name) {
			return errors.New("Invalid DNS alias cache on USB")
		}
		if expiry > now {
			// A router clock correction cannot retain aliases indefinitely.
			g.aliases[name] = min(expiry, now+geoDNSTTL+60)
		}
	}
	return nil
}

func (g *GeoDNS) rememberAliases(aliases map[string]uint32) error {
	if len(aliases) == 0 {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now().Unix()
	for name, expiry := range g.aliases {
		if expiry <= now {
			delete(g.aliases, name)
		}
	}
	changed := false
	for name, ttl := range aliases {
		changed = changed || g.aliases[name] <= now+int64(ttl)+5
	}
	if !changed {
		return nil
	}
	next := make(map[string]int64, len(g.aliases)+len(aliases))
	for name, expiry := range g.aliases {
		next[name] = expiry
	}
	for name, ttl := range aliases {
		next[name] = max(next[name], now+int64(ttl)+60)
	}
	if len(next) > MaxDomains {
		return errors.New("Geo DNS alias limit reached")
	}
	if g.aliasPath != "" {
		if err := writeJSON(g.aliasPath, next); err != nil {
			return errors.New("Cannot save DNS alias cache on USB")
		}
	}
	g.aliases = next
	return nil
}

func (g *GeoDNS) setDomains(domains []Domain) error {
	m, err := compileDomainMatcher(domains)
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.matcher = m
	g.mu.Unlock()
	return nil
}

func (g *GeoDNS) setUpstreams(ips []string) {
	g.mu.Lock()
	g.upstreams = make([]string, len(ips))
	for i, ip := range ips {
		g.upstreams[i] = net.JoinHostPort(ip, "53")
	}
	g.mu.Unlock()
}

func (g *GeoDNS) status() map[string]any {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return map[string]any{"storage": "USB + RAM", "queries": g.queries, "learned": g.learned, "error": g.lastError}
}

func (g *GeoDNS) start(address string) error {
	udp, err := net.ListenPacket("udp4", address)
	if err != nil {
		return errors.New("Cannot bind the private Geo DNS UDP listener")
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		return errors.New("Cannot bind the private Geo DNS TCP listener")
	}
	g.servers = []*dns.Server{
		{PacketConn: udp, Handler: g, UDPSize: 4096},
		{Listener: tcp, Handler: g, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, MaxTCPQueries: 32},
	}
	for _, server := range g.servers {
		go func() {
			if err := server.ActivateAndServe(); err != nil {
				g.mu.Lock()
				g.lastError = "Geo DNS listener stopped unexpectedly"
				g.mu.Unlock()
			}
		}()
	}
	return nil
}

func (g *GeoDNS) close() {
	for _, server := range g.servers {
		_ = server.Shutdown()
	}
}

func (g *GeoDNS) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	answer := new(dns.Msg)
	answer.SetRcode(request, dns.RcodeServerFailure)
	defer func() {
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			size := uint16(512)
			if opt := request.IsEdns0(); opt != nil {
				size = max(512, min(opt.UDPSize(), 4096))
			}
			answer.Truncate(int(size))
		}
		_ = w.WriteMsg(answer)
	}()
	peer, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil || peer != g.allowed {
		answer.SetRcode(request, dns.RcodeRefused)
		return
	}
	if request.Opcode != dns.OpcodeQuery || request.Response || len(request.Question) != 1 || request.Question[0].Qclass != dns.ClassINET {
		answer.SetRcode(request, dns.RcodeFormatError)
		return
	}
	if request.Question[0].Qtype == dns.TypeAXFR || request.Question[0].Qtype == dns.TypeIXFR {
		answer.SetRcode(request, dns.RcodeRefused)
		return
	}
	select {
	case g.semaphore <- struct{}{}:
		defer func() { <-g.semaphore }()
	default:
		return
	}
	g.mu.Lock()
	upstreams := append([]string(nil), g.upstreams...)
	g.queries++
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	query := request.Copy()
	query.Id = dns.Id()
	var response *dns.Msg
	for _, upstream := range upstreams {
		client := &dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: 4096}
		response, _, err = client.ExchangeContext(ctx, query, upstream)
		if err == nil && response.Truncated {
			client.Net = "tcp"
			response, _, err = client.ExchangeContext(ctx, query, upstream)
		}
		if err == nil && !response.Truncated {
			break
		}
		response = nil
	}
	if response == nil || !response.Response || response.Opcode != dns.OpcodeQuery || len(response.Question) != 1 || !strings.EqualFold(response.Question[0].Name, request.Question[0].Name) || response.Question[0].Qtype != request.Question[0].Qtype || response.Question[0].Qclass != dns.ClassINET {
		g.mu.Lock()
		g.lastError = "Geo DNS upstream unavailable; check the VPN connection"
		g.mu.Unlock()
		return
	}
	if len(response.Answer) > 128 {
		return
	}
	g.mu.RLock()
	force := g.aliases[dnsName(request.Question[0].Name)] > time.Now().Unix()
	addresses, aliases := geoAnswerRoutes(g.matcher, request.Question[0].Name, response, force)
	g.mu.RUnlock()
	if len(addresses) > 64 || len(aliases) > 64 {
		return
	}
	if err = g.rememberAliases(aliases); err != nil {
		g.mu.Lock()
		g.lastError = err.Error()
		g.mu.Unlock()
		return
	}
	for address, ttl := range addresses {
		if err = g.register(ctx, address, ttl); err != nil {
			g.mu.Lock()
			g.lastError = "Geo DNS routing failed: " + err.Error()
			g.mu.Unlock()
			return // Never release a selected answer before its RAM route exists.
		}
	}
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range section {
			if record.Header().Rrtype != dns.TypeOPT {
				record.Header().Ttl = min(record.Header().Ttl, geoDNSTTL)
			}
		}
	}
	response.Id = request.Id
	answer = response
	g.mu.Lock()
	g.lastError = ""
	g.learned += uint64(len(addresses))
	g.mu.Unlock()
}

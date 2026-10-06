package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	MaxCustomDownload  = 1 << 20
	MaxSourceURL       = 2048
	MaxSourceLine      = 4096
	MaxSourceRedirects = 5
)

// Custom sources are plain data. No regex, script, hosts or adblock syntax.
func customDomain(s string) (Domain, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	d := Domain{Suffix: true}
	if strings.HasPrefix(s, "full:") {
		d.Suffix = false
		s = strings.TrimPrefix(s, "full:")
	} else {
		s = strings.TrimPrefix(s, "domain:")
	}
	d.Name = strings.TrimSuffix(s, ".")
	_, ipError := netip.ParseAddr(d.Name)
	if !validDomain(d.Name) || !strings.Contains(d.Name, ".") || ipError == nil || numericHost(d.Name) {
		return Domain{}, errors.New("Use a domain like example.com or full:host.example.com; no URL, wildcard, regex or IP")
	}
	return d, nil
}

func numericHost(s string) bool {
	return strings.Trim(s, "0123456789.") == ""
}

func customPrefix(s string) (string, error) {
	s = strings.TrimSpace(s)
	p, e := netip.ParsePrefix(s)
	if e != nil {
		a, ae := netip.ParseAddr(s)
		if ae != nil {
			return "", errors.New("Use an IPv4 address or subnet, for example 203.0.113.0/24")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.Addr().Is4() {
		return "", errors.New("Custom rules support IPv4 only")
	}
	return p.Masked().String(), nil
}

func (p *Policy) validateCustom() error {
	if len(p.CustomDomains) > MaxDomains || len(p.CustomIPs) > MaxIPs {
		return fmt.Errorf("Custom rules exceed the budget: %d domains / %d IPv4 prefixes", MaxDomains, MaxIPs)
	}
	for i, s := range p.CustomDomains {
		d, e := customDomain(s)
		if e != nil {
			return fmt.Errorf("Custom domain %d: %w", i+1, e)
		}
		p.CustomDomains[i] = d.Name
		if !d.Suffix {
			p.CustomDomains[i] = "full:" + d.Name
		}
	}
	for i, s := range p.CustomIPs {
		ip, e := customPrefix(s)
		if e != nil {
			return fmt.Errorf("Custom subnet %d: %w", i+1, e)
		}
		p.CustomIPs[i] = ip
	}
	for i, s := range p.CustomURLs {
		s = strings.TrimSpace(s)
		if e := validateCustomURL(s); e != nil {
			return fmt.Errorf("Custom list %d: %w", i+1, e)
		}
		p.CustomURLs[i] = s
	}
	return nil
}

// The suffix rule wins over the exact rule for the same name: RouterOS cannot
// add two FWD records with an identical name. Budgets apply to the whole union.
func addDomain(out map[string]Domain, d Domain) error {
	old, exists := out[d.Name]
	d.Suffix = d.Suffix || exists && old.Suffix
	out[d.Name] = d
	if len(out) > MaxDomains {
		return fmt.Errorf("Combined lists exceed %d domains; nothing was truncated", MaxDomains)
	}
	return nil
}

func sortedDomains(out map[string]Domain) []Domain {
	domains := make([]Domain, 0, len(out))
	for _, d := range out {
		covered := false
		parent := d.Name
		for {
			_, parent, _ = strings.Cut(parent, ".")
			if parent == "" {
				break
			}
			if rule, ok := out[parent]; ok && rule.Suffix {
				covered = true
				break
			}
		}
		if !covered {
			domains = append(domains, d)
		}
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })
	return domains
}

func addCustomIP(out map[string]bool, ip string) error {
	out[ip] = true
	if len(out) > MaxIPs {
		return fmt.Errorf("Combined lists exceed %d IPv4 prefixes; nothing was truncated", MaxIPs)
	}
	return nil
}

func readCustomList(r io.Reader, ips map[string]bool, domains map[string]Domain) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), MaxSourceLine)
	lineNo, entries := 0, 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(scanner.Text(), "\uFEFF"), "#", 2)[0])
		if line == "" {
			continue
		}
		entries++
		var e error
		ip, ipErr := customPrefix(line)
		if ipErr == nil {
			e = addCustomIP(ips, ip)
		} else {
			var d Domain
			d, e = customDomain(line)
			if e == nil {
				e = addDomain(domains, d)
			}
		}
		if e != nil {
			return fmt.Errorf("Line %d: %w", lineNo, e)
		}
	}
	if scanner.Err() != nil {
		return errors.New("Cannot read text list or a line exceeds 4 KiB")
	}
	if entries == 0 {
		return errors.New("Text list has no rules")
	}
	return nil
}

func validateCustomURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > MaxSourceURL || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("Use a public HTTPS file URL on port 443, without credentials or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip, e := netip.ParseAddr(host); e == nil {
		if !publicSourceIP(ip) {
			return errors.New("List URL must not point to a local or reserved address")
		}
	} else if !validDomain(host) || !strings.Contains(host, ".") || numericHost(host) || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".home.arpa") {
		return errors.New("List URL must use a public internet hostname")
	}
	return nil
}

var reservedSourceIPs = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
}

func publicSourceIP(ip netip.Addr) bool {
	// This deployment is IPv4-only; reject IPv6, including mapped IPv4 forms.
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reservedSourceIPs {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

type sourceLookup func(context.Context, string, string) ([]netip.Addr, error)

func dialSource(lookup sourceLookup) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil || port != "443" {
			return nil, errors.New("Invalid source address")
		}
		ips, e := lookup(ctx, "ip4", host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("Cannot resolve list hostname")
		}
		for _, ip := range ips {
			if !publicSourceIP(ip) {
				return nil, errors.New("List hostname resolves to a local or reserved address")
			}
		}
		// Dial the checked IP directly, preventing a second DNS lookup/rebinding.
		d := net.Dialer{Timeout: 15 * time.Second}
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("Cannot connect to list host")
	}
}

func customSourceClient() *http.Client {
	return &http.Client{
		Timeout:   time.Minute,
		Transport: &http.Transport{DialContext: dialSource(net.DefaultResolver.LookupNetIP), DisableKeepAlives: true, TLSHandshakeTimeout: 15 * time.Second, MaxResponseHeaderBytes: 16 << 10},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= MaxSourceRedirects {
				return errors.New("Too many source redirects")
			}
			return validateCustomURL(r.URL.String())
		},
	}
}

func downloadCustom(ctx context.Context, raw, path string) error {
	if e := validateCustomURL(raw); e != nil {
		return e
	}
	return downloadWithClient(ctx, customSourceClient(), raw, path, MaxCustomDownload)
}

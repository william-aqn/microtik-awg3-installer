package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const dlcURL = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"

// Fetch into USB-backed files. Never load the complete GeoSite database into RAM.
func download(ctx context.Context, url, path string, limit int64) error {
	c := &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{MaxIdleConns: 1, DisableKeepAlives: true}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || r.URL.Scheme != "https" {
			return errors.New("Unsafe download redirect")
		}
		switch r.URL.Hostname() {
		case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "raw.githubusercontent.com", "antifilter.download":
			return nil
		}
		return errors.New("Unexpected download host")
	}}
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return e
	}
	resp, e := c.Do(req)
	if e != nil {
		return errors.New("Source download failed; check DNS, time and internet")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Source returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return errors.New("Source exceeds download size limit")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if n > limit {
		return errors.New("Source exceeds download size limit")
	}
	if n == 0 {
		return errors.New("Empty source")
	}
	return nil
}

func readPrefixes(r io.Reader, out map[string]bool, skipped *int) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		p, e := netip.ParsePrefix(line)
		if e != nil {
			a, ae := netip.ParseAddr(line)
			if ae != nil {
				return errors.New("Source contains an invalid address; existing lists were kept")
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !p.Addr().Is4() {
			*skipped++
			continue
		}
		out[p.Masked().String()] = true
		if len(out) > MaxIPs {
			return fmt.Errorf("IPv4 list exceeds %d prefixes; choose a smaller category. Nothing was truncated", MaxIPs)
		}
	}
	return scanner.Err()
}

// GeoSite is a protobuf: GeoSiteList.entry(1), GeoSite.country_code(1),
// GeoSite.domain(2); Domain.type(1), Domain.value(2), Domain.attribute(3).
// Parse length-delimited fields directly from a file, including arbitrary field
// order. Unselected categories are skipped without allocating their contents.
func pbField(f io.ReadSeeker, end int64) (uint64, uint64, int64, int64, error) {
	pos, e := f.Seek(0, io.SeekCurrent)
	if e != nil {
		return 0, 0, 0, 0, e
	}
	if pos == end {
		return 0, 0, 0, 0, io.EOF
	}
	if pos > end {
		return 0, 0, 0, 0, errors.New("Invalid protobuf boundary")
	}
	key, e := pbVarint(f)
	if e != nil {
		return 0, 0, 0, 0, e
	}
	field, wire := key>>3, key&7
	if field == 0 {
		return 0, 0, 0, 0, errors.New("Invalid protobuf field")
	}
	var size int64
	var val uint64
	switch wire {
	case 0:
		val, e = pbVarint(f)
	case 1:
		size = 8
	case 2:
		var n uint64
		n, e = pbVarint(f)
		if n > MaxDownload {
			return 0, 0, 0, 0, errors.New("Protobuf field too large")
		}
		size = int64(n)
	case 5:
		size = 4
	default:
		return 0, 0, 0, 0, errors.New("Unsupported protobuf wire type")
	}
	if e != nil {
		return 0, 0, 0, 0, e
	}
	start, e := f.Seek(0, io.SeekCurrent)
	if e != nil {
		return 0, 0, 0, 0, e
	}
	if start+size > end {
		return 0, 0, 0, 0, io.ErrUnexpectedEOF
	}
	if wire == 0 {
		return field, wire, int64(val), start, nil
	}
	return field, wire, start, start + size, nil
}
func pbVarint(r io.Reader) (uint64, error) {
	var n uint64
	var b [1]byte
	for i := 0; i < 10; i++ {
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, e
		}
		if i == 9 && b[0] > 1 {
			return 0, errors.New("Protobuf varint overflow")
		}
		n |= uint64(b[0]&127) << uint(i*7)
		if b[0] < 128 {
			return n, nil
		}
	}
	return 0, errors.New("Protobuf varint overflow")
}
func pbString(f io.ReadSeeker, start, end int64, limit int) (string, error) {
	if end-start > int64(limit) {
		return "", errors.New("Protobuf string too large")
	}
	b := make([]byte, int(end-start))
	if _, e := f.Seek(start, io.SeekStart); e != nil {
		return "", e
	}
	_, e := io.ReadFull(f, b)
	return string(b), e
}
func pbDomain(f io.ReadSeeker, end int64) (Domain, error) {
	var d Domain
	typ := int64(0)
	for {
		k, w, s, n, e := pbField(f, end)
		if e == io.EOF {
			break
		}
		if e != nil {
			return d, e
		}
		if k == 1 && w == 0 {
			typ = s
		}
		if k == 2 && w == 2 {
			d.Name, e = pbString(f, s, n, 253)
			if e != nil {
				return d, e
			}
		}
		if _, e = f.Seek(n, io.SeekStart); e != nil {
			return d, e
		}
	}
	if typ != 2 && typ != 3 {
		return d, errors.New("Selected GeoSite category contains regexp/keyword rules unsupported by RouterOS DNS; category was rejected in full")
	}
	d.Name = strings.ToLower(d.Name)
	d.Suffix = typ == 2
	if !validDomain(d.Name) {
		return d, errors.New("Invalid domain in GeoSite source")
	}
	return d, nil
}
func readGeoSite(f io.ReadSeeker, selected []string) ([]Domain, error) {
	end, e := f.Seek(0, io.SeekEnd)
	if e != nil {
		return nil, e
	}
	if end > MaxDownload {
		return nil, errors.New("GeoSite file too large")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, e
	}
	wanted := map[string]bool{}
	found := map[string]bool{}
	domains := map[Domain]bool{}
	for _, s := range selected {
		wanted[strings.ToUpper(s)] = true
	}
	for {
		k, w, s, n, e := pbField(f, end)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if k == 1 && w == 2 {
			var name string
			for {
				ck, cw, cs, cn, ce := pbField(f, n)
				if ce == io.EOF {
					break
				}
				if ce != nil {
					return nil, ce
				}
				if ck == 1 && cw == 2 {
					name, ce = pbString(f, cs, cn, 64)
					if ce != nil {
						return nil, ce
					}
				}
				if _, ce = f.Seek(cn, io.SeekStart); ce != nil {
					return nil, ce
				}
			}
			if wanted[name] {
				found[name] = true
				if _, e = f.Seek(s, io.SeekStart); e != nil {
					return nil, e
				}
				for {
					dk, dw, _, dn, de := pbField(f, n)
					if de == io.EOF {
						break
					}
					if de != nil {
						return nil, de
					}
					if dk == 2 && dw == 2 {
						d, de := pbDomain(f, dn)
						if de != nil {
							return nil, de
						}
						domains[d] = true
						if len(domains) > MaxDomains {
							return nil, fmt.Errorf("GeoSite exceeds %d domains; nothing was truncated", MaxDomains)
						}
					}
					if _, de = f.Seek(dn, io.SeekStart); de != nil {
						return nil, de
					}
				}
			}
		}
		if _, e = f.Seek(n, io.SeekStart); e != nil {
			return nil, e
		}
	}
	for name := range wanted {
		if !found[name] {
			return nil, fmt.Errorf("GeoSite category not found: %s", name)
		}
	}
	out := make([]Domain, 0, len(domains))
	for d := range domains {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return !out[i].Suffix && out[j].Suffix
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func compileSources(ctx context.Context, p Policy, dir string) (Bundle, error) {
	p = p.Clone()
	b := Bundle{Downloaded: time.Now().UTC().Format(time.RFC3339)}
	if e := p.Validate(); e != nil {
		return b, e
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return b, e
	}
	tmp, e := os.MkdirTemp(dir, "source-")
	if e != nil {
		return b, e
	}
	defer os.RemoveAll(tmp)
	ips := map[string]bool{}
	urls := []string{}
	for _, s := range p.GeoIP {
		urls = append(urls, "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/"+s+".txt")
	}
	for _, s := range p.Antifilter {
		urls = append(urls, antiURLs[s])
	}
	for _, url := range urls {
		path := filepath.Join(tmp, "ip.txt")
		if e = download(ctx, url, path, 4<<20); e != nil {
			return b, e
		}
		f, e := os.Open(path)
		if e != nil {
			return b, e
		}
		e = readPrefixes(f, ips, &b.IPv6Skipped)
		f.Close()
		if e != nil {
			return b, e
		}
	}
	for ip := range ips {
		b.IPs = append(b.IPs, ip)
	}
	sort.Strings(b.IPs)
	if len(p.GeoSite) > 0 {
		path := filepath.Join(tmp, "dlc.dat")
		sumPath := filepath.Join(tmp, "sha256")
		if e = download(ctx, dlcURL, path, MaxDownload); e != nil {
			return b, e
		}
		if e = download(ctx, dlcURL+".sha256sum", sumPath, 1024); e != nil {
			return b, e
		}
		sum, e := os.ReadFile(sumPath)
		if e != nil {
			return b, e
		}
		fields := strings.Fields(string(sum))
		if len(fields) == 0 || len(fields[0]) != 64 {
			return b, errors.New("Invalid GeoSite checksum file")
		}
		f, e := os.Open(path)
		if e != nil {
			return b, e
		}
		defer f.Close()
		h := sha256.New()
		if _, e = io.Copy(h, f); e != nil {
			return b, e
		}
		if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(fields[0]) {
			return b, errors.New("GeoSite checksum mismatch; retry after the upstream release finishes")
		}
		b.Domains, e = readGeoSite(f, p.GeoSite)
		if e != nil {
			return b, e
		}
	}
	if len(urls)+len(p.GeoSite) > 0 && len(b.IPs)+len(b.Domains) == 0 {
		return b, errors.New("Selected sources have no supported IPv4 entries")
	}
	return b, b.Validate()
}

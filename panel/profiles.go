package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxProfiles = 16
const MaxConfigBytes = 16384

type VPNConfig struct {
	Text    string
	Values  map[string]string
	Address string
	DNS     []string
	MTU     int
	Host    string
	Port    int
}

var configKeys = map[string]string{
	"privatekey": "private_key", "listenport": "listen_port", "jc": "jc", "jmin": "jmin", "jmax": "jmax",
	"s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4", "h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4",
	"i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5", "headerprotectionkey": "header_protection_key",
	"contentpaddingaddition": "content_padding_addition", "rekeyaftertime": "rekey_after_time", "rekeytimeout": "rekey_timeout",
	"rejectaftertime": "reject_after_time", "keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts",
	"randomtrailers": "random_trailers", "disablecookies": "disable_cookies",
}
var peerKeys = map[string]bool{"publickey": true, "presharedkey": true, "endpoint": true, "allowedips": true, "persistentkeepalive": true}
var profileID = regexp.MustCompile(`^[a-f0-9]{16}$`)
var hexPacket = regexp.MustCompile(`<b\s*0x([^>]*)>`)

func parseVPNConfig(text string) (VPNConfig, error) {
	c := VPNConfig{Values: map[string]string{}, MTU: 1280, DNS: []string{"1.1.1.1", "1.0.0.1"}}
	text = strings.TrimPrefix(text, "\ufeff")
	if len(text) == 0 || len(text) > MaxConfigBytes || strings.ContainsRune(text, 0) {
		return c, errors.New("Config must contain 1..16384 bytes")
	}
	section := ""
	sections := map[string]bool{}
	lines := []string{}
	for n, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			if (section != "[interface]" && section != "[peer]") || sections[section] {
				return c, errors.New("Use exactly one Interface and one Peer section")
			}
			sections[section] = true
			lines = append(lines, line)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !ok || section == "" || value == "" || len(value) > 8192 || strings.ContainsAny(value, "\r\x00") {
			return c, fmt.Errorf("Invalid config line %d; contents hidden", n+1)
		}
		if key == "preup" || key == "postup" || key == "predown" || key == "postdown" || key == "saveconfig" || key == "table" || key == "fwmark" {
			return c, errors.New("Custom hooks, Table, FwMark and SaveConfig are not supported; import a native client config")
		}
		_, known := configKeys[key]
		known = known || key == "address" || key == "dns" || key == "mtu"
		if (section == "[interface]" && !known) || (section == "[peer]" && !peerKeys[key]) {
			return c, fmt.Errorf("Unsupported parameter on line %d; no data was discarded", n+1)
		}
		if _, exists := c.Values[key]; exists {
			return c, fmt.Errorf("Duplicate parameter on line %d", n+1)
		}
		if key == "i1" || key == "i2" || key == "i3" || key == "i4" || key == "i5" {
			invalid := false
			value = hexPacket.ReplaceAllStringFunc(value, func(s string) string {
				v := strings.Join(strings.Fields(s[strings.Index(s, "0x")+2:len(s)-1]), "")
				if _, e := hex.DecodeString(v); e != nil || v == "" {
					invalid = true
				}
				return "<b 0x" + v + ">"
			})
			if invalid {
				return c, errors.New("Invalid hexadecimal packet signature; contents hidden")
			}
		}
		c.Values[key] = value
		originalKey, _, _ := strings.Cut(line, "=")
		lines = append(lines, strings.TrimSpace(originalKey)+" = "+value)
	}
	if len(sections) != 2 {
		return c, errors.New("Both Interface and Peer sections are required")
	}
	for _, key := range []string{"privatekey", "publickey", "presharedkey", "headerprotectionkey"} {
		v, ok := c.Values[key]
		if !ok && (key == "presharedkey" || key == "headerprotectionkey") {
			continue
		}
		b, e := base64.StdEncoding.DecodeString(v)
		if e != nil || len(b) != 32 {
			return c, fmt.Errorf("Invalid %s; value hidden", key)
		}
	}
	addr, e := netip.ParsePrefix(c.Values["address"])
	if e != nil || !addr.Addr().Is4() || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() {
		return c, errors.New("A single IPv4 tunnel Address is required")
	}
	c.Address = addr.String()
	if v := c.Values["dns"]; v != "" {
		c.DNS = nil
		for _, s := range strings.Split(v, ",") {
			a, e := netip.ParseAddr(strings.TrimSpace(s))
			if e != nil || !publicIPv4(a) {
				return c, errors.New("Use one or two public IPv4 DNS servers")
			}
			c.DNS = append(c.DNS, a.String())
		}
		if len(c.DNS) < 1 || len(c.DNS) > 2 {
			return c, errors.New("Use one or two DNS servers")
		}
	}
	if v := c.Values["mtu"]; v != "" {
		c.MTU, e = strconv.Atoi(v)
		if e != nil || c.MTU < 1280 || c.MTU > 1420 {
			return c, errors.New("MTU must be 1280..1420")
		}
	}
	host, port, e := net.SplitHostPort(c.Values["endpoint"])
	if e != nil {
		return c, errors.New("Endpoint must be an IPv4 address or DNS name and port")
	}
	c.Port, e = strconv.Atoi(port)
	if e != nil || c.Port < 1 || c.Port > 65535 {
		return c, errors.New("Invalid endpoint port")
	}
	if a, e := netip.ParseAddr(host); e == nil {
		if !publicIPv4(a) {
			return c, errors.New("Endpoint must be public IPv4")
		}
	} else if !validDomain(strings.ToLower(host)) {
		return c, errors.New("Invalid endpoint hostname")
	}
	c.Host = host
	allowed := map[string]bool{}
	for _, s := range strings.Split(c.Values["allowedips"], ",") {
		s = strings.TrimSpace(s)
		if s != "0.0.0.0/0" && s != "0.0.0.0/1" && s != "128.0.0.0/1" && s != "::/0" && s != "::/1" && s != "8000::/1" {
			return c, errors.New("Profile must allow the full IPv4 internet; device routing is managed separately")
		}
		allowed[s] = true
	}
	if !allowed["0.0.0.0/0"] && !(allowed["0.0.0.0/1"] && allowed["128.0.0.0/1"]) {
		return c, errors.New("AllowedIPs must include the full IPv4 internet")
	}
	for key, value := range c.Values {
		if key == "listenport" || key == "jc" || key == "jmin" || key == "jmax" || key == "s1" || key == "s2" || key == "s3" || key == "s4" {
			if _, e := strconv.ParseUint(value, 10, 16); e != nil {
				return c, fmt.Errorf("Invalid numeric %s", key)
			}
		}
		if strings.HasPrefix(key, "h") && len(key) == 2 || key == "persistentkeepalive" || key == "contentpaddingaddition" || key == "rekeyaftertime" || key == "rekeytimeout" || key == "rejectaftertime" || key == "keepalivetimeout" || key == "maxhandshakeattempts" {
			bits := 16
			if len(key) == 2 {
				bits = 32
			}
			if !validRange(value, bits) {
				return c, fmt.Errorf("Invalid range for %s", key)
			}
		}
		if key == "randomtrailers" || key == "disablecookies" {
			switch strings.ToLower(value) {
			case "true", "1", "on", "yes":
				c.Values[key] = "true"
			case "false", "0", "off", "no":
				c.Values[key] = "false"
			default:
				return c, fmt.Errorf("Invalid boolean %s", key)
			}
		}
	}
	c.Text = strings.Join(lines, "\n") + "\n"
	return c, nil
}
func publicIPv4(a netip.Addr) bool {
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}
func validRange(v string, bits int) bool {
	p := strings.Split(v, "-")
	if len(p) > 2 {
		return false
	}
	lo, e := strconv.ParseUint(p[0], 10, bits)
	if e != nil {
		return false
	}
	if len(p) == 2 {
		hi, e := strconv.ParseUint(p[1], 10, bits)
		return e == nil && hi >= lo
	}
	return true
}
func (c VPNConfig) UAPI(endpoint string) string {
	var b strings.Builder
	b.WriteString("set=1\n")
	// Device keys must precede public_key, which switches UAPI to peer scope.
	for _, key := range []string{"privatekey", "listenport", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers", "disablecookies"} {
		if v, ok := c.Values[key]; ok {
			if key == "privatekey" || key == "headerprotectionkey" {
				x, _ := base64.StdEncoding.DecodeString(v)
				v = hex.EncodeToString(x)
			}
			fmt.Fprintf(&b, "%s=%s\n", configKeys[key], v)
		}
	}
	b.WriteString("replace_peers=true\n")
	pub, _ := base64.StdEncoding.DecodeString(c.Values["publickey"])
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub))
	if v := c.Values["presharedkey"]; v != "" {
		x, _ := base64.StdEncoding.DecodeString(v)
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(x))
	}
	fmt.Fprintf(&b, "endpoint=%s:%d\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\n", endpoint, c.Port)
	keep := c.Values["persistentkeepalive"]
	if keep == "" {
		keep = "25"
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n\n", keep)
	return b.String()
}
func (c VPNConfig) HandshakeWindow() time.Duration {
	v := c.Values["rejectaftertime"]
	parts := strings.Split(v, "-")
	seconds, _ := strconv.Atoi(parts[len(parts)-1])
	if seconds < 180 {
		seconds = 180
	}
	return time.Duration(seconds+60) * time.Second
}

type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Config   string `json:"config"`
	Revision string `json:"revision"`
	Updated  string `json:"updated"`
}
type ProfileSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Revision string `json:"revision"`
	Updated  string `json:"updated"`
}
type ProfileStore struct {
	mu    sync.Mutex
	path  string
	items []Profile
}

func openProfiles(dir string) (*ProfileStore, error) {
	p := &ProfileStore{path: filepath.Join(dir, "profiles.json"), items: []Profile{}}
	if e := readJSON(p.path, &p.items); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("Cannot read profile store")
	}
	if len(p.items) > MaxProfiles {
		return nil, errors.New("Profile limit exceeded")
	}
	seen := map[string]bool{}
	for _, v := range p.items {
		if !profileID.MatchString(v.ID) || seen[v.ID] {
			return nil, errors.New("Invalid profile store")
		}
		seen[v.ID] = true
		if _, e := parseVPNConfig(v.Config); e != nil {
			return nil, errors.New("Saved profile is invalid")
		}
	}
	return p, nil
}
func (p *ProfileStore) List() []ProfileSummary {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []ProfileSummary{}
	for _, v := range p.items {
		c, _ := parseVPNConfig(v.Config)
		out = append(out, ProfileSummary{v.ID, v.Name, net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), v.Revision, v.Updated})
	}
	return out
}
func (p *ProfileStore) Get(id string) (Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.items {
		if v.ID == id {
			return v, nil
		}
	}
	return Profile{}, errors.New("Profile not found")
}
func (p *ProfileStore) Save(v Profile) (Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v.Name = strings.TrimSpace(v.Name)
	if len(v.Name) < 1 || len(v.Name) > 80 || strings.ContainsAny(v.Name, "\r\n\x00") {
		return v, errors.New("Profile name must contain 1..80 characters")
	}
	c, e := parseVPNConfig(v.Config)
	if e != nil {
		return v, e
	}
	v.Config = c.Text
	index := -1
	if v.ID == "" {
		if len(p.items) >= MaxProfiles {
			return v, errors.New("Maximum 16 saved profiles")
		}
		v.ID = randomID()[:16]
	} else {
		if !profileID.MatchString(v.ID) {
			return v, errors.New("Invalid profile ID")
		}
		for i, old := range p.items {
			if old.ID == v.ID {
				index = i
				if old.Revision != v.Revision {
					return v, errors.New("Profile changed in another session; reopen it before saving")
				}
			}
		}
		if index < 0 {
			return v, errors.New("Profile not found")
		}
	}
	v.Revision = randomID()[:16]
	v.Updated = time.Now().UTC().Format(time.RFC3339)
	next := append([]Profile(nil), p.items...)
	if index < 0 {
		next = append(next, v)
	} else {
		next[index] = v
	}
	if e = writeJSON(p.path+".previous", p.items); e != nil {
		return v, e
	}
	if e = writeJSON(p.path, next); e == nil {
		p.items = next
	}
	return v, e
}
func (p *ProfileStore) Delete(id, revision, active string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if id == active {
		return errors.New("Select another profile before deleting the active profile")
	}
	next := []Profile{}
	found := false
	for _, v := range p.items {
		if v.ID == id {
			if v.Revision != revision {
				return errors.New("Profile changed; refresh first")
			}
			found = true
		} else {
			next = append(next, v)
		}
	}
	if !found {
		return errors.New("Profile not found")
	}
	if e := writeJSON(p.path+".previous", p.items); e != nil {
		return e
	}
	if e := writeJSON(p.path, next); e != nil {
		return e
	}
	p.items = next
	return nil
}

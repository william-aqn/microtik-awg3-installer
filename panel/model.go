package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	Version     = "0.2.0"
	MaxIPs      = 512
	MaxDomains  = 256
	MaxDevices  = 24
	MaxSources  = 12
	MaxDownload = 48 << 20
	MaxDNSIPs   = 2048
	Tag         = "AWG3UI "
)

type Device struct {
	MAC  string `json:"mac"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}
type Policy struct {
	Default    string   `json:"default"`
	Devices    []Device `json:"devices"`
	GeoIP      []string `json:"geoip"`
	GeoSite    []string `json:"geosite"`
	Antifilter []string `json:"antifilter"`
	AutoUpdate bool     `json:"auto_update"`
}
type Domain struct {
	Name   string `json:"name"`
	Suffix bool   `json:"suffix"`
}
type Bundle struct {
	IPs         []string `json:"ips"`
	Domains     []Domain `json:"domains"`
	IPv6Skipped int      `json:"ipv6_skipped"`
	Downloaded  string   `json:"downloaded"`
}
type Saved struct {
	Policy   Policy `json:"policy"`
	Bundle   Bundle `json:"bundle"`
	Revision string `json:"revision"`
}
type Settings struct {
	Listen         string   `json:"listen"`
	RouterURL      string   `json:"router_url"`
	RouterUser     string   `json:"router_user"`
	RouterPassword string   `json:"router_password"`
	PasswordSalt   string   `json:"password_salt"`
	PasswordHash   string   `json:"password_hash"`
	Hosts          []string `json:"hosts"`
	LAN            string   `json:"lan"`
	Bridge         string   `json:"bridge"`
	DataDir        string   `json:"data_dir"`
	Uplink         string   `json:"uplink"`
	Gateway        string   `json:"gateway"`
}

var sourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9!-]{0,63}$`)
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)
var antiURLs = map[string]string{
	"subnet":     "https://antifilter.download/list/subnet.lst",
	"allyouneed": "https://antifilter.download/list/allyouneed.lst",
	"ipsum":      "https://antifilter.download/list/ipsum.lst",
	"ip":         "https://antifilter.download/list/ip.lst",
	"ipresolve":  "https://antifilter.download/list/ipresolve.lst",
}

func validMode(s string) bool  { return s == "direct" || s == "geo" || s == "vpn" }
func (p Policy) Clone() Policy { p.Devices = append([]Device(nil), p.Devices...); return p }
func (p *Policy) Validate() error {
	if !validMode(p.Default) {
		return errors.New("Default mode must be direct, geo or vpn")
	}
	if len(p.Devices) > MaxDevices {
		return fmt.Errorf("Device limit: %d", MaxDevices)
	}
	seen := map[string]bool{}
	for i := range p.Devices {
		d := &p.Devices[i]
		m, err := net.ParseMAC(d.MAC)
		if err != nil || len(m) != 6 || m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" {
			return errors.New("Invalid device MAC")
		}
		d.MAC = strings.ToUpper(m.String())
		if seen[d.MAC] || !validMode(d.Mode) || len(d.Name) > 80 {
			return errors.New("Duplicate device or invalid mode/name")
		}
		seen[d.MAC] = true
	}
	if len(p.GeoIP)+len(p.GeoSite)+len(p.Antifilter) > MaxSources {
		return fmt.Errorf("Source limit: %d", MaxSources)
	}
	hasGeo := p.Default == "geo"
	for _, d := range p.Devices {
		hasGeo = hasGeo || d.Mode == "geo"
	}
	if hasGeo && len(p.GeoIP)+len(p.GeoSite)+len(p.Antifilter) == 0 {
		return errors.New("Choose at least one source before assigning Geo mode")
	}
	for _, group := range [][]string{p.GeoIP, p.GeoSite} {
		for _, s := range group {
			if !sourceName.MatchString(s) {
				return errors.New("Use lower-case source names without paths or attributes")
			}
		}
	}
	for _, s := range p.Antifilter {
		if _, ok := antiURLs[s]; !ok {
			return errors.New("Unknown Antifilter list")
		}
	}
	return nil
}
func validDomain(s string) bool {
	if len(s) > 253 || len(s) < 1 || strings.ContainsAny(s, "\r\n\t /:@") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func (b Bundle) Validate() error {
	if len(b.IPs) > MaxIPs || len(b.Domains) > MaxDomains {
		return errors.New("Compiled list exceeds the hardware budget")
	}
	for _, s := range b.IPs {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() || p != p.Masked() {
			return errors.New("Invalid IPv4 prefix in saved data")
		}
	}
	for _, d := range b.Domains {
		if !validDomain(d.Name) {
			return errors.New("Invalid domain in saved data")
		}
	}
	return nil
}
func readJSON(path string, out any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if info.Size() > 1<<20 {
		return errors.New("State file too large")
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}
func writeJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func rq(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`, "\r", ``).Replace(s) + `"`
}

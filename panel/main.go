package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/*
var web embed.FS

type App struct {
	mu              sync.Mutex
	s               Settings
	configPath      string
	router          *Router
	profiles        *ProfileStore
	tunnel          *Tunnel
	state           Saved
	busy            bool
	message         string
	lastError       string
	demo            bool
	demoEnabled     bool
	demoProfile     Profile
	sessions        map[string]time.Time
	loginWindow     time.Time
	loginAttempts   int
	lastAutoAttempt time.Time
}

func defaultPolicy() Policy {
	return Policy{Default: "vpn", Devices: []Device{}, GeoIP: []string{}, GeoSite: []string{}, Antifilter: []string{}}
}
func randomID() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}
func (a *App) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	allowed := false
	for _, h := range a.s.Hosts {
		if r.Host == h {
			allowed = true
		}
	}
	if !allowed {
		apiError(w, 403, "Unrecognized Host header")
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		apiError(w, 405, "Method not allowed")
		return
	}
	if r.Method == "POST" {
		origin, e := url.Parse(r.Header.Get("Origin"))
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if e != nil || origin.Host != r.Host || origin.Scheme != scheme || r.Header.Get("X-AWG-Request") != "1" {
			apiError(w, 403, "Same-origin request required")
			return
		}
	}
	if r.URL.Path == "/api/login" {
		a.login(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if !a.authorized(r) {
			apiError(w, 401, "Sign in to the panel")
			return
		}
		switch r.URL.Path {
		case "/api/state":
			if r.Method != "GET" {
				apiError(w, 405, "GET required")
				return
			}
			a.status(w, r)
		case "/api/apply":
			a.start(w, r, "apply")
		case "/api/refresh":
			a.start(w, r, "refresh")
		case "/api/toggle":
			a.tunnelAPI(w, r, "toggle")
		case "/api/connect", "/api/disconnect", "/api/restart", "/api/rollback", "/api/poweroff":
			a.tunnelAPI(w, r, strings.TrimPrefix(r.URL.Path, "/api/"))
		case "/api/profiles":
			a.profileAPI(w, r)
		case "/api/password":
			a.passwordAPI(w, r)
		case "/api/diagnostics":
			if r.Method != "GET" {
				apiError(w, 405, "GET required")
				return
			}
			if a.demo {
				reply(w, 200, map[string]string{"mode": "preview", "router": "not connected"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			d := a.diagnostics(ctx)
			reply(w, 200, d)
		case "/api/logout":
			if r.Method != "POST" {
				apiError(w, 405, "POST required")
				return
			}
			c, _ := r.Cookie("awg_session")
			a.mu.Lock()
			if c != nil {
				delete(a.sessions, c.Value)
			}
			a.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "awg_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			reply(w, 200, map[string]bool{"ok": true})
		default:
			apiError(w, 404, "Not found")
		}
		return
	}
	if r.Method != "GET" {
		apiError(w, 405, "GET required")
		return
	}
	switch r.URL.Path {
	case "/", "/app.js", "/profiles.js", "/password.js", "/style.css", "/geo.css", "/password.css":
		sub, _ := fs.Sub(web, "web")
		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (a *App) authorized(r *http.Request) bool {
	if a.demo {
		return true
	}
	c, e := r.Cookie("awg_session")
	if e != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[c.Value]
	return ok && time.Now().Before(expires)
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiError(w, 405, "POST required")
		return
	}
	a.mu.Lock()
	if time.Since(a.loginWindow) > time.Minute {
		a.loginWindow = time.Now()
		a.loginAttempts = 0
	}
	a.loginAttempts++
	limited := a.loginAttempts > 5
	a.mu.Unlock()
	if limited {
		apiError(w, 429, "Wait one minute before signing in again")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxPasswordRequest)).Decode(&body); e != nil {
		apiError(w, 400, "Invalid request")
		return
	}
	a.mu.Lock()
	saltText, hashText := a.s.PasswordSalt, a.s.PasswordHash
	a.mu.Unlock()
	salt, _ := hex.DecodeString(saltText)
	expected, _ := hex.DecodeString(hashText)
	hash, e := pbkdf2.Key(sha256.New, body.Password, salt, PasswordIterations, 32)
	if e != nil || subtle.ConstantTimeCompare(hash, expected) != 1 {
		apiError(w, 401, "Incorrect panel password")
		return
	}
	token := randomID()
	a.mu.Lock()
	if a.s.PasswordSalt != saltText || a.s.PasswordHash != hashText {
		a.mu.Unlock()
		apiError(w, 401, "Password changed; sign in again")
		return
	}
	for t, expiry := range a.sessions {
		if time.Now().After(expiry) {
			delete(a.sessions, t)
		}
	}
	if len(a.sessions) >= 8 {
		a.mu.Unlock()
		apiError(w, 429, "Too many active sessions")
		return
	}
	a.sessions[token] = time.Now().Add(8 * time.Hour)
	a.mu.Unlock()
	sessionCookie(w, r, token)
	reply(w, 200, map[string]bool{"ok": true})
}
func (a *App) status(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	out := map[string]any{"version": Version, "preview": a.demo, "policy": a.state.Policy, "bundle": a.state.Bundle, "revision": a.state.Revision, "busy": a.busy, "message": a.message, "error": a.lastError, "limits": map[string]int{"ips": MaxIPs, "domains": MaxDomains, "devices": MaxDevices}}
	a.mu.Unlock()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	out["panel_heap_bytes"] = mem.Alloc
	if a.profiles != nil {
		out["profiles"] = a.profiles.List()
	}
	if a.demo {
		out["router"] = []Row{{"board-name": "hAP ac^2", "version": "7.24.5", "free-memory": "29464985"}}
		out["leases"] = []Row{{"mac-address": "02:00:00:00:00:01", "address": "192.168.3.20", "host-name": "Laptop", "status": "bound"}, {"mac-address": "02:00:00:00:00:02", "address": "192.168.3.21", "host-name": "Phone", "status": "bound"}, {"mac-address": "02:00:00:00:00:03", "address": "192.168.3.22", "host-name": "TV", "status": "bound"}}
		a.mu.Lock()
		out["vpn_enabled"] = a.demoEnabled
		out["container_running"] = true
		out["tunnel"] = TunnelStatus{Enabled: a.demoEnabled, Connected: a.demoEnabled, ActiveID: a.demoProfile.ID, ActiveName: a.demoProfile.Name, ActiveRevision: a.demoProfile.Revision, Phase: "preview"}
		a.mu.Unlock()
		reply(w, 200, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if a.tunnel != nil {
		ts := a.tunnel.Status(ctx)
		out["tunnel"] = ts
		out["vpn_enabled"] = ts.Enabled
		out["container_running"] = true
	}
	resources, e := a.router.rows(ctx, "system/resource", "board-name,version,free-memory,free-hdd-space,cpu-load")
	if e != nil {
		out["router_error"] = e.Error()
		reply(w, 200, out)
		return
	}
	out["router"] = resources
	leases, e := a.router.rows(ctx, "ip/dhcp-server/lease", "mac-address,address,host-name,status,disabled")
	if e != nil {
		out["router_error"] = e.Error()
	}
	out["leases"] = leases
	ready, e := a.router.rows(ctx, "ip/firewall/address-list", "address", "list=AWG3UI-ready")
	out["geo_ready"] = e == nil && len(ready) == 1
	reply(w, 200, out)
}
func (a *App) start(w http.ResponseWriter, r *http.Request, kind string) {
	if r.Method != "POST" {
		apiError(w, 405, "POST required")
		return
	}
	a.mu.Lock()
	p := a.state.Policy
	if a.busy {
		a.mu.Unlock()
		apiError(w, 409, "An operation is already running")
		return
	}
	a.mu.Unlock()
	if kind == "apply" {
		p = Policy{}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxPolicyBytes))
		dec.DisallowUnknownFields()
		if e := dec.Decode(&p); e != nil {
			apiError(w, 400, "Invalid policy JSON")
			return
		}
		if e := p.Validate(); e != nil {
			apiError(w, 400, e.Error())
			return
		}
	}
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		apiError(w, 409, "An operation is already running")
		return
	}
	a.busy = true
	a.message = "Checking settings"
	a.lastError = ""
	a.mu.Unlock()
	go a.work(kind, p)
	reply(w, 202, map[string]bool{"accepted": true})
}
func sameSources(a, b Policy) bool {
	x, _ := json.Marshal([][]string{a.GeoIP, a.GeoSite, a.Antifilter, a.CustomDomains, a.CustomIPs, a.CustomURLs})
	y, _ := json.Marshal([][]string{b.GeoIP, b.GeoSite, b.Antifilter, b.CustomDomains, b.CustomIPs, b.CustomURLs})
	return string(x) == string(y)
}
func (a *App) finish(e error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.busy = false
	if e != nil {
		a.lastError = e.Error()
		a.message = "Operation failed. Inspect diagnostics before retrying."
		log.Print(a.lastError)
	} else {
		a.message = "Settings applied"
	}
}
func (a *App) work(kind string, p Policy) {
	var err error
	defer func() {
		if err != nil && !a.demo {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			d := a.diagnostics(ctx)
			cancel()
			d["error"] = err.Error()
			if e := writeJSON(filepath.Join(a.s.DataDir, "last-error.json"), d); e != nil {
				log.Print("Could not save diagnostic snapshot")
			}
		}
		a.finish(err)
	}()
	if a.demo {
		// Validate local custom rules in preview, without fetching remote lists.
		if kind == "apply" && p.remoteSources() == 0 {
			var b Bundle
			b, err = compileSources(context.Background(), p, os.TempDir())
			if err != nil {
				return
			}
			a.mu.Lock()
			a.state.Bundle = b
			a.mu.Unlock()
		}
		a.mu.Lock()
		if kind == "toggle" {
			a.demoEnabled = !a.demoEnabled
		}
		if kind == "apply" {
			a.state.Policy = p
		}
		a.message = "Preview only"
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	a.mu.Lock()
	old := a.state
	a.message = "Downloading and validating selected lists"
	a.mu.Unlock()
	b := old.Bundle
	if kind == "refresh" || old.Revision == "" || !sameSources(old.Policy, p) {
		if p.remoteSources() > 0 && !a.tunnel.Status(ctx).Connected {
			err = errors.New("Connect a VPN profile before downloading Geo lists")
			return
		}
		b, err = compileSources(ctx, p, a.s.DataDir)
		if err != nil {
			return
		}
	}
	state := Saved{p, b, randomID()[:16]}
	if err = writeJSON(filepath.Join(a.s.DataDir, "pending.json"), state); err != nil {
		return
	}
	a.mu.Lock()
	a.message = "Applying policy; Geo devices temporarily use VPN"
	a.mu.Unlock()
	if err = a.router.apply(ctx, state); err != nil {
		return
	}
	if err = writeJSON(filepath.Join(a.s.DataDir, "state.json"), state); err != nil {
		return
	}
	a.mu.Lock()
	a.state = state
	a.mu.Unlock()
	_ = os.Remove(filepath.Join(a.s.DataDir, "pending.json"))
}
func (a *App) maintenance() {
	// Always reconcile volatile lists after startup. If a previous commit reached
	// the router but the process died before saving, recover its pending snapshot.
	time.Sleep(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	var pending Saved
	if readJSON(filepath.Join(a.s.DataDir, "pending.json"), &pending) == nil && pending.Policy.Validate() == nil && pending.Bundle.Validate() == nil {
		rows, e := a.router.rows(ctx, "ip/firewall/mangle", "comment,jump-target")
		if e == nil {
			entry, e := findEntry(rows)
			if e == nil && entry["comment"] == Tag+"entry "+pending.Revision {
				a.mu.Lock()
				a.state = pending
				a.mu.Unlock()
			}
		}
	}
	a.mu.Lock()
	state := a.state
	a.busy = true
	a.message = "Restoring USB list snapshot"
	a.mu.Unlock()
	if state.Revision == "" {
		state.Revision = randomID()[:16]
	}
	if state.Revision != "" {
		e := a.router.apply(ctx, state)
		if e == nil {
			e = writeJSON(filepath.Join(a.s.DataDir, "state.json"), state)
		}
		if e == nil {
			a.mu.Lock()
			a.state = state
			a.mu.Unlock()
			e = a.tunnel.Restore(ctx)
		}
		if e != nil {
			a.saveDiagnostic(e)
		}
		a.finish(e)
	} else {
		a.finish(nil)
	}
	cancel()
	go a.watchTunnel()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for range tick.C {
		a.mu.Lock()
		busy := a.busy
		p := a.state.Policy
		last := a.state.Bundle.Downloaded
		a.mu.Unlock()
		if busy {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		rows, e := a.router.rows(ctx, "ip/firewall/address-list", ".id,list", "list=AWG3UI-dns-a", "list=AWG3UI-dns-b", "#|")
		if e == nil && len(rows) > MaxDNSIPs {
			a.mu.Lock()
			if a.busy {
				a.mu.Unlock()
				cancel()
				continue
			}
			a.busy = true
			a.mu.Unlock()
			source := `:if ([:len [/system/script/job/find where script="awg-ui-apply"]] > 0) do={ :error "Apply in progress" }; /ip/firewall/address-list/remove [find where list="AWG3UI-ready"]; /ip/dns/static/disable [find where comment~"^AWG3UI dns-"]; /ip/firewall/address-list/remove [find where list="AWG3UI-dns-a" or list="AWG3UI-dns-b"];`
			e = a.router.script(ctx, "awg-ui-guard", source)
			a.mu.Lock()
			a.busy = false
			a.lastError = "DNS address limit exceeded. Geo now uses VPN for all internet. Choose fewer domains and apply again."
			a.mu.Unlock()
			if e != nil {
				log.Print(e)
			}
		}
		cancel()
		stamp, e := time.Parse(time.RFC3339, last)
		if p.AutoUpdate && (e != nil || time.Since(stamp) > 24*time.Hour) && time.Since(a.lastAutoAttempt) > time.Hour {
			a.mu.Lock()
			if !a.busy {
				a.busy = true
				a.lastAutoAttempt = time.Now()
				a.mu.Unlock()
				a.work("refresh", p)
			} else {
				a.mu.Unlock()
			}
		}
	}
}
func validateSettings(s Settings) error {
	if s.RouterURL != "http://172.18.20.1" || s.Gateway != "172.18.20.1" || !ifaceName.MatchString(s.Uplink) {
		return errors.New("Router API must use the 172.18.20.1 container link and a valid uplink")
	}
	p, e := netip.ParsePrefix(s.LAN)
	if e != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() != 24 || p != p.Masked() {
		return errors.New("Panel requires a private IPv4 LAN /24")
	}
	if !ifaceName.MatchString(s.Bridge) || len(s.Hosts) == 0 || s.RouterUser == "" || s.RouterPassword == "" || s.DataDir == "" {
		return errors.New("Incomplete panel settings")
	}
	salt, e := hex.DecodeString(s.PasswordSalt)
	if e != nil || len(salt) != 16 {
		return errors.New("Invalid password salt")
	}
	hash, e := hex.DecodeString(s.PasswordHash)
	if e != nil || len(hash) != 32 {
		return errors.New("Invalid password hash")
	}
	return nil
}
func run() error {
	config := flag.String("config", "/data/settings.json", "Private settings file")
	demo := flag.Bool("demo", false, "Read-only router preview on 127.0.0.1:9865")
	diag := flag.Bool("diag", false, "Print sanitized router diagnostics and exit")
	control := flag.String("control", "", "Local controller command: toggle, connect, disconnect, restart, rollback or diag")
	check := flag.String("check-sources", "", "Validate a policy JSON and download lists, without a router")
	checkProfile := flag.String("check-profile", "", "Validate a native config without connecting or printing secrets")
	flag.Parse()
	if *control != "" {
		return controlCLI(*control)
	}
	if *checkProfile != "" {
		b, e := os.ReadFile(*checkProfile)
		if e != nil {
			return errors.New("Cannot read profile file")
		}
		if _, e = parseVPNConfig(string(b)); e != nil {
			return e
		}
		fmt.Println("Profile valid. IPv4 mode; no network changes made.")
		return nil
	}
	if *check != "" {
		var p Policy
		if e := readJSON(*check, &p); e != nil {
			return e
		}
		b, e := compileSources(context.Background(), p, os.TempDir())
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"ips": len(b.IPs), "domains": len(b.Domains), "ipv6_skipped": b.IPv6Skipped, "downloaded": b.Downloaded})
	}
	a := &App{demo: *demo, sessions: map[string]time.Time{}, state: Saved{Policy: defaultPolicy()}, message: "Ready"}
	if *demo {
		a.s = Settings{Listen: "127.0.0.1:9865", Hosts: []string{"127.0.0.1:9865", "localhost:9865"}}
		dir, e := os.MkdirTemp("", "awg-control-preview-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(dir)
		a.profiles, _ = openProfiles(dir)
	} else {
		a.configPath = *config
		if e := readJSON(*config, &a.s); e != nil {
			return errors.New("Cannot read private settings file")
		}
		if e := validateSettings(a.s); e != nil {
			return e
		}
		a.router = newRouter(a.s)
		var e error
		a.profiles, e = openProfiles(a.s.DataDir)
		if e != nil {
			return e
		}
		a.tunnel, e = openTunnel(a.s.DataDir, &LinuxTunnel{uplink: a.s.Uplink, gateway: a.s.Gateway}, a.router)
		if e != nil {
			return e
		}
		if e := readJSON(filepath.Join(a.s.DataDir, "state.json"), &a.state); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e := a.state.Policy.Validate(); e != nil {
			return e
		}
		if e := a.state.Bundle.Validate(); e != nil {
			return e
		}
		if *diag {
			d := a.diagnostics(context.Background())
			return json.NewEncoder(os.Stdout).Encode(d)
		}
		a.busy = true
		if e := a.listenControl(); e != nil {
			return e
		}
		go a.maintenance()
	}
	server := &http.Server{Addr: a.s.Listen, Handler: http.HandlerFunc(a.serve), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if a.tunnel != nil {
			_ = a.tunnel.driver.Stop(ctx)
		}
		_ = server.Shutdown(ctx)
	}()
	log.Printf("AWG panel %s listening on %s; preview=%t", Version, a.s.Listen, *demo)
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

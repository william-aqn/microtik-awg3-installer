package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type TunnelRouting interface {
	Configure(context.Context, VPNConfig, string) error
	Gate(context.Context, bool) error
	LED(context.Context, bool) error
}
type TunnelSaved struct {
	Active   Profile `json:"active"`
	Previous Profile `json:"previous"`
	Enabled  bool    `json:"enabled"`
}
type TunnelStatus struct {
	TunnelStats
	Enabled        bool   `json:"enabled"`
	Connected      bool   `json:"connected"`
	ActiveID       string `json:"active_id"`
	ActiveName     string `json:"active_name"`
	ActiveRevision string `json:"active_revision"`
	PreviousName   string `json:"previous_name"`
	CanRollback    bool   `json:"can_rollback"`
	Phase          string `json:"phase"`
	Error          string `json:"error,omitempty"`
}
type Tunnel struct {
	mu               sync.Mutex
	op               sync.Mutex
	saved            TunnelSaved
	phase, lastError string
	dir              string
	driver           TunnelDriver
	routing          TunnelRouting
	resolve          func(context.Context, string) (string, error)
	verifyTimeout    time.Duration
	endpoints        map[string]string
}

func resolveEndpoint(ctx context.Context, host string) (string, error) {
	if a, e := netip.ParseAddr(host); e == nil {
		if !publicIPv4(a) {
			return "", errors.New("Endpoint is not public IPv4")
		}
		return a.String(), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if e != nil {
		return "", errors.New("Cannot resolve VPN endpoint through router DNS")
	}
	for _, a := range ips {
		if publicIPv4(a) {
			return a.String(), nil
		}
	}
	return "", errors.New("Endpoint has no public IPv4 address")
}
func openTunnel(dir string, d TunnelDriver, r TunnelRouting) (*Tunnel, error) {
	t := &Tunnel{dir: dir, driver: d, routing: r, resolve: resolveEndpoint, verifyTimeout: 35 * time.Second, phase: "off", endpoints: map[string]string{}}
	if e := readJSON(filepath.Join(dir, "endpoints.json"), &t.endpoints); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("Cannot read endpoint cache")
	}
	if t.endpoints == nil {
		t.endpoints = map[string]string{}
	}
	if e := readJSON(filepath.Join(dir, "tunnel.json"), &t.saved); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("Cannot read tunnel state")
	}
	// A crash during activation must restore the last committed profile.
	var pending TunnelSaved
	if e := readJSON(filepath.Join(dir, "activation.json"), &pending); e == nil {
		t.saved = pending
		t.lastError = "Interrupted activation recovered; previous committed profile selected"
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("Cannot read activation recovery file")
	}
	for _, p := range []Profile{t.saved.Active, t.saved.Previous} {
		if p.ID != "" {
			if !profileID.MatchString(p.ID) {
				return nil, errors.New("Invalid saved profile identity")
			}
			if _, e := parseVPNConfig(p.Config); e != nil {
				return nil, errors.New("Invalid saved tunnel configuration")
			}
		}
	}
	return t, nil
}
func (t *Tunnel) snapshot() TunnelSaved { t.mu.Lock(); defer t.mu.Unlock(); return t.saved }
func (t *Tunnel) setPhase(p string)     { t.mu.Lock(); t.phase = p; t.mu.Unlock() }
func (t *Tunnel) persist(s TunnelSaved) error {
	if e := writeJSON(filepath.Join(t.dir, "tunnel.json"), s); e != nil {
		return errors.New("Cannot save tunnel state on USB")
	}
	t.mu.Lock()
	t.saved = s
	t.mu.Unlock()
	return nil
}
func (t *Tunnel) Status(ctx context.Context) TunnelStatus {
	t.mu.Lock()
	s := t.saved
	out := TunnelStatus{Enabled: s.Enabled, ActiveID: s.Active.ID, ActiveName: s.Active.Name, ActiveRevision: s.Active.Revision, PreviousName: s.Previous.Name, CanRollback: s.Previous.ID != "", Phase: t.phase, Error: t.lastError}
	t.mu.Unlock()
	stats, e := t.driver.Stats(ctx)
	out.TunnelStats = stats
	c, _ := parseVPNConfig(s.Active.Config)
	out.Connected = e == nil && s.Enabled && stats.Running && stats.Handshake > 0 && time.Since(time.Unix(stats.Handshake, 0)) < c.HandshakeWindow()
	if out.Phase == "connected" && !out.Connected {
		out.Phase = "disconnected"
	}
	return out
}
func (t *Tunnel) rememberError(e error) {
	t.mu.Lock()
	if e != nil {
		t.lastError = e.Error()
	} else {
		t.lastError = ""
	}
	t.mu.Unlock()
}
func (t *Tunnel) bringUp(ctx context.Context, p Profile) error {
	if e := t.driver.Initialize(ctx); e != nil {
		return e
	}
	c, e := parseVPNConfig(p.Config)
	if e != nil {
		return e
	}
	endpoint, e := t.resolve(ctx, c.Host)
	if e != nil {
		// Router DNS may itself use the VPN. A saved public endpoint allows a
		// restart without opening a separate cleartext DNS path through WAN.
		cached, parseErr := netip.ParseAddr(t.endpoints[c.Host])
		if parseErr != nil || !publicIPv4(cached) {
			return e
		}
		endpoint = cached.String()
	} else {
		if t.endpoints == nil {
			t.endpoints = map[string]string{}
		}
		if len(t.endpoints) >= MaxProfiles*2 {
			old := t.snapshot()
			for host := range t.endpoints {
				active, _ := parseVPNConfig(old.Active.Config)
				previous, _ := parseVPNConfig(old.Previous.Config)
				if host != active.Host && host != previous.Host {
					delete(t.endpoints, host)
				}
			}
		}
		t.endpoints[c.Host] = endpoint
		if e = writeJSON(filepath.Join(t.dir, "endpoints.json"), t.endpoints); e != nil {
			return errors.New("Cannot save resolved VPN endpoint on USB")
		}
	}
	if e = t.routing.Configure(ctx, c, endpoint); e != nil {
		return e
	}
	// Enable the policy guard before replacing the tunnel. Container FORWARD
	// drops cleartext fallback; Direct devices retain their explicit WAN route.
	if e = t.routing.Gate(ctx, true); e != nil {
		return e
	}
	if e = t.driver.Stop(ctx); e != nil {
		return e
	}
	if e = t.driver.Start(ctx, c, endpoint); e != nil {
		return e
	}
	t.setPhase("verifying")
	verify, cancel := context.WithTimeout(ctx, t.verifyTimeout)
	defer cancel()
	for {
		probeErr := t.driver.Probe(verify)
		stats, statErr := t.driver.Stats(verify)
		if probeErr == nil && statErr == nil && stats.Handshake > 0 && stats.RX > 0 {
			return nil
		}
		select {
		case <-verify.Done():
			return errors.New("VPN verification timed out: handshake, received traffic and internet response are required")
		case <-time.After(time.Second):
		}
	}
}
func (t *Tunnel) Activate(ctx context.Context, p Profile) (err error) {
	t.op.Lock()
	defer t.op.Unlock()
	defer func() { t.rememberError(err) }()
	if _, err = parseVPNConfig(p.Config); err != nil {
		return err
	}
	old := t.snapshot()
	if err = writeJSON(filepath.Join(t.dir, "activation.json"), old); err != nil {
		return errors.New("Cannot save rollback point")
	}
	t.setPhase("connecting")
	_ = t.routing.LED(ctx, false)
	if err = t.bringUp(ctx, p); err == nil {
		next := TunnelSaved{Active: p, Previous: old.Active, Enabled: true}
		if old.Active.ID == p.ID && old.Active.Revision == p.Revision {
			next.Previous = old.Previous
		}
		err = t.persist(next)
		if err == nil {
			_ = os.Remove(filepath.Join(t.dir, "activation.json"))
			t.setPhase("connected")
			_ = t.routing.LED(ctx, true)
			return nil
		}
	}
	original := err
	t.setPhase("rolling_back")
	restore, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	if old.Enabled && old.Active.ID != "" {
		if e := t.bringUp(restore, old.Active); e == nil {
			if e = t.persist(old); e == nil {
				_ = os.Remove(filepath.Join(t.dir, "activation.json"))
				t.setPhase("connected")
				_ = t.routing.LED(restore, true)
				return fmt.Errorf("%v; previous profile restored", original)
			}
		}
		_ = t.driver.Stop(restore)
		_ = t.routing.LED(restore, false)
		t.setPhase("error")
		return fmt.Errorf("%v; rollback also failed, VPN traffic remains blocked", original)
	}
	// A failed first connection stays guarded until the user explicitly turns
	// VPN off or retries. Do not silently fall back to cleartext internet.
	_ = t.driver.Stop(restore)
	failed := TunnelSaved{Active: p, Previous: old.Active, Enabled: true}
	if e := t.persist(failed); e != nil {
		t.setPhase("error")
		return fmt.Errorf("%v; could not persist recovery state", original)
	}
	_ = os.Remove(filepath.Join(t.dir, "activation.json"))
	_ = t.routing.Gate(restore, true)
	_ = t.routing.LED(restore, false)
	t.setPhase("error")
	return fmt.Errorf("%v; VPN traffic blocked until retry or Disconnect", original)
}
func (t *Tunnel) Disable(ctx context.Context) (err error) {
	t.op.Lock()
	defer t.op.Unlock()
	defer func() { t.rememberError(err) }()
	s := t.snapshot()
	s.Enabled = false
	if err = t.persist(s); err != nil {
		return err
	}
	t.setPhase("disconnecting")
	if err = t.routing.Gate(ctx, false); err != nil {
		return err
	}
	err = t.driver.Stop(ctx)
	_ = t.routing.LED(ctx, false)
	if err == nil {
		_ = os.Remove(filepath.Join(t.dir, "activation.json"))
		t.setPhase("off")
	}
	return err
}
func (t *Tunnel) Toggle(ctx context.Context) error {
	if t.Status(ctx).Connected {
		return t.Disable(ctx)
	}
	s := t.snapshot()
	if s.Active.ID == "" {
		return errors.New("Import and activate a VPN profile first")
	}
	return t.Activate(ctx, s.Active)
}
func (t *Tunnel) Restore(ctx context.Context) error {
	if e := t.driver.Initialize(ctx); e != nil {
		return e
	}
	s := t.snapshot()
	if s.Enabled && s.Active.ID != "" {
		return t.Activate(ctx, s.Active)
	}
	return t.Disable(ctx)
}
func (t *Tunnel) Rollback(ctx context.Context) error {
	s := t.snapshot()
	if s.Previous.ID == "" {
		return errors.New("No previous profile available")
	}
	return t.Activate(ctx, s.Previous)
}

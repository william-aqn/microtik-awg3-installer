package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleConfig(endpoint string) string {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	return "[Interface]\nPrivateKey = " + key + "\nAddress = 10.77.0.2/32\nDNS = 1.1.1.1,1.0.0.1\nMTU = 1280\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30\nS3 = 24\nS4 = 24\nH1 = 100-200\nHeaderProtectionKey = " + key + "\nContentPaddingAddition = 4-10\nRandomTrailers = on\nI1 = <b0x16 03 01>\n[Peer]\nPublicKey = " + key + "\nPresharedKey = " + key + "\nEndpoint = " + endpoint + ":51820\nAllowedIPs = 0.0.0.0/0,::/0\n"
}
func TestConfigPreservesAWG3AndRejectsExecutableHooks(t *testing.T) {
	text := sampleConfig("vpn.example.com")
	text += "PersistentKeepalive = 25-35 # AWG3 range\n"
	c, e := parseVPNConfig(text)
	if e != nil {
		t.Fatal(e)
	}
	u := c.UAPI("9.9.9.9")
	for _, want := range []string{"header_protection_key=30313233", "content_padding_addition=4-10", "random_trailers=true", "i1=<b 0x160301>", "endpoint=9.9.9.9:51820", "persistent_keepalive_interval=25-35"} {
		if !strings.Contains(u, want) {
			t.Fatal("missing", want)
		}
	}
	if strings.Index(u, "public_key=") < strings.Index(u, "header_protection_key=") {
		t.Fatal("device and peer scopes mixed")
	}
	for _, hook := range []string{"PostUp", "preUP", "pOsTdOwN", "SaveConfig", "Table", "FwMark", "UnknownFutureField"} {
		_, e := parseVPNConfig(strings.Replace(text, "Address =", hook+" = hidden-test-value\nAddress =", 1))
		if e == nil || strings.Contains(e.Error(), "hidden-test-value") {
			t.Fatal("unsafe import", hook, e)
		}
	}
	for _, bad := range []string{strings.Replace(text, "MTU = 1280", "MTU = 10", 1), strings.Replace(text, "[Peer]", "[Peer]\n[Peer]", 1), strings.Replace(text, "ContentPaddingAddition = 4-10", "ContentPaddingAddition = 20-10", 1), strings.Replace(text, "Endpoint = vpn.example.com", "Endpoint = 127.0.0.1", 1)} {
		if _, e := parseVPNConfig(bad); e == nil {
			t.Fatal("accepted invalid config")
		}
	}
}
func TestProfilesDraftsRevisionsAndSecretFreeSummary(t *testing.T) {
	p, e := openProfiles(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	v, e := p.Save(Profile{Name: "first", Config: sampleConfig("9.9.9.9")})
	if e != nil {
		t.Fatal(e)
	}
	summaries, _ := json.Marshal(p.List())
	if strings.Contains(string(summaries), "PrivateKey") || strings.Contains(string(summaries), "config") {
		t.Fatal("summary leaked config")
	}
	stale := v
	v.Name = "edited"
	v, e = p.Save(v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Save(stale); e == nil {
		t.Fatal("stale write accepted")
	}
	if e = p.Delete(v.ID, v.Revision, v.ID); e == nil {
		t.Fatal("active profile deleted")
	}
	if e = p.Delete(v.ID, v.Revision, ""); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(p.path + ".previous"); e != nil {
		t.Fatal("recovery snapshot missing")
	}
}

type fakeTunnelDriver struct {
	stats     TunnelStats
	failHost  string
	starts    []string
	stops     int
	probeFail bool
}

func (d *fakeTunnelDriver) Initialize(context.Context) error { return nil }
func (d *fakeTunnelDriver) Start(_ context.Context, c VPNConfig, ip string) error {
	d.starts = append(d.starts, ip)
	if ip == d.failHost {
		return errors.New("engine rejected profile")
	}
	d.stats = TunnelStats{Running: true, Handshake: time.Now().Unix(), RX: 42, TX: 80}
	return nil
}
func (d *fakeTunnelDriver) Stop(context.Context) error {
	d.stats = TunnelStats{}
	d.stops++
	return nil
}
func (d *fakeTunnelDriver) Stats(context.Context) (TunnelStats, error) { return d.stats, nil }
func (d *fakeTunnelDriver) Probe(context.Context) error {
	if d.probeFail {
		return errors.New("no response")
	}
	return nil
}

type fakeTunnelRouting struct {
	enabled   bool
	led       bool
	endpoints []string
}

func (r *fakeTunnelRouting) Configure(_ context.Context, c VPNConfig, ip string) error {
	r.endpoints = append(r.endpoints, ip)
	return nil
}
func (r *fakeTunnelRouting) Gate(_ context.Context, on bool) error { r.enabled = on; return nil }
func (r *fakeTunnelRouting) LED(_ context.Context, on bool) error  { r.led = on; return nil }
func newTestTunnel(t *testing.T) (*Tunnel, *fakeTunnelDriver, *fakeTunnelRouting) {
	t.Helper()
	d := &fakeTunnelDriver{}
	r := &fakeTunnelRouting{}
	v, e := openTunnel(t.TempDir(), d, r)
	if e != nil {
		t.Fatal(e)
	}
	v.verifyTimeout = 20 * time.Millisecond
	return v, d, r
}
func testProfile(id, endpoint string) Profile {
	return Profile{ID: id, Name: "Profile " + id, Revision: "1111111111111111", Config: sampleConfig(endpoint)}
}
func TestEndpointCacheBreaksVPNDNSBootstrapCycle(t *testing.T) {
	v, d, r := newTestTunnel(t)
	v.resolve = func(context.Context, string) (string, error) { return "9.9.9.9", nil }
	p := testProfile("1111111111111111", "vpn.example.com")
	if e := v.Activate(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	_ = d.Stop(context.Background())
	restarted, e := openTunnel(v.dir, d, r)
	if e != nil {
		t.Fatal(e)
	}
	restarted.resolve = func(context.Context, string) (string, error) {
		return "", errors.New("DNS unavailable until VPN connects")
	}
	if e = restarted.Restore(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !restarted.Status(context.Background()).Connected {
		t.Fatal("Saved public endpoint did not restore the connection")
	}
}
func TestProfileActivationRollbackAndSoftDisconnect(t *testing.T) {
	v, d, r := newTestTunnel(t)
	ctx := context.Background()
	first := testProfile("1111111111111111", "9.9.9.9")
	second := testProfile("2222222222222222", "8.8.8.8")
	if e := v.Activate(ctx, first); e != nil {
		t.Fatal(e)
	}
	if !r.enabled || !v.Status(ctx).Connected {
		t.Fatal("not connected")
	}
	d.failHost = "8.8.8.8"
	if e := v.Activate(ctx, second); e == nil || !strings.Contains(e.Error(), "previous profile restored") {
		t.Fatal(e)
	}
	if v.snapshot().Active.ID != first.ID || !r.enabled || !d.stats.Running {
		t.Fatal("rollback did not restore previous tunnel")
	}
	d.failHost = ""
	if e := v.Activate(ctx, second); e != nil {
		t.Fatal(e)
	}
	if v.snapshot().Previous.ID != first.ID {
		t.Fatal("lost previous profile")
	}
	if e := v.Toggle(ctx); e != nil {
		t.Fatal(e)
	}
	if d.stats.Running || r.enabled || v.snapshot().Enabled {
		t.Fatal("soft disconnect left routing enabled")
	}
	if e := v.Toggle(ctx); e != nil {
		t.Fatal(e)
	}
	if !v.Status(ctx).Connected {
		t.Fatal("toggle did not reconnect")
	}
	if e := v.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if v.snapshot().Active.ID != first.ID {
		t.Fatal("manual rollback")
	}
}
func TestFailedFirstConnectionRemainsGuarded(t *testing.T) {
	v, d, r := newTestTunnel(t)
	d.probeFail = true
	e := v.Activate(context.Background(), testProfile("1111111111111111", "9.9.9.9"))
	if e == nil {
		t.Fatal("unverified connection accepted")
	}
	if !r.enabled || !v.snapshot().Enabled || d.stats.Running {
		t.Fatal("failure leaked or remained running")
	}
	if e = v.Disable(context.Background()); e != nil {
		t.Fatal(e)
	}
	if r.enabled {
		t.Fatal("explicit disconnect did not restore WAN")
	}
}
func TestCrashRecoveryRestoresCommittedProfile(t *testing.T) {
	dir := t.TempDir()
	old := TunnelSaved{Active: testProfile("1111111111111111", "9.9.9.9"), Enabled: true}
	newer := TunnelSaved{Active: testProfile("2222222222222222", "8.8.8.8"), Enabled: true}
	if e := writeJSON(filepath.Join(dir, "tunnel.json"), newer); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(filepath.Join(dir, "activation.json"), old); e != nil {
		t.Fatal(e)
	}
	v, e := openTunnel(dir, &fakeTunnelDriver{}, &fakeTunnelRouting{})
	if e != nil {
		t.Fatal(e)
	}
	if v.snapshot().Active.ID != old.Active.ID {
		t.Fatal("interrupted candidate became active")
	}
}
func TestProfileAPIAuthorizationAndDraftSave(t *testing.T) {
	a := testApp()
	a.profiles, _ = openProfiles(t.TempDir())
	body, _ := json.Marshal(map[string]string{"action": "save", "name": "test", "config": sampleConfig("9.9.9.9")})
	if w := request(a, "POST", "/api/profiles", string(body), "router.test", "http://router.test", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	cookie := &http.Cookie{Name: "awg_session", Value: "test"}
	a.sessions["test"] = time.Now().Add(time.Hour)
	if w := request(a, "POST", "/api/profiles", string(body), "router.test", "http://router.test", cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := request(a, "GET", "/api/profiles", "", "router.test", "", cookie)
	if strings.Contains(w.Body.String(), "PrivateKey") || strings.Contains(w.Body.String(), "HeaderProtectionKey") {
		t.Fatal("list exposed secrets")
	}
	if a.busy {
		t.Fatal("saving a draft tried to reconnect")
	}
}

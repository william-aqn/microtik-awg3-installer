package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in: this test owns a disposable Linux network namespace.
func TestNativeEngineLifecycle(t *testing.T) {
	if os.Getenv("AWG_NATIVE_TEST") != "1" {
		t.Skip("Run inside a disposable NET_ADMIN container with /dev/net/tun")
	}
	b, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	if len(f) < 5 || f[1] != "via" || f[3] != "dev" {
		t.Fatal("Unexpected test container route")
	}
	var logs bytes.Buffer
	d := &LinuxTunnel{uplink: f[4], gateway: f[2], testLog: &logs}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer d.Stop(context.Background())
	if err = d.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	c, err := parseVPNConfig(sampleConfig("203.0.113.10") + "PersistentKeepalive = 25-35\n")
	if err != nil {
		t.Fatal(err)
	}
	for cycle := 0; cycle < 2; cycle++ {
		if err = d.Start(ctx, c, "203.0.113.10"); err != nil {
			_ = d.Stop(ctx)
			t.Fatalf("%v; synthetic fixture engine output: %s", err, logs.String())
		}
		s, e := d.Stats(ctx)
		if e != nil || !s.Running || s.Handshake != 0 {
			t.Fatalf("Unexpected native engine state: %+v, %v", s, e)
		}
		if err = d.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		if s, e = d.Stats(ctx); e != nil || s.Running {
			t.Fatal("Engine remained running after soft disconnect")
		}
	}
}

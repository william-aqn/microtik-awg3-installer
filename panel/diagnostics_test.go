package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type deadlineTunnelDriver struct{ *fakeTunnelDriver }

func (d *deadlineTunnelDriver) Stats(ctx context.Context) (TunnelStats, error) {
	if err := ctx.Err(); err != nil {
		return TunnelStats{Running: true}, err
	}
	return d.fakeTunnelDriver.Stats(ctx)
}

func TestSlowRouterDiagnosticsDoesNotInventDisconnectedTunnel(t *testing.T) {
	tunnel, driver, _ := newTestTunnel(t)
	tunnel.driver = &deadlineTunnelDriver{driver}
	if err := tunnel.Activate(context.Background(), testProfile("1111111111111111", "9.9.9.9")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel() // Router table inspection has exhausted the report deadline.
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	app := &App{tunnel: tunnel, router: newRouter(Settings{RouterURL: server.URL})}
	report := app.diagnostics(ctx)
	if _, ok := report["resource"].(string); !ok {
		t.Fatal("The simulated Router API timeout was not reported")
	}
	status := report["tunnel"].(TunnelStatus)
	if !status.Connected || status.Handshake == 0 {
		t.Fatal("Router API failure overwrote the healthy local tunnel snapshot", status)
	}
}

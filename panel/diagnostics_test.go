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
		// Either cancellation or a failed response must win the transport race;
		// a successful empty table made this check timing-dependent.
		w.WriteHeader(http.StatusGatewayTimeout)
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

func TestDiagnosticsExposeUpdateReadiness(t *testing.T) {
	app := &App{busy: true, lastError: "restore failed", geoError: "lists pending", state: Saved{Revision: "policy-revision"}}
	report := app.diagnostics(context.Background())
	if report["busy"] != true || report["error"] != "restore failed" || report["geo_error"] != "lists pending" || report["revision"] != "policy-revision" {
		t.Fatal("Update health check cannot distinguish startup or failure", report)
	}
	app.busy, app.lastError, app.geoError = false, "", ""
	report = app.diagnostics(context.Background())
	if report["busy"] != false || report["error"] != "" || report["geo_error"] != "" {
		t.Fatal("Completed restoration is not reported", report)
	}
}

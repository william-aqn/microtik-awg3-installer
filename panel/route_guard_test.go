package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func healthyRouteRows() []Row {
	return []Row{
		{".id": "*1", "comment": "AWGC tunnel route", "routing-table": "to-awg", "dst-address": "0.0.0.0/0", "gateway": "172.18.20.2@main", "immediate-gw": "172.18.20.2%docker-awg-veth", "distance": "1", "disabled": "false", "active": "true"},
		{".id": "*2", "comment": "AWGC no main fallback", "routing-table": "to-awg", "dst-address": "0.0.0.0/0", "distance": "254", "blackhole": "true", "disabled": "false"},
	}
}

func routeTestRouter(t *testing.T, rows *[]Row, write func(http.ResponseWriter, Row)) *Router {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == "POST" && req.URL.Path == "/rest/ip/route/print":
			var query struct {
				Query []string `json:".query"`
			}
			if json.NewDecoder(req.Body).Decode(&query) != nil || len(query.Query) != 1 || query.Query[0] != "routing-table=to-awg" {
				t.Error("route inspection was not scoped to the managed table")
			}
			_ = json.NewEncoder(w).Encode(*rows)
		case req.Method == "PATCH" && req.URL.Path == "/rest/ip/route/*1":
			var change Row
			if json.NewDecoder(req.Body).Decode(&change) != nil || len(change) != 1 || change["disabled"] != "false" {
				t.Error("repair attempted to change more than the disabled flag")
			}
			write(w, change)
		default:
			t.Error("unexpected request", req.Method, req.URL.Path)
			http.Error(w, "unexpected", 400)
		}
	}))
	t.Cleanup(server.Close)
	return newRouter(Settings{RouterURL: server.URL})
}

func TestRouteGuardRepairsDisabledRouteAndIsIdleOtherwise(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		rows := healthyRouteRows()
		if legacy {
			rows[0]["comment"] = "AWG3 default"
			rows[1]["comment"] = "AWG3UI no main fallback"
		}
		writes := 0
		r := routeTestRouter(t, &rows, func(w http.ResponseWriter, _ Row) {
			writes++
			rows[0]["disabled"], rows[0]["active"] = "false", "true"
			_ = json.NewEncoder(w).Encode(rows[0])
		})
		ctx := context.Background()
		if fixed, e := r.EnsureRoute(ctx); fixed || e != nil || writes != 0 {
			t.Fatal("healthy route changed", fixed, e, writes)
		}
		rows[0]["disabled"], rows[0]["active"] = "true", "false"
		if fixed, e := r.EnsureRoute(ctx); !fixed || e != nil || writes != 1 {
			t.Fatal("disabled route not repaired", fixed, e, writes)
		}
		if fixed, e := r.EnsureRoute(ctx); fixed || e != nil || writes != 1 {
			t.Fatal("healthy poll wrote configuration", fixed, e, writes)
		}
	}
}

func TestRouteGuardRefusesAmbiguousOrChangedRoutes(t *testing.T) {
	cases := map[string]func([]Row) []Row{
		"missing":   func(r []Row) []Row { return r[1:] },
		"duplicate": func(r []Row) []Row { return append(r, r[0]) },
		"unexpected default": func(r []Row) []Row {
			return append(r, Row{"routing-table": "to-awg", "dst-address": "0.0.0.0/0", "gateway": "192.168.1.1"})
		},
		"gateway changed":        func(r []Row) []Row { r[0]["gateway"] = "192.168.1.1"; return r },
		"table changed":          func(r []Row) []Row { r[0]["routing-table"] = "main"; return r },
		"distance changed":       func(r []Row) []Row { r[0]["distance"] = "255"; return r },
		"owner changed":          func(r []Row) []Row { r[0]["comment"] = "My route"; return r },
		"dynamic":                func(r []Row) []Row { r[0]["dynamic"] = "true"; return r },
		"missing fallback":       func(r []Row) []Row { return r[:1] },
		"disabled fallback":      func(r []Row) []Row { r[1]["disabled"] = "true"; return r },
		"non-blackhole fallback": func(r []Row) []Row { r[1]["blackhole"] = "false"; return r },
		"absent blackhole flag":  func(r []Row) []Row { delete(r[1], "blackhole"); return r },
		"blackhole tunnel":       func(r []Row) []Row { r[0]["blackhole"] = ""; return r },
		"inactive":               func(r []Row) []Row { r[0]["active"] = "false"; return r },
		"wrong interface":        func(r []Row) []Row { r[0]["immediate-gw"] = "172.18.20.2%ether1"; return r },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rows := mutate(healthyRouteRows())
			r := routeTestRouter(t, &rows, func(w http.ResponseWriter, _ Row) { t.Error("unsafe repair"); http.Error(w, "unexpected", 400) })
			if fixed, e := r.EnsureRoute(context.Background()); fixed || e == nil {
				t.Fatal("invalid route accepted", fixed, e)
			}
		})
	}
}

func TestRouteGuardAcceptsNativeRouterOSSwitchRepresentation(t *testing.T) {
	// Captured shape from RouterOS 7.24.5: an enabled inactive blackhole has
	// an empty switch value and omits disabled/active, while gateway omits @main.
	rows := healthyRouteRows()
	rows[0]["gateway"] = "172.18.20.2"
	rows[1]["blackhole"] = ""
	delete(rows[1], "disabled")
	r := routeTestRouter(t, &rows, func(w http.ResponseWriter, _ Row) { t.Error("healthy native route changed") })
	if repaired, e := r.EnsureRoute(context.Background()); repaired || e != nil {
		t.Fatal("native RouterOS route rejected", repaired, e)
	}
}

func TestRouteGuardRepairsNativeDisabledRouteWithOmittedDefaults(t *testing.T) {
	rows := healthyRouteRows()
	rows[0]["disabled"] = "true"
	delete(rows[0], "active")
	delete(rows[0], "distance")
	delete(rows[0], "immediate-gw")
	rows[1]["blackhole"] = ""
	rows[1]["active"] = "true"
	delete(rows[1], "disabled")
	writes := 0
	r := routeTestRouter(t, &rows, func(w http.ResponseWriter, _ Row) {
		writes++
		rows[0] = healthyRouteRows()[0]
		_ = json.NewEncoder(w).Encode(rows[0])
	})
	if repaired, e := r.EnsureRoute(context.Background()); !repaired || e != nil || writes != 1 {
		t.Fatal("native disabled route not repaired", repaired, e, writes)
	}
}

func TestRouteGuardVerifiesRepairAndReportsAPIFailure(t *testing.T) {
	for _, denied := range []bool{false, true} {
		rows := healthyRouteRows()
		rows[0]["disabled"], rows[0]["active"] = "true", "false"
		r := routeTestRouter(t, &rows, func(w http.ResponseWriter, _ Row) {
			if denied {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			// A successful HTTP response is not proof the route became active.
			_ = json.NewEncoder(w).Encode(rows[0])
		})
		if _, e := r.EnsureRoute(context.Background()); e == nil {
			t.Fatal("failed repair was reported as healthy")
		}
	}
}

func TestTunnelRouteGuardDetectsFailureAndHonorsDisconnect(t *testing.T) {
	tunnel, driver, routing := newTestTunnel(t)
	ctx := context.Background()
	if e := tunnel.Activate(ctx, testProfile("1111111111111111", "9.9.9.9")); e != nil {
		t.Fatal(e)
	}
	routing.routeError = errors.New("Managed VPN route is missing")
	if e := tunnel.ReconcileRoute(ctx); e == nil {
		t.Fatal("missing route ignored")
	}
	if s := tunnel.Status(ctx); s.Connected || s.Phase != "routing_error" || !strings.Contains(s.Error, "route is missing") || !s.Running {
		t.Fatal("handshake concealed routing failure", s)
	}
	routing.routeError, routing.routeRepairs = nil, true
	starts := len(driver.starts)
	if e := tunnel.ReconcileRoute(ctx); e != nil {
		t.Fatal(e)
	}
	if s := tunnel.Status(ctx); !s.Connected || s.Route.Repairs != 1 || s.Route.LastRepair == 0 || s.Error != "" || len(driver.starts) != starts {
		t.Fatal("route repair restarted VPN or did not clear failure", s)
	}
	if e := tunnel.Disable(ctx); e != nil {
		t.Fatal(e)
	}
	checks := routing.routeChecks
	if e := tunnel.ReconcileRoute(ctx); e != nil {
		t.Fatal(e)
	}
	if routing.routeChecks != checks || routing.enabled || driver.stats.Running || tunnel.Status(ctx).Connected {
		t.Fatal("background repair undid Disconnect")
	}
}

func TestTunnelDoesNotConnectWithMissingOrStaleRoute(t *testing.T) {
	tunnel, driver, routing := newTestTunnel(t)
	ctx := context.Background()
	routing.routeError = errors.New("Managed VPN route is missing")
	if e := tunnel.Activate(ctx, testProfile("1111111111111111", "9.9.9.9")); e == nil || len(driver.starts) != 0 {
		t.Fatal("connection started without route validation")
	}
	routing.routeError = nil
	if e := tunnel.Toggle(ctx); e != nil {
		t.Fatal(e)
	}
	tunnel.mu.Lock()
	tunnel.route.CheckedAt = time.Now().Add(-time.Minute).Unix()
	tunnel.mu.Unlock()
	if s := tunnel.Status(ctx); s.Connected || s.Phase != "routing_error" || !strings.Contains(s.Error, "overdue") {
		t.Fatal("stale route status was trusted", s)
	}
	checks := routing.routeChecks
	tunnel.op.Lock()
	if e := tunnel.ReconcileRoute(ctx); e != nil {
		t.Fatal(e)
	}
	tunnel.op.Unlock()
	if routing.routeChecks != checks {
		t.Fatal("guard raced a connection operation")
	}
	if e := tunnel.ReconcileRoute(ctx); e != nil || !tunnel.Status(ctx).Connected {
		t.Fatal(e)
	}
}

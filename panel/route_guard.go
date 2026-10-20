package main

import (
	"context"
	"errors"
	"log"
	"time"
)

const routeCheckMaxAge = 20 * time.Second

type RouteHealth struct {
	Ready      bool   `json:"ready"`
	CheckedAt  int64  `json:"checked_at"`
	Repairs    uint64 `json:"repairs"`
	LastRepair int64  `json:"last_repair,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RouterOS switch properties can be present with an empty value in REST.
// Absence and an explicit false must remain distinct from that representation.
func routeSwitch(row Row, key string) bool {
	value, present := row[key]
	return present && (value == "" || value == "true" || value == "yes")
}

// Only the installed default route can be repaired. Unknown routes, changed
// gateways and missing fallback protection require deliberate reconfiguration.
func managedTunnelRoute(rows []Row) (Row, error) {
	var tunnel, fallback Row
	for _, row := range rows {
		if row["routing-table"] != "to-awg" || row["dst-address"] != "0.0.0.0/0" {
			continue
		}
		switch row["comment"] {
		case "AWGC tunnel route", "AWG3 default":
			if tunnel != nil {
				return nil, errors.New("Multiple managed VPN routes; inspect IP Routes")
			}
			tunnel = row
		case "AWGC no main fallback", "AWG3UI no main fallback":
			if fallback != nil {
				return nil, errors.New("Multiple VPN fallback guards; inspect IP Routes")
			}
			fallback = row
		default:
			return nil, errors.New("Unexpected default route in to-awg; automatic repair refused")
		}
	}
	if tunnel == nil || tunnel[".id"] == "" {
		return nil, errors.New("Managed VPN route is missing; restore the RouterOS integration")
	}
	// Disabled routes omit the default distance (1); the active readback below
	// must report it explicitly before we accept the repair.
	distanceOK := tunnel["distance"] == "1" || (tunnel["disabled"] == "true" && tunnel["distance"] == "")
	if tunnel["dynamic"] == "true" || routeSwitch(tunnel, "blackhole") || !distanceOK ||
		(tunnel["gateway"] != "172.18.20.2@main" && tunnel["gateway"] != "172.18.20.2") {
		return nil, errors.New("Managed VPN route was changed; automatic repair refused")
	}
	if fallback == nil || !routeSwitch(fallback, "blackhole") || fallback["disabled"] == "true" ||
		fallback["dynamic"] == "true" || fallback["distance"] != "254" {
		return nil, errors.New("VPN fallback protection is missing or changed; inspect IP Routes")
	}
	return tunnel, nil
}

func (r *Router) EnsureRoute(ctx context.Context) (bool, error) {
	read := func() (Row, error) {
		rows, e := r.rows(ctx, "ip/route", ".id,comment,routing-table,dst-address,gateway,immediate-gw,distance,disabled,active,dynamic,blackhole", "routing-table=to-awg")
		if e != nil {
			return nil, e
		}
		return managedTunnelRoute(rows)
	}
	row, e := read()
	if e != nil {
		return false, e
	}
	repaired := false
	if row["disabled"] == "true" {
		if e = r.call(ctx, "PATCH", "ip/route/"+row[".id"], Row{"disabled": "false"}, nil); e != nil {
			return false, e
		}
		repaired = true
		row, e = read()
		if e != nil {
			return false, e
		}
	}
	if row["disabled"] == "true" || row["active"] != "true" || row["immediate-gw"] != "172.18.20.2%docker-awg-veth" {
		return false, errors.New("VPN route is not active through the container; inspect IP Routes and the container interface")
	}
	return repaired, nil
}

func (t *Tunnel) ensureRoute(ctx context.Context) error {
	repaired, e := t.routing.EnsureRoute(ctx)
	t.mu.Lock()
	t.route.CheckedAt = time.Now().Unix()
	t.route.Ready = e == nil
	t.route.Error = ""
	if e != nil {
		t.route.Error = e.Error()
	}
	if repaired {
		t.route.Repairs++
		t.route.LastRepair = t.route.CheckedAt
	}
	t.mu.Unlock()
	if repaired {
		log.Print("AWGC route guard: re-enabled the managed VPN route")
	}
	return e
}

func (t *Tunnel) ReconcileRoute(ctx context.Context) error {
	// Serialize with connect/disconnect, including button-triggered operations.
	// A normal Disconnect must never be undone by this background check.
	if !t.op.TryLock() {
		return nil
	}
	defer t.op.Unlock()
	s := t.snapshot()
	if !s.Enabled || s.Active.ID == "" {
		return nil
	}
	return t.ensureRoute(ctx)
}

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func trafficSettings() Settings { return Settings{LAN: "192.168.3.0/24", Bridge: "bridge"} }
func measuredTraffic() []Row {
	rows := trafficRules(trafficSettings())
	for i := range rows {
		rows[i]["bytes"] = []string{"100", "900", "200", "1800"}[i]
		rows[i]["packets"] = []string{"1", "9", "2", "18"}[i]
		rows[i][".id"] = []string{"*1", "*2", "*3", "*4"}[i]
	}
	return rows
}

func TestTrafficCountsBothDirectionsWithoutPolicyDoubleCounting(t *testing.T) {
	rows := append(measuredTraffic(), Row{"comment": Tag + "AWG3UI-a", "bytes": "999999", "packets": "9999"})
	got := parseTraffic(rows, trafficSettings())
	if !got.Available || got.Direct.Upload.Bytes != 100 || got.Direct.Download.Bytes != 900 || got.VPN.Upload.Bytes != 200 || got.VPN.Download.Bytes != 1800 || got.VPN.Download.Packets != 18 || got.SampledAt == "" {
		t.Fatal(got)
	}
	// Native router counters may restart at zero; this is a new measurement,
	// not a negative delta or a continuation of an invented cumulative total.
	for _, row := range rows {
		row["bytes"], row["packets"] = "0", "0"
	}
	zero := parseTraffic(rows, trafficSettings())
	if !zero.Available || zero.Direct != (TrafficPath{}) || zero.VPN != (TrafficPath{}) {
		t.Fatal(zero)
	}
}

func TestTrafficNeverTurnsMissingOrInvalidDataIntoZero(t *testing.T) {
	for _, change := range []func([]Row) []Row{
		func(rows []Row) []Row { return rows[:3] },
		func(rows []Row) []Row { return append(rows, rows[0]) },
		func(rows []Row) []Row { rows[0]["disabled"] = "true"; return rows },
		func(rows []Row) []Row { rows[0]["invalid"] = "true"; return rows },
		func(rows []Row) []Row { rows[0]["src-address-list"] = ""; return rows },
		func(rows []Row) []Row { rows[0]["bytes"] = "-1"; return rows },
		func(rows []Row) []Row { rows[0]["packets"] = ""; return rows },
		func(rows []Row) []Row { rows[0]["bytes"] = "18446744073709551616"; return rows },
	} {
		got := parseTraffic(change(measuredTraffic()), trafficSettings())
		if got.Available || got.Error == "" || got.Direct != (TrafficPath{}) || got.VPN != (TrafficPath{}) {
			t.Fatal("invalid readings were presented as current traffic", got)
		}
	}
}

func TestTrafficObservationExcludesManagementTransportAndPrivateNetworks(t *testing.T) {
	type flow struct{ in, out, src, dst string }
	rules := trafficRules(trafficSettings())
	contains := func(address string, prefixes []string) bool {
		for _, prefix := range prefixes {
			if netip.MustParsePrefix(prefix).Contains(netip.MustParseAddr(address)) {
				return true
			}
		}
		return false
	}
	matches := func(rule Row, f flow, ready bool) bool {
		if !ready {
			return false
		}
		for _, pair := range [][2]string{{"in-interface", f.in}, {"out-interface", f.out}} {
			if rule[pair[0]] != "" && rule[pair[0]] != pair[1] {
				return false
			}
		}
		if rule["in-interface-list"] == "WAN" && f.in != "ether1" || rule["out-interface-list"] == "WAN" && f.out != "ether1" {
			return false
		}
		for _, pair := range [][2]string{{"src-address", f.src}, {"dst-address", f.dst}} {
			if rule[pair[0]] != "" && !contains(pair[1], []string{rule[pair[0]]}) {
				return false
			}
		}
		if rule["dst-address-list"] == "!"+trafficLocalList && contains(f.dst, trafficPrivate) || rule["src-address-list"] == "!"+trafficLocalList && contains(f.src, trafficPrivate) {
			return false
		}
		return true
	}
	cases := []struct {
		f    flow
		want string
	}{
		{flow{"bridge", "ether1", "192.168.3.20", "77.88.44.55"}, "direct upload"},
		{flow{"ether1", "bridge", "77.88.44.55", "192.168.3.20"}, "direct download"},
		{flow{"bridge", "docker-awg-veth", "192.168.3.20", "74.125.8.166"}, "vpn upload"},
		{flow{"docker-awg-veth", "bridge", "74.125.8.166", "192.168.3.20"}, "vpn download"},
		{flow{"bridge", "docker-awg-veth", "192.168.3.20", "172.18.20.2"}, ""},
		{flow{"docker-awg-veth", "bridge", "172.18.20.2", "192.168.3.20"}, ""},
		{flow{"docker-awg-veth", "ether1", "172.18.20.2", "9.9.9.9"}, ""},
		{flow{"ether1", "docker-awg-veth", "9.9.9.9", "172.18.20.2"}, ""},
		{flow{"", "docker-awg-veth", "172.18.20.1", "1.1.1.1"}, ""},
		{flow{"bridge", "ether1", "192.168.3.20", "192.168.1.1"}, ""},
		{flow{"ether1", "bridge", "192.168.1.1", "192.168.3.20"}, ""},
		{flow{"bridge", "bridge", "192.168.3.20", "192.168.3.21"}, ""},
	}
	for _, c := range cases {
		var found []string
		for _, rule := range rules {
			if rule["action"] != "passthrough" || rule["chain"] != "forward" {
				t.Fatal("counter changes packet handling", rule)
			}
			if matches(rule, c.f, false) {
				t.Fatal("counted before volatile metadata was ready")
			}
			if matches(rule, c.f, true) {
				found = append(found, strings.TrimPrefix(rule["comment"], trafficTag))
			}
		}
		if len(found) > 1 || (len(found) == 0) != (c.want == "") || len(found) == 1 && found[0] != c.want {
			t.Fatalf("%+v: %v", c, found)
		}
	}
}

func TestTrafficRefreshIsReadOnlyAndDoesNotScanGeoOrConnections(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		var query map[string]any
		_ = json.NewDecoder(req.Body).Decode(&query)
		if req.Method != "POST" || req.URL.Path != "/rest/ip/firewall/mangle/print" || !reflect.DeepEqual(query[".query"], []any{"chain=forward"}) {
			t.Errorf("unexpected polling operation %s %s %v", req.Method, req.URL.Path, query)
		}
		_ = json.NewEncoder(w).Encode(measuredTraffic())
	}))
	defer server.Close()
	s := trafficSettings()
	s.RouterURL = server.URL
	r := newRouter(s)
	r.trafficInitialized = true
	for range 2 {
		if !r.traffic(context.Background()).Available {
			t.Fatal("reading unavailable")
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestTrafficSetupKeepsExistingCountersAndUsesOnlyRAMMetadata(t *testing.T) {
	var mangle []Row
	lists := map[string][]Row{}
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		switch req.URL.Path {
		case "/rest/ip/firewall/mangle/print":
			_ = json.NewEncoder(w).Encode(mangle)
		case "/rest/ip/firewall/address-list/print":
			query := body[".query"].([]any)[0].(string)
			_ = json.NewEncoder(w).Encode(lists[strings.TrimPrefix(query, "list=")])
		case "/rest/ip/firewall/address-list/add":
			writes++
			if body["dynamic"] != "yes" {
				t.Error("metadata was persisted to flash")
			}
			name := body["list"].(string)
			lists[name] = append(lists[name], Row{"address": body["address"].(string), "comment": body["comment"].(string), "dynamic": "true"})
			_, _ = w.Write([]byte(`{"ret":"*1"}`))
		case "/rest/ip/firewall/mangle/add":
			writes++
			row := Row{"bytes": "12345", "packets": "45"}
			for k, v := range body {
				row[k] = v.(string)
			}
			mangle = append(mangle, row)
			_, _ = w.Write([]byte(`{"ret":"*2"}`))
		default:
			t.Errorf("unexpected mutation %s", req.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	s := trafficSettings()
	s.RouterURL = server.URL
	r := newRouter(s)
	if err := r.initializeTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstWrites := writes
	if len(mangle) != 4 || len(lists[trafficLocalList]) != 9 || len(lists[trafficReadyList]) != 1 {
		t.Fatal(mangle, lists)
	}
	if err := r.initializeTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes != firstWrites {
		t.Fatal("startup rewrote counters", writes, firstWrites)
	}
	if got := r.traffic(context.Background()); !got.Available || got.Direct.Download.Bytes != 12345 {
		t.Fatal(got)
	}
	// Ownership conflicts do not cause replacement or removal of foreign rules.
	mangle[0]["action"] = "accept"
	if r.initializeTraffic(context.Background()) == nil || writes != firstWrites {
		t.Fatal("modified foreign/changed rule")
	}
	if r.traffic(context.Background()).Available {
		t.Fatal("failed setup displayed a current reading")
	}
}

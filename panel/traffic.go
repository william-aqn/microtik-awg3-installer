package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const trafficTag = "AWGC traffic "
const trafficLocalList = "AWGC-traffic-local"
const trafficReadyList = "AWGC-traffic-ready"
const trafficProps = ".id,comment,chain,action,src-address,dst-address,src-address-list,dst-address-list,in-interface,out-interface,in-interface-list,out-interface-list,disabled,invalid,dynamic,bytes,packets"

var trafficPrivate = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"}

type TrafficCount struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}
type TrafficPath struct {
	Upload   TrafficCount `json:"upload"`
	Download TrafficCount `json:"download"`
}
type TrafficSnapshot struct {
	Available bool        `json:"available"`
	Error     string      `json:"error,omitempty"`
	SampledAt string      `json:"sampled_at,omitempty"`
	Direct    TrafficPath `json:"direct"`
	VPN       TrafficPath `json:"vpn"`
}

// These counters observe actual LAN forwarding in both directions. They do not
// mark, accept or drop packets, and survive policy-slot switches and VPN toggles.
func trafficRules(s Settings) []Row {
	return []Row{
		{"comment": trafficTag + "direct upload", "chain": "forward", "action": "passthrough", "in-interface": s.Bridge, "out-interface-list": "WAN", "src-address": s.LAN, "src-address-list": trafficReadyList, "dst-address-list": "!" + trafficLocalList},
		{"comment": trafficTag + "direct download", "chain": "forward", "action": "passthrough", "in-interface-list": "WAN", "out-interface": s.Bridge, "dst-address": s.LAN, "dst-address-list": trafficReadyList, "src-address-list": "!" + trafficLocalList},
		{"comment": trafficTag + "vpn upload", "chain": "forward", "action": "passthrough", "in-interface": s.Bridge, "out-interface": "docker-awg-veth", "src-address": s.LAN, "src-address-list": trafficReadyList, "dst-address-list": "!" + trafficLocalList},
		{"comment": trafficTag + "vpn download", "chain": "forward", "action": "passthrough", "in-interface": "docker-awg-veth", "out-interface": s.Bridge, "dst-address": s.LAN, "dst-address-list": trafficReadyList, "src-address-list": "!" + trafficLocalList},
	}
}

func trafficRuleMatches(row, want Row) bool {
	if row["disabled"] == "true" || row["invalid"] == "true" || row["dynamic"] == "true" {
		return false
	}
	for _, key := range []string{"comment", "chain", "action", "src-address", "dst-address", "src-address-list", "dst-address-list", "in-interface", "out-interface", "in-interface-list", "out-interface-list"} {
		if row[key] != want[key] {
			return false
		}
	}
	return true
}

// Volatile metadata avoids writing even these small exclusion lists to flash.
// The ready list is added last; after a router reboot counters stay dormant until
// exclusions are restored. A container restart leaves the existing totals alone.
func (r *Router) ensureTraffic(ctx context.Context) error {
	wanted := trafficRules(r.settings)
	rows, err := r.rows(ctx, "ip/firewall/mangle", trafficProps)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	before := ""
	for _, row := range rows {
		if before == "" && row["dynamic"] != "true" && routerRecordID.MatchString(row[".id"]) {
			before = row[".id"]
		}
		if !strings.HasPrefix(row["comment"], trafficTag) {
			continue
		}
		valid := false
		for _, want := range wanted {
			valid = valid || trafficRuleMatches(row, want)
		}
		if !valid || existing[row["comment"]] {
			return errors.New("Traffic counter rules were changed or duplicated; inspect diagnostics")
		}
		existing[row["comment"]] = true
	}
	for _, spec := range []struct {
		name string
		ips  []string
	}{{trafficLocalList, trafficPrivate}, {trafficReadyList, []string{r.settings.LAN}}} {
		entries, e := r.rows(ctx, "ip/firewall/address-list", "address,comment,dynamic,disabled", "list="+spec.name)
		if e != nil {
			return e
		}
		missing := map[string]bool{}
		for _, ip := range spec.ips {
			missing[ip] = true
		}
		for _, row := range entries {
			if !missing[row["address"]] || row["comment"] != trafficTag+"metadata" || row["dynamic"] != "true" || row["disabled"] == "true" {
				return errors.New("Traffic counter metadata is occupied or modified")
			}
			missing[row["address"]] = false
		}
		for _, ip := range spec.ips {
			if missing[ip] {
				if e = r.call(ctx, "POST", "ip/firewall/address-list/add", Row{"list": spec.name, "address": ip, "dynamic": "yes", "comment": trafficTag + "metadata"}, nil); e != nil {
					return e
				}
			}
		}
	}
	for _, want := range wanted {
		if existing[want["comment"]] {
			continue
		}
		if before != "" {
			want["place-before"] = before
		}
		if err = r.call(ctx, "POST", "ip/firewall/mangle/add", want, nil); err != nil {
			return err
		}
	}
	return nil
}

func (r *Router) initializeTraffic(ctx context.Context) error {
	err := r.ensureTraffic(ctx)
	r.trafficMu.Lock()
	r.trafficInitialized = true
	r.trafficError = err
	r.trafficMu.Unlock()
	return err
}

func parseTraffic(rows []Row, s Settings) TrafficSnapshot {
	out := TrafficSnapshot{}
	wanted := trafficRules(s)
	counts := []*TrafficCount{&out.Direct.Upload, &out.Direct.Download, &out.VPN.Upload, &out.VPN.Download}
	for i, want := range wanted {
		found := false
		for _, row := range rows {
			if row["comment"] != want["comment"] {
				continue
			}
			if found || !trafficRuleMatches(row, want) {
				return TrafficSnapshot{Error: "Traffic counters were changed or duplicated"}
			}
			found = true
			for _, field := range []struct {
				name string
				dst  *uint64
			}{{"bytes", &counts[i].Bytes}, {"packets", &counts[i].Packets}} {
				n, err := strconv.ParseUint(row[field.name], 10, 64)
				if err != nil {
					return TrafficSnapshot{Error: "Router returned invalid traffic counters"}
				}
				*field.dst = n
			}
		}
		if !found {
			return TrafficSnapshot{Error: "Traffic counter rules are missing; restart the panel container"}
		}
	}
	out.Available = true
	out.SampledAt = time.Now().UTC().Format(time.RFC3339)
	return out
}

func (r *Router) traffic(ctx context.Context) TrafficSnapshot {
	r.trafficMu.RLock()
	initialized, setupErr := r.trafficInitialized, r.trafficError
	r.trafficMu.RUnlock()
	if !initialized {
		return TrafficSnapshot{Error: "Traffic counters are starting"}
	}
	if setupErr != nil {
		return TrafficSnapshot{Error: fmt.Sprintf("Traffic counters unavailable: %v", setupErr)}
	}
	// Only the small mangle table is read. Never scan connections, DNS records or
	// the large Geo address lists during the five-second dashboard refresh.
	rows, err := r.rows(ctx, "ip/firewall/mangle", trafficProps, "chain=forward")
	if err != nil {
		return TrafficSnapshot{Error: err.Error()}
	}
	return parseTraffic(rows, r.settings)
}

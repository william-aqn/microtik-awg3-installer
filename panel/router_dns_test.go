package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectDNSPreparationAndGate(t *testing.T) {
	for _, scenario := range []string{"normal", "old-button", "doh", "dynamic", "foreign-helper"} {
		t.Run(scenario, func(t *testing.T) {
			helper := Row{}
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/print") {
					var body struct {
						Query []string `json:".query"`
					}
					_ = json.NewDecoder(req.Body).Decode(&body)
					rows := []Row{}
					if req.URL.Path == "/rest/ip/dns/print" {
						row := Row{}
						if scenario == "doh" {
							row["use-doh-server"] = "https://dns.example/dns-query"
						}
						if scenario == "dynamic" {
							row["dynamic-servers"] = "192.168.1.1"
						}
						rows = []Row{row}
					} else if len(body.Query) == 1 {
						switch body.Query[0] {
						case "name=awg-stop":
							source := "/system/script/run awg-control-direct-dns"
							if scenario == "old-button" {
								source = "/container/stop 0"
							}
							rows = []Row{{"source": source}}
						case "name=awg-control-direct-dns":
							if scenario == "foreign-helper" {
								rows = []Row{{".id": "*1", "comment": "unrelated"}}
							} else if len(helper) != 0 {
								rows = []Row{helper}
							}
						case "name=awg-control-gate":
							rows = []Row{{".id": "*2", "comment": Tag + "managed", "source": `/import file-name="usb1-part1/awg-control-data/router-awg-control-gate.rsc"`}}
						}
					}
					_ = json.NewEncoder(w).Encode(rows)
					return
				}
				if req.Method == "PUT" || req.Method == "PATCH" {
					writes++
					_ = json.NewDecoder(req.Body).Decode(&helper)
					helper[".id"] = "*1"
				}
				_ = json.NewEncoder(w).Encode(Row{})
			}))
			defer server.Close()
			r := newRouter(Settings{RouterURL: server.URL, DataDir: t.TempDir(), LAN: "192.168.3.0/24"})
			r.scriptDir = "usb1-part1/awg-control-data"
			ctx := context.Background()
			err := r.prepareDirectDNS(ctx, []string{"1.1.1.1", "8.8.8.8"})
			if scenario != "normal" {
				if err == nil || writes != 0 {
					t.Fatal("Unsafe DNS configuration was changed", scenario, err, writes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = r.prepareDirectDNS(ctx, []string{"1.1.1.1", "8.8.8.8"}); err != nil {
				t.Fatal(err)
			}
			if writes != 1 || helper["source"] != "/ip/dns/set servers=1.1.1.1,8.8.8.8" {
				t.Fatal("Unchanged helper rewrote persistent configuration", helper, writes)
			}
			for _, on := range []bool{true, false} {
				if err := r.Gate(ctx, on); err != nil {
					t.Fatal(err)
				}
				batch, err := os.ReadFile(filepath.Join(r.settings.DataDir, "router-awg-control-gate.rsc"))
				if err != nil {
					t.Fatal(err)
				}
				want := "/ip/dns/set servers=172.18.20.2"
				if !on {
					want = "/system/script/run awg-control-direct-dns"
				}
				if !strings.Contains(string(batch), want) {
					t.Fatal("DNS did not follow the connection state", string(batch))
				}
				if !on && !strings.Contains(string(batch), "else={ :if ([:len [/system/script/find where name=\"awg-control-restore-dns\"]]") {
					t.Fatal("Disconnect cannot recover from a failed first profile setup")
				}
			}
		})
	}
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const controlSocket = "/run/awg-control.sock"

func (a *App) profileAPI(w http.ResponseWriter, r *http.Request) {
	if a.profiles == nil {
		apiError(w, 503, "Profile manager unavailable")
		return
	}
	if r.Method == "GET" {
		id := r.URL.Query().Get("id")
		if id == "" {
			reply(w, 200, a.profiles.List())
			return
		}
		p, e := a.profiles.Get(id)
		if e != nil {
			apiError(w, 404, e.Error())
			return
		}
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="`+p.ID+`.conf"`)
			_, _ = io.WriteString(w, p.Config)
			return
		}
		reply(w, 200, p)
		return
	}
	var input struct {
		Action string `json:"action"`
		Profile
		IDToActivate string `json:"profile_id"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&input); e != nil {
		apiError(w, 400, "Invalid profile request")
		return
	}
	if input.Action == "activate" {
		p, e := a.profiles.Get(input.IDToActivate)
		if e != nil {
			apiError(w, 404, e.Error())
			return
		}
		if e = a.queueTunnel("activate", p); e != nil {
			apiError(w, 409, e.Error())
			return
		}
		reply(w, 202, map[string]bool{"accepted": true})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		apiError(w, 409, "An operation is already running")
		return
	}
	switch input.Action {
	case "save":
		p, e := a.profiles.Save(input.Profile)
		if e != nil {
			apiError(w, 400, e.Error())
			return
		}
		reply(w, 200, map[string]string{"id": p.ID, "revision": p.Revision})
		a.message = "Profile saved. Activate it to change the connection."
	case "delete":
		active := ""
		if a.tunnel != nil {
			saved := a.tunnel.snapshot()
			active = saved.Active.ID
			if input.ID == saved.Previous.ID {
				apiError(w, 400, "This profile is retained for connection rollback")
				return
			}
		}
		if e := a.profiles.Delete(input.ID, input.Revision, active); e != nil {
			apiError(w, 400, e.Error())
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
		a.message = "Profile removed; previous store retained on USB."
	default:
		apiError(w, 400, "Unknown profile action")
	}
}
func (a *App) queueTunnel(action string, p Profile) error {
	switch action {
	case "toggle", "connect", "disconnect", "restart", "rollback", "activate", "poweroff":
	default:
		return errors.New("Unsupported tunnel action")
	}
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return errors.New("An operation is already running")
	}
	a.busy = true
	a.lastError = ""
	a.message = "Updating connection"
	a.mu.Unlock()
	go func() {
		var e error
		ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
		defer cancel()
		if a.demo {
			a.mu.Lock()
			if action == "activate" {
				a.demoProfile = p
			}
			if action == "toggle" {
				a.demoEnabled = !a.demoEnabled
			} else if action == "disconnect" {
				a.demoEnabled = false
			} else {
				a.demoEnabled = true
			}
			a.mu.Unlock()
		} else {
			switch action {
			case "toggle":
				e = a.tunnel.Toggle(ctx)
			case "disconnect":
				e = a.tunnel.Disable(ctx)
			case "rollback":
				e = a.tunnel.Rollback(ctx)
			case "activate":
				e = a.tunnel.Activate(ctx, p)
			case "poweroff":
				e = a.tunnel.Disable(ctx)
				if e == nil {
					time.Sleep(500 * time.Millisecond)
					e = a.router.PowerOff(ctx)
				}
			default:
				s := a.tunnel.snapshot()
				if action == "connect" && a.tunnel.Status(ctx).Connected {
					break
				} else if s.Active.ID == "" {
					e = errors.New("Import and activate a profile first")
				} else {
					e = a.tunnel.Activate(ctx, s.Active)
				}
			}
		}
		if e != nil {
			a.saveDiagnostic(e)
		}
		a.finish(e)
	}()
	return nil
}
func (a *App) tunnelAPI(w http.ResponseWriter, r *http.Request, action string) {
	if r.Method != "POST" {
		apiError(w, 405, "POST required")
		return
	}
	if !a.demo && a.tunnel == nil {
		apiError(w, 503, "Controller unavailable")
		return
	}
	if e := a.queueTunnel(action, Profile{}); e != nil {
		apiError(w, 409, e.Error())
		return
	}
	reply(w, 202, map[string]bool{"accepted": true})
}
func (a *App) watchTunnel() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for range tick.C {
		a.mu.Lock()
		busy := a.busy
		a.mu.Unlock()
		if busy {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s := a.tunnel.Status(ctx)
		_ = a.router.LED(ctx, s.Connected)
		cancel()
	}
}
func (a *App) diagnostics(ctx context.Context) map[string]any {
	d := map[string]any{"version": Version}
	if a.router != nil {
		d, _ = a.router.diagnostics(ctx)
	}
	if a.tunnel != nil {
		d["tunnel"] = a.tunnel.Status(ctx)
	}
	return d
}
func (a *App) saveDiagnostic(e error) {
	if a.demo {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d := a.diagnostics(ctx)
	d["error"] = e.Error()
	_ = writeJSON(filepath.Join(a.s.DataDir, "last-error.json"), d)
}
func (a *App) listenControl() error {
	_ = os.Remove(controlSocket)
	listener, e := net.Listen("unix", controlSocket)
	if e != nil {
		return errors.New("Cannot open local control socket")
	}
	if e = os.Chmod(controlSocket, 0600); e != nil {
		_ = listener.Close()
		return e
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 20 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/diag" {
			reply(w, 200, a.diagnostics(r.Context()))
			return
		}
		if r.Method != "POST" {
			apiError(w, 405, "POST required")
			return
		}
		if e := a.queueTunnel(strings.TrimPrefix(r.URL.Path, "/"), Profile{}); e != nil {
			apiError(w, 409, e.Error())
			return
		}
		reply(w, 202, map[string]bool{"accepted": true})
	})}
	go func() { _ = server.Serve(listener) }()
	return nil
}
func controlCLI(action string) error {
	allowed := map[string]bool{"toggle": true, "connect": true, "disconnect": true, "restart": true, "rollback": true, "diag": true}
	if !allowed[action] {
		return errors.New("Unknown control command")
	}
	client := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", controlSocket)
	}}}
	method := "POST"
	if action == "diag" {
		method = "GET"
	}
	deadline := time.Now().Add(100 * time.Second)
	for {
		req, _ := http.NewRequest(method, "http://localhost/"+action, nil)
		resp, e := client.Do(req)
		var b []byte
		if e == nil {
			b, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if resp.StatusCode < 300 {
				fmt.Println(string(b))
				return nil
			}
		}
		// A physical press can start a stopped container before the controller
		// is ready. Only idempotent Connect retries, never Toggle.
		if action == "connect" && time.Now().Before(deadline) && (e != nil || resp.StatusCode == 409) {
			time.Sleep(time.Second)
			continue
		}
		if e != nil {
			return errors.New("Controller unavailable or still starting")
		}
		return fmt.Errorf("Control request refused: %s", strings.TrimSpace(string(b)))
	}
}

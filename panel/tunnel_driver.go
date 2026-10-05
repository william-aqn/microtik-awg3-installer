package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const awgSocket = "/var/run/amneziawg/awg0.sock"

type TunnelStats struct {
	Running   bool   `json:"running"`
	Handshake int64  `json:"handshake"`
	RX        uint64 `json:"rx_bytes"`
	TX        uint64 `json:"tx_bytes"`
}
type TunnelDriver interface {
	Initialize(context.Context) error
	Start(context.Context, VPNConfig, string) error
	Stop(context.Context) error
	Stats(context.Context) (TunnelStats, error)
	Probe(context.Context) error
}
type LinuxTunnel struct {
	mu                        sync.Mutex
	uplink, gateway, endpoint string
	child                     *exec.Cmd
	done                      chan struct{}
	testLog                   io.Writer
}

func command(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout = io.Discard
	c.Stderr = io.Discard
	if e := c.Run(); e != nil {
		return fmt.Errorf("%s operation failed; command output suppressed to protect secrets", name)
	}
	return nil
}
func (d *LinuxTunnel) Initialize(ctx context.Context) error {
	b, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e != nil {
		return errors.New("Cannot inspect IPv4 forwarding")
	}
	if strings.TrimSpace(string(b)) != "1" {
		if e = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); e != nil {
			return errors.New("Container requires IPv4 forwarding")
		}
	}
	// This container owns its network namespace. Forwarded LAN traffic must
	// never leave through the cleartext uplink, even if the tunnel disappears.
	rules := [][]string{{"-P", "FORWARD", "DROP"}, {"-F", "FORWARD"}, {"-A", "FORWARD", "-i", d.uplink, "-o", "awg0", "-j", "ACCEPT"}, {"-A", "FORWARD", "-i", "awg0", "-o", d.uplink, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}, {"-t", "nat", "-F", "POSTROUTING"}, {"-t", "nat", "-A", "POSTROUTING", "-o", "awg0", "-j", "MASQUERADE"}}
	for _, args := range rules {
		if e = command(ctx, "iptables-legacy", args...); e != nil {
			return e
		}
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if e = command(ctx, "ip", "route", "replace", cidr, "via", d.gateway, "dev", d.uplink); e != nil {
			return e
		}
	}
	return nil
}
func uapi(ctx context.Context, path, request string) (map[string]string, error) {
	conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	if e != nil {
		return nil, errors.New("Tunnel control socket is unavailable")
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	_ = conn.SetDeadline(deadline)
	if _, e = io.WriteString(conn, request); e != nil {
		return nil, errors.New("Tunnel control write failed")
	}
	result := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(conn, 128<<10))
	scanner.Buffer(make([]byte, 4096), 16384)
	ended := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			ended = true
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "errno", "last_handshake_time_sec", "rx_bytes", "tx_bytes":
			result[k] = v
		}
	}
	if scanner.Err() != nil || !ended {
		return nil, errors.New("Incomplete tunnel control response")
	}
	if result["errno"] != "0" {
		return nil, errors.New("AWG rejected configuration or control request; secret values are hidden")
	}
	return result, nil
}
func (d *LinuxTunnel) Start(ctx context.Context, c VPNConfig, endpoint string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.child != nil {
		return errors.New("Previous tunnel process has not stopped")
	}
	if e := command(ctx, "ip", "route", "replace", endpoint+"/32", "via", d.gateway, "dev", d.uplink); e != nil {
		return e
	}
	d.endpoint = endpoint
	_ = os.Remove(awgSocket)
	child := exec.Command("amneziawg-go", "-f", "awg0")
	child.Env = append(os.Environ(), "LOG_LEVEL=silent", "GOMEMLIMIT=12MiB", "GOGC=40", "GOMAXPROCS=2")
	child.Stdout = io.Discard
	child.Stderr = io.Discard
	if d.testLog != nil {
		child.Env = append(child.Env, "LOG_LEVEL=verbose")
		child.Stdout, child.Stderr = d.testLog, d.testLog
	}
	if e := child.Start(); e != nil {
		return errors.New("Cannot start AWG engine")
	}
	d.child = child
	d.done = make(chan struct{})
	done := d.done
	go func() { _ = child.Wait(); close(done) }()
	ready := false
	for i := 0; i < 60; i++ {
		if _, e := os.Stat(awgSocket); e == nil {
			ready = true
			break
		}
		select {
		case <-done:
			return errors.New("AWG engine exited during startup")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		return errors.New("AWG engine did not open its control socket")
	}
	if _, e := uapi(ctx, awgSocket, c.UAPI(endpoint)); e != nil {
		return e
	}
	for _, args := range [][]string{{"address", "add", c.Address, "dev", "awg0"}, {"link", "set", "dev", "awg0", "mtu", strconv.Itoa(c.MTU), "up"}, {"route", "replace", "0.0.0.0/1", "dev", "awg0"}, {"route", "replace", "128.0.0.0/1", "dev", "awg0"}} {
		if e := command(ctx, "ip", args...); e != nil {
			return e
		}
	}
	return nil
}
func (d *LinuxTunnel) Stop(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Removing the interface removes its routes and closes the engine's TUN.
	_ = command(ctx, "ip", "link", "delete", "dev", "awg0")
	if d.child != nil {
		_ = d.child.Process.Signal(os.Interrupt)
		select {
		case <-d.done:
		case <-time.After(time.Second):
			_ = d.child.Process.Kill()
			select {
			case <-d.done:
			case <-time.After(time.Second):
				return errors.New("AWG engine did not stop")
			}
		}
		d.child = nil
		d.done = nil
	}
	if d.endpoint != "" {
		_ = command(ctx, "ip", "route", "del", d.endpoint+"/32", "via", d.gateway, "dev", d.uplink)
		d.endpoint = ""
	}
	_ = os.Remove(awgSocket)
	return nil
}
func (d *LinuxTunnel) Stats(ctx context.Context) (TunnelStats, error) {
	d.mu.Lock()
	live := d.child != nil
	if live {
		select {
		case <-d.done:
			live = false
		default:
		}
	}
	d.mu.Unlock()
	if !live {
		return TunnelStats{}, nil
	}
	m, e := uapi(ctx, awgSocket, "get=1\n\n")
	if e != nil {
		return TunnelStats{Running: true}, e
	}
	s := TunnelStats{Running: true}
	s.Handshake, _ = strconv.ParseInt(m["last_handshake_time_sec"], 10, 64)
	s.RX, _ = strconv.ParseUint(m["rx_bytes"], 10, 64)
	s.TX, _ = strconv.ParseUint(m["tx_bytes"], 10, 64)
	return s, nil
}
func (d *LinuxTunnel) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", "1.1.1.1:443")
	if e != nil {
		return errors.New("No internet response through the tunnel")
	}
	_ = c.Close()
	return nil
}

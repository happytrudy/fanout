package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequireWriteRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		origin string
		code   int
	}{
		{"get", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"cross-origin", http.MethodPost, "https://attacker.example", http.StatusForbidden},
		{"post", http.MethodPost, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://fanout.example/api/stop", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			got := requireWriteRequest(rec, req)
			if tc.code == 0 {
				if !got {
					t.Fatal("合法 POST 被拒绝")
				}
				return
			}
			if got || rec.Code != tc.code {
				t.Fatalf("got allowed=%v status=%d, want status=%d", got, rec.Code, tc.code)
			}
		})
	}
}

func TestTunnelRouteIDSurvivesNodeSwap(t *testing.T) {
	tunnel := &Tunnel{Slot: 1, RouteID: "exit-abc123", Node: Node{HostName: "old.example"}}
	before := tunnelTag(tunnel)
	tunnel.setNode(Node{HostName: "new.example"})
	if got := tunnelTag(tunnel); got != before {
		t.Fatalf("route tag changed after node swap: before=%q after=%q", before, got)
	}
}

func TestStoppedTunnelStatusIsTerminal(t *testing.T) {
	tunnel := &Tunnel{Status: "up"}
	tunnel.stop()
	tunnel.setStatus("up", "")
	tunnel.setExitIP("198.51.100.1")
	state := tunnel.snapshot()
	if state.Status != "stopped" || state.ExitIP != "" {
		t.Fatalf("stopped tunnel was resurrected: %+v", state)
	}
}

func TestStopWaitsForInFlightTunnelStart(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "checking")
	bin := filepath.Join(dir, "fake-sing-box")
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"check\" ]; then\n  touch %q\n  sleep 1\n  exit 0\nfi\nif [ \"$1\" = \"run\" ]; then\n  exec sleep 30\nfi\nexit 1\n", marker)
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	tunnel := &Tunnel{
		Slot: 1, Port: 24568, Status: "starting", portMayChange: true,
		Node: Node{Config: testVPNGateProfile}, Cred: SocksCred{User: "user", Pass: "password"},
	}
	started := make(chan error, 1)
	go func() { started <- tunnel.startSingBox(bin, dir) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("假 sing-box 未进入配置校验")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tunnel.stop()
	if err := <-started; err != nil {
		t.Fatalf("启动不应因并发 Stop 返回错误: %v", err)
	}
	if tunnel.snapshot().Status != "stopped" {
		t.Fatal("Stop 后隧道状态不是 stopped")
	}
	if tunnel.proc == nil || !tunnel.proc.exited() {
		t.Fatal("Stop 后启动中的 sing-box 子进程仍在运行")
	}
}

func TestSaveStateSerializesConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	manager := &Manager{
		workDir: dir,
		tunnels: map[int]*Tunnel{1: {
			Slot: 1, RouteID: "exit-one", Port: 20001, Status: "up",
			Node: Node{HostName: "jp1", Config: "profile"}, Cred: SocksCred{User: "user", Pass: "password"},
		}},
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.saveState(); err != nil {
				t.Errorf("saveState: %v", err)
			}
		}()
	}
	wg.Wait()
	blob, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(blob, &state); err != nil {
		t.Fatalf("并发保存后的状态文件不可解析: %v", err)
	}
	if len(state.Tunnels) != 1 || state.Tunnels[0].RouteID != "exit-one" {
		t.Fatalf("并发保存后的状态错误: %+v", state)
	}
}

func TestSaveStatePersistsPendingPortFlag(t *testing.T) {
	dir := t.TempDir()
	manager := &Manager{
		workDir: dir,
		tunnels: map[int]*Tunnel{1: {
			Slot: 1, RouteID: "exit-one", Port: 20001, Status: "starting", portMayChange: true,
			Node: Node{HostName: "jp1", Config: "profile"}, Cred: SocksCred{User: "user", Pass: "password"},
		}},
	}
	if err := manager.saveState(); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(blob, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Tunnels) != 1 || !state.Tunnels[0].PortPending {
		t.Fatalf("pending public port should not be fixed: %+v", state)
	}
}

func TestParallelHealthCheckUsesBoundedConcurrency(t *testing.T) {
	tunnels := make([]*Tunnel, 6)
	for i := range tunnels {
		tunnels[i] = &Tunnel{Slot: i + 1, RouteID: "exit-test", Status: "up"}
	}
	var active, peak atomic.Int32
	results := parallelHealthCheck(tunnels, 3, func(*Tunnel) bool {
		current := active.Add(1)
		for {
			seen := peak.Load()
			if current <= seen || peak.CompareAndSwap(seen, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		return true
	})
	if len(results) != len(tunnels) {
		t.Fatalf("health results = %d, want %d", len(results), len(tunnels))
	}
	if got := peak.Load(); got < 2 || got > 3 {
		t.Fatalf("parallelism = %d, want 2..3", got)
	}
}

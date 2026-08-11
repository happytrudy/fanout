package main

import (
	"net/http"
	"net/http/httptest"
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

package main

import (
	"os"
	"testing"
	"time"
)

func TestLiveVPNGateExit(t *testing.T) {
	if os.Getenv("FANOUT_LIVE_TEST") != "1" {
		t.Skip("FANOUT_LIVE_TEST 未启用")
	}
	nodes, err := fetchNodes(60 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configurePanel(dir)
	defer closePanel()
	m := NewManager(1, dir)
	// Start must see the fetched list as well as the initial node so the live
	// test exercises the normal same-region fallback path. VPN Gate's first
	// listed node is frequently unavailable.
	m.nodes = nodes
	m.fetched = time.Now()
	tunnel, err := m.Start(nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	m.waitUp(tunnel)
	state := tunnel.snapshot()
	if state.Status != "up" {
		t.Fatalf("VPN Gate 出口未连通: %s", state.Err)
	}
	if state.ExitIP == "" {
		t.Fatal("出口 IP 为空")
	}
}

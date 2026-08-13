package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// 状态会同时被健康检查、Web API、持久化和后台重连读取，必须统一走快照。
func TestTunnelSnapshotConcurrent(t *testing.T) {
	tunnel := &Tunnel{
		Slot:   1,
		Port:   20001,
		Node:   Node{HostName: "jp1.example", CountryCode: "JP"},
		Status: "up",
		ExitIP: "198.51.100.1",
	}

	const iterations = 1000
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tunnel.setNode(Node{HostName: fmt.Sprintf("jp%d.example", i), CountryCode: "JP"})
			tunnel.setStatus("starting", fmt.Sprintf("retry-%d", i))
			tunnel.setExitIP(fmt.Sprintf("198.51.100.%d", i%255))
		}
	}()
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				state := tunnel.snapshot()
				_ = state.Node.HostName
				_ = tunnelTag(tunnel)
				_ = exitLabel(tunnel)
			}
		}()
	}
	wg.Wait()
}

func TestRestoreStateDoesNotPublishPartialState(t *testing.T) {
	dir := t.TempDir()
	state := persistedState{Tunnels: []persistedTunnel{
		{Slot: 1, RouteID: "exit-one", Port: 21001, HostName: "one", SocksUser: "userone", SocksPass: "passone"},
		{Slot: 2, RouteID: "exit-two", Port: 70000, HostName: "two", SocksUser: "usertwo", SocksPass: "passtwo"},
	}}
	blob, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), blob, 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(2, dir)
	if _, err := m.restoreState(); err == nil {
		t.Fatal("后续状态记录非法时恢复应失败")
	}
	if got := len(m.Tunnels()); got != 0 {
		t.Fatalf("恢复失败不应留下部分隧道，got %d", got)
	}
}

func TestReconnectRejectsConcurrentAttempt(t *testing.T) {
	tunnel := &Tunnel{Status: "up"}
	if !tunnel.reconnectMu.TryLock() {
		t.Fatal("测试前无法取得重连锁")
	}
	defer tunnel.reconnectMu.Unlock()

	if (&Manager{}).reconnect(tunnel, "jp1.example", nil) {
		t.Fatal("已有重连在进行时，不应启动第二个重连任务")
	}
}

func TestManagerStopPreservesExitAndDeleteReleasesIt(t *testing.T) {
	dir := t.TempDir()
	configurePanel(dir)
	defer closePanel()
	tunnel := &Tunnel{
		Slot: 1, RouteID: "exit-one", Port: 24570, Status: "up",
		Node: Node{HostName: "jp1", CountryCode: "JP", Config: "profile"},
		Cred: SocksCred{User: "user", Pass: "password"},
	}
	m := NewManager(2, dir)
	m.tunnels[1] = tunnel
	if err := m.Stop(1); err != nil {
		t.Fatal(err)
	}
	if len(m.Tunnels()) != 1 || m.Tunnels()[0].snapshot().Status != "stopped" {
		t.Fatalf("停止后出口应保留: %+v", m.Tunnels())
	}
	blob, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(blob, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Tunnels) != 1 || state.Tunnels[0].Status != "stopped" {
		t.Fatalf("停止状态未持久化: %+v", state)
	}
	if err := m.Delete(1); err != nil {
		t.Fatal(err)
	}
	if len(m.Tunnels()) != 0 {
		t.Fatal("永久删除后出口仍占用槽位")
	}
}

package main

import (
	"fmt"
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

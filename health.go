package main

import (
	"log"
	"sync"
	"time"
)

const (
	healthInterval = 10 * time.Second
	healthFailures = 2 // 连续失败几次才判定掉线，避免网络抖动误杀
	healthTimeout  = 6 * time.Second
	// VPN Gate 列表最多同时管理 20 条隧道。限制并发避免所有 endpoint
	// 同时向 ipify 发起请求，同时让一轮健康检查不会被串行超时拖垮。
	healthCheckWorkers = 8
)

type healthResult struct {
	tunnel  *Tunnel
	state   tunnelSnapshot
	healthy bool
}

// WatchHealth 周期检查每条隧道是否还能出网，掉线的自动换节点重连。
// VPN Gate 是志愿者节点，运行中掉线很常见。
func (m *Manager) WatchHealth() {
	fails := map[int]int{}

	for range time.Tick(healthInterval) {
		for _, result := range parallelHealthCheck(m.Tunnels(), healthCheckWorkers, m.tunnelHealthy) {
			state := result.state
			// 手动换节点或停止可能恰好发生在探测期间；旧结果不能驱动新状态重连。
			current := result.tunnel.snapshot()
			if current.Status != "up" || current.RouteID != state.RouteID || current.ExitIP != state.ExitIP {
				continue
			}
			if result.healthy {
				fails[state.Slot] = 0
				continue
			}

			fails[state.Slot]++
			if fails[state.Slot] < healthFailures {
				log.Printf("隧道 %d (%s) 探测失败 %d 次", state.Slot, state.Node.HostName, fails[state.Slot])
				continue
			}

			log.Printf("隧道 %d (%s) 已掉线，正在换节点重连", state.Slot, state.Node.HostName)
			fails[state.Slot] = 0
			m.reconnect(result.tunnel, state.Node.HostName, nil)
		}
	}
}

func parallelHealthCheck(tunnels []*Tunnel, workers int, healthy func(*Tunnel) bool) []healthResult {
	jobs := make(chan healthResult)
	results := make(chan healthResult, len(tunnels))
	if workers < 1 {
		workers = 1
	}
	if workers > len(tunnels) {
		workers = len(tunnels)
	}
	if workers == 0 {
		return nil
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				job.healthy = healthy(job.tunnel)
				results <- job
			}
		}()
	}
	go func() {
		for _, tunnel := range tunnels {
			state := tunnel.snapshot()
			if state.Status == "up" {
				jobs <- healthResult{tunnel: tunnel, state: state}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]healthResult, 0, len(tunnels))
	for result := range results {
		out = append(out, result)
	}
	return out
}

// tunnelHealthy 判断隧道是否还真的走在 VPN 上。
//
// 比对出口 IP 可以同时发现 endpoint 已断线和服务端出口发生变化。
func (m *Manager) tunnelHealthy(t *Tunnel) bool {
	got, err := t.probeExitIP(healthTimeout)
	if err != nil {
		return false
	}
	return got == t.snapshot().ExitIP
}

// reconnect 就地把一条隧道换到别的节点上，保持槽位与端口不变，
// 这样已经分发出去的客户端配置仍然可用。
//
// oldHost 必须是本次重连前那条隧道真正绑着的节点名。调用方若已经
// 改过 t.Node（比如手动换节点），就要把改之前的名字传进来，
// 否则 rebind 找不到旧绑定，入站会掉成孤儿。
func (m *Manager) reconnect(t *Tunnel, oldHost string, replacement *Node) bool {
	if !t.reconnectMu.TryLock() {
		return false
	}
	t.stateMu.Lock()
	if t.Status == "stopped" {
		t.stateMu.Unlock()
		t.reconnectMu.Unlock()
		return false
	}
	if replacement != nil {
		t.Node = *replacement
	}
	t.Status, t.Err, t.ExitIP = "starting", "正在换节点重连", ""
	t.stateMu.Unlock()

	t.stopEngine()

	go func() {
		defer t.reconnectMu.Unlock()
		// 通知延后到 rebind/resync 之后：那两步会把入站改绑到新节点，
		// 提前重建配置会因为入站还指着旧节点名而丢掉路由规则
		m.bringUpPersist(t, false, true)
		state := t.snapshot()
		if state.Status != "up" {
			return
		}
		m.syncAfterReconnect(t, oldHost)
	}()
	return true
}

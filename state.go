package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// persistedTunnel 是隧道在磁盘上的形态。
// 只存重建所需的信息，运行态（进程、监听）重启后重新建立。
type persistedTunnel struct {
	Slot        int    `json:"slot"`
	RouteID     string `json:"route_id,omitempty"`
	Port        int    `json:"port"`
	HostName    string `json:"hostname"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Config      string `json:"config"`
	// SOCKS5 凭据要存盘：用户已经把它分发给客户端了，重启后变掉等于全断
	SocksUser string `json:"socks_user,omitempty"`
	SocksPass string `json:"socks_pass,omitempty"`
}

type persistedState struct {
	Tunnels []persistedTunnel `json:"tunnels"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

// saveState 把当前隧道写入磁盘，供重启后恢复。
func (m *Manager) saveState() error {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	var st persistedState
	for _, t := range m.Tunnels() {
		state := t.snapshot()
		// 只跳过用户主动停掉的。starting/failed 的隧道也要存：
		// 它们正在重连或等着重试，漏存会让重启后凭空少几个出口。
		if state.Status == "stopped" {
			continue
		}
		cred := t.credential()
		st.Tunnels = append(st.Tunnels, persistedTunnel{
			Slot:        state.Slot,
			RouteID:     state.RouteID,
			Port:        state.Port,
			HostName:    state.Node.HostName,
			CountryCode: state.Node.CountryCode,
			Country:     state.Node.Country,
			Config:      state.Node.Config,
			SocksUser:   cred.User,
			SocksPass:   cred.Pass,
		})
	}

	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := statePath(m.workDir)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// restoreState 读回上次的隧道并逐条拉起。
// 节点配置一并存了盘，所以即使 VPN Gate 列表里该节点已消失也能重建。
func (m *Manager) restoreState() (int, error) {
	blob, err := os.ReadFile(statePath(m.workDir))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	var st persistedState
	if err := json.Unmarshal(blob, &st); err != nil {
		return 0, fmt.Errorf("解析状态文件失败: %w", err)
	}

	// 从当前节点列表补回地区、延迟等元数据；节点已下线时退回存盘的最小信息
	known := map[string]Node{}
	for _, n := range m.nodes {
		known[n.HostName] = n
	}

	restored := make([]*Tunnel, 0, len(st.Tunnels))
	seenSlots := make(map[int]bool, len(st.Tunnels))
	seenPorts := make(map[int]bool, len(st.Tunnels))
	seenRouteIDs := make(map[string]bool, len(st.Tunnels))
	for _, p := range st.Tunnels {
		if p.Slot < 1 || p.Slot > m.maxSlots {
			return 0, fmt.Errorf("状态文件中的槽位 %d 不在 1-%d 范围内", p.Slot, m.maxSlots)
		}
		if seenSlots[p.Slot] {
			return 0, fmt.Errorf("状态文件中槽位 %d 重复", p.Slot)
		}
		if err := validatePort(p.Port); err != nil {
			return 0, fmt.Errorf("状态文件中槽位 %d 的 SOCKS5 端口无效: %w", p.Slot, err)
		}
		if seenPorts[p.Port] {
			return 0, fmt.Errorf("状态文件中 SOCKS5 端口 %d 重复", p.Port)
		}
		node, ok := known[p.HostName]
		if !ok {
			// 节点已从 VPN Gate 列表消失，用存盘的信息重建
			node = Node{
				HostName:    p.HostName,
				CountryCode: p.CountryCode,
				Country:     p.Country,
			}
		}
		node.Config = p.Config
		// 从旧版本升上来的状态文件没有凭据字段，补一套新的
		cred := SocksCred{User: p.SocksUser, Pass: p.SocksPass}
		if cred.User == "" || cred.Pass == "" {
			gen, err := newSocksCred()
			if err != nil {
				return 0, fmt.Errorf("生成 SOCKS5 凭据失败: %w", err)
			}
			cred = gen
		}
		routeID := p.RouteID
		if routeID == "" {
			token, err := randomToken(6)
			if err != nil {
				return 0, fmt.Errorf("生成出口路由标识失败: %w", err)
			}
			routeID = "exit-" + token
		}
		if seenRouteIDs[routeID] {
			return 0, fmt.Errorf("状态文件中出口路由标识 %q 重复", routeID)
		}
		if err := validateCred(cred); err != nil {
			return 0, fmt.Errorf("状态文件中槽位 %d 的 SOCKS5 凭据无效: %w", p.Slot, err)
		}
		t := &Tunnel{
			Slot:          p.Slot,
			RouteID:       routeID,
			Port:          p.Port,
			Node:          node,
			Status:        "starting",
			Cred:          cred,
			portMayChange: false,
		}
		m.mu.Lock()
		m.tunnels[p.Slot] = t
		m.mu.Unlock()
		seenSlots[p.Slot] = true
		seenPorts[p.Port] = true
		seenRouteIDs[routeID] = true
		restored = append(restored, t)
	}
	// Legacy state files receive Route IDs during restore. Persist them before
	// dialing so a crash during the first reconnect cannot orphan migrated binds.
	if err := m.saveState(); err != nil {
		return 0, fmt.Errorf("保存恢复后的状态失败: %w", err)
	}
	for _, t := range restored {
		go m.bringUpPersist(t, true, true)
	}
	return len(st.Tunnels), nil
}

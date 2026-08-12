package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SocksCred is the public credential assigned to one exit.
type SocksCred struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// Tunnel is one VPN Gate exit. Its userspace OpenVPN endpoint and authenticated
// public SOCKS listener are dynamically owned by the shared embedded sing-box.
type Tunnel struct {
	Slot    int       `json:"slot"`
	RouteID string    `json:"-"`
	Port    int       `json:"port"`
	Node    Node      `json:"node"`
	Status  string    `json:"status"` // starting | up | failed | stopped
	ExitIP  string    `json:"exit_ip"`
	Err     string    `json:"err,omitempty"`
	Since   time.Time `json:"since"`
	Cred    SocksCred `json:"cred"`

	endpointPort  int
	proc          *singBoxProc
	engine        *embeddedEngine
	mu            sync.Mutex
	stateMu       sync.RWMutex
	lifecycleMu   sync.Mutex
	adminMu       sync.Mutex
	reconnectMu   sync.Mutex
	portMayChange bool
}

// embeddedEngine is assigned by Manager so tunnel health probes and lifecycle
// operations address the shared Box directly.
func (t *Tunnel) setEngine(engine *embeddedEngine) {
	t.mu.Lock()
	t.engine = engine
	t.mu.Unlock()
}

type tunnelSnapshot struct {
	Slot    int       `json:"slot"`
	RouteID string    `json:"-"`
	Port    int       `json:"port"`
	Node    Node      `json:"node"`
	Status  string    `json:"status"`
	ExitIP  string    `json:"exit_ip"`
	Err     string    `json:"err,omitempty"`
	Since   time.Time `json:"since"`
}

func (t *Tunnel) snapshot() tunnelSnapshot {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return tunnelSnapshot{Slot: t.Slot, RouteID: t.RouteID, Port: t.Port, Node: t.Node, Status: t.Status, ExitIP: t.ExitIP, Err: t.Err, Since: t.Since}
}

func (t *Tunnel) setStatus(status, errText string) {
	t.stateMu.Lock()
	if t.Status == "stopped" && status != "stopped" {
		t.stateMu.Unlock()
		return
	}
	t.Status, t.Err = status, errText
	t.stateMu.Unlock()
}

func (t *Tunnel) setNode(node Node) {
	t.stateMu.Lock()
	t.Node = node
	t.stateMu.Unlock()
}

func (t *Tunnel) setExitIP(ip string) {
	t.stateMu.Lock()
	if t.Status == "stopped" {
		t.stateMu.Unlock()
		return
	}
	t.ExitIP = ip
	t.stateMu.Unlock()
}

func (t *Tunnel) setPublicPort(port int) {
	t.stateMu.Lock()
	t.Port = port
	t.stateMu.Unlock()
}

func (t *Tunnel) publicPortMayChange() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.portMayChange
}

func (t *Tunnel) processName() string { return fmt.Sprintf("tunnel-%d", t.Slot) }

func freeLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func (t *Tunnel) startSingBox(bin, workDir string) error {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	return t.startSingBoxLocked(bin, workDir)
}

// startSingBoxLocked starts this tunnel while the lifecycle lock is held.
func (t *Tunnel) startSingBoxLocked(bin, workDir string) error {
	if t.snapshot().Status == "stopped" {
		return fmt.Errorf("隧道已停止")
	}
	t.mu.Lock()
	engine := t.engine
	t.mu.Unlock()
	if engine != nil {
		for attempts := 0; attempts < 3; attempts++ {
			state := t.snapshot()
			if !portAvailable(state.Port, "tcp") {
				if !t.publicPortMayChange() {
					return fmt.Errorf("公网 SOCKS5 端口 %d 已被占用", state.Port)
				}
				next, err := freeRandomPort(map[int]bool{state.Port: true})
				if err != nil {
					return fmt.Errorf("公网 SOCKS5 端口 %d 已被占用且无法分配备用端口: %w", state.Port, err)
				}
				t.setPublicPort(next)
				continue
			}
			if err := engine.addTunnel(t); err != nil {
				return err
			}
			t.mu.Lock()
			t.portMayChange = false
			t.mu.Unlock()
			return nil
		}
		return fmt.Errorf("无法分配可用的公网 SOCKS5 端口")
	}
	t.mu.Lock()
	if t.endpointPort == 0 {
		port, err := freeLoopbackPort()
		if err != nil {
			t.mu.Unlock()
			return fmt.Errorf("分配内部 SOCKS5 端口失败: %w", err)
		}
		t.endpointPort = port
	}
	port := t.endpointPort
	if t.proc == nil {
		dir := filepath.Join(workDir, "sing-box")
		t.proc = &singBoxProc{bin: bin, dir: dir, name: t.processName()}
		t.proc.reapOrphan()
	}
	proc := t.proc
	t.mu.Unlock()

	for attempts := 0; attempts < 3; attempts++ {
		state := t.snapshot()
		if state.Status == "stopped" {
			return fmt.Errorf("隧道已停止")
		}
		// A freshly allocated public port may be claimed between allocation and
		// the child start. Reassign only before the first successful start; a
		// reconnect must preserve the client-facing port already distributed.
		if proc.exited() && !portAvailable(state.Port, "tcp") {
			t.mu.Lock()
			mayChange := t.portMayChange
			t.mu.Unlock()
			if !mayChange {
				return fmt.Errorf("公网 SOCKS5 端口 %d 已被占用", state.Port)
			}
			next, err := freeRandomPort(map[int]bool{state.Port: true})
			if err != nil {
				return fmt.Errorf("公网 SOCKS5 端口 %d 已被占用且无法分配备用端口: %w", state.Port, err)
			}
			t.setPublicPort(next)
			continue
		}

		cfg, err := buildTunnelSingBoxConfig(state.Node.Config, port, state.Port, t.credential())
		if err != nil {
			return fmt.Errorf("转换 VPN Gate 配置失败: %w", err)
		}
		cfgPath, err := writeSingBoxConfig(proc.dir, proc.name, cfg)
		if err != nil {
			return fmt.Errorf("写 sing-box 隧道配置失败: %w", err)
		}
		if err := verifySingBoxConfig(bin, cfgPath); err != nil {
			return err
		}
		if err := proc.start(cfgPath); err != nil {
			t.mu.Lock()
			mayChange := t.portMayChange
			t.mu.Unlock()
			if mayChange && singBoxListenConflict(proc) {
				next, portErr := freeRandomPort(map[int]bool{state.Port: true})
				if portErr != nil {
					return fmt.Errorf("公网 SOCKS5 端口 %d 被抢占且无法分配备用端口: %w", state.Port, portErr)
				}
				t.setPublicPort(next)
				continue
			}
			return err
		}
		t.mu.Lock()
		t.portMayChange = false
		t.mu.Unlock()
		return nil
	}
	return fmt.Errorf("无法分配可用的公网 SOCKS5 端口")
}

func (t *Tunnel) stopEngine() {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	t.stopEngineLocked()
}

func (t *Tunnel) stopEngineLocked() {
	t.mu.Lock()
	engine := t.engine
	proc := t.proc
	t.mu.Unlock()
	if engine != nil {
		engine.removeTunnel(t)
		return
	}
	if proc != nil {
		proc.stop()
	}
}

func (t *Tunnel) internalProxyAddr() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.engine != nil {
		return "", fmt.Errorf("嵌入式 OpenVPN endpoint 不使用 loopback SOCKS5")
	}
	if t.endpointPort == 0 || t.proc == nil || t.proc.exited() {
		return "", fmt.Errorf("OpenVPN endpoint 未运行")
	}
	return fmt.Sprintf("127.0.0.1:%d", t.endpointPort), nil
}

func (t *Tunnel) internalProxyPort() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.endpointPort
}

func (t *Tunnel) dial(network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("只支持 TCP")
	}
	t.mu.Lock()
	engine := t.engine
	t.mu.Unlock()
	if engine != nil {
		return engine.dialTunnel(context.Background(), t, network, addr)
	}
	proxyAddr, err := t.internalProxyAddr()
	if err != nil {
		return nil, err
	}
	return dialSOCKS5(proxyAddr, addr, 20*time.Second)
}

func (t *Tunnel) credential() SocksCred {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.Cred
}

func (t *Tunnel) setCredential(c SocksCred) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Cred = c
}

// restartWithCredential recreates only this exit's public SOCKS listener. The
// OpenVPN endpoint and all other listeners stay running. Restore the old
// configuration if the replacement cannot start.
func (t *Tunnel) restartWithCredential(bin, workDir string, next SocksCred) error {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	if t.snapshot().Status == "stopped" {
		return fmt.Errorf("隧道已停止")
	}
	previous := t.credential()
	t.setCredential(next)
	t.mu.Lock()
	engine := t.engine
	t.mu.Unlock()
	if engine != nil {
		if err := engine.updateTunnelCredential(t); err == nil {
			return nil
		} else {
			t.setCredential(previous)
			if rollbackErr := engine.updateTunnelCredential(t); rollbackErr != nil {
				return fmt.Errorf("更新公网 SOCKS5 凭据失败: %w；恢复旧凭据也失败: %v", err, rollbackErr)
			}
			return fmt.Errorf("更新公网 SOCKS5 凭据失败: %w", err)
		}
	}
	if err := t.startSingBoxLocked(bin, workDir); err == nil {
		return nil
	} else {
		t.setCredential(previous)
		if rollbackErr := t.startSingBoxLocked(bin, workDir); rollbackErr != nil {
			return fmt.Errorf("重启出口以应用 SOCKS5 凭据失败: %w；恢复旧配置也失败: %v", err, rollbackErr)
		}
		return fmt.Errorf("重启出口以应用 SOCKS5 凭据失败: %w", err)
	}
}

func (t *Tunnel) probeExitIP(timeout time.Duration) (string, error) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return t.dial(network, addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	resp, err := client.Get("http://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("查询出口 IP 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("查询出口 IP 返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", fmt.Errorf("读取出口 IP 失败: %w", err)
	}
	ip := strings.TrimSpace(string(body))
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("出口 IP 返回异常: %q", ip)
	}
	return ip, nil
}

func (t *Tunnel) waitExitIP(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if ip, err := t.probeExitIP(6 * time.Second); err == nil {
			return ip, nil
		} else {
			lastErr = err
		}
		t.mu.Lock()
		engine, proc := t.engine, t.proc
		t.mu.Unlock()
		if engine == nil {
			if proc == nil {
				return "", fmt.Errorf("sing-box 隧道进程未启动")
			}
			if proc.exited() {
				return "", fmt.Errorf("sing-box 隧道进程已退出，详见 %s", filepath.Join(proc.dir, proc.name+".log"))
			}
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("等待 OpenVPN endpoint 就绪超时: %w", lastErr)
}

func (t *Tunnel) stop() {
	t.adminMu.Lock()
	defer t.adminMu.Unlock()
	t.stopLocked()
}

func (t *Tunnel) stopLocked() {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	t.setStatus("stopped", "")
	t.stopEngineLocked()
}

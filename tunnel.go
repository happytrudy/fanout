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

// Tunnel is one VPN Gate exit. Each tunnel owns an isolated sing-box process
// with a userspace OpenVPN endpoint, an authenticated public SOCKS listener,
// and a loopback-only SOCKS listener for the gateway process.
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

	endpointPort int
	proc         *singBoxProc
	mu           sync.Mutex
	stateMu      sync.RWMutex
	reconnectMu  sync.Mutex
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
	t.ExitIP = ip
	t.stateMu.Unlock()
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

	state := t.snapshot()
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
	return proc.start(cfgPath)
}

func (t *Tunnel) stopEngine() {
	t.mu.Lock()
	proc := t.proc
	t.mu.Unlock()
	if proc != nil {
		proc.stop()
	}
}

func (t *Tunnel) internalProxyAddr() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
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

// restartWithCredential restarts only this tunnel's sing-box process. The
// gateway uses the separate unauthenticated loopback listener, so its process
// and all other exits remain untouched. Restore the old configuration if the
// replacement cannot start.
func (t *Tunnel) restartWithCredential(bin, workDir string, next SocksCred) error {
	previous := t.credential()
	t.setCredential(next)
	if err := t.startSingBox(bin, workDir); err == nil {
		return nil
	} else {
		t.setCredential(previous)
		if rollbackErr := t.startSingBox(bin, workDir); rollbackErr != nil {
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
		proc := t.proc
		t.mu.Unlock()
		if proc == nil {
			return "", fmt.Errorf("sing-box 隧道进程未启动")
		}
		if proc.exited() {
			return "", fmt.Errorf("sing-box 隧道进程已退出，详见 %s", filepath.Join(proc.dir, proc.name+".log"))
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("等待 OpenVPN endpoint 就绪超时: %w", lastErr)
}

func (t *Tunnel) stop() {
	t.setStatus("stopped", "")
	t.stopEngine()
}

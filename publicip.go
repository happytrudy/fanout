package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// publicIPSources 是几个只回一行纯 IPv4 的接口，任意一个先返回就用它。
var publicIPSources = []string{
	"https://api.ipify.org",
	"https://ipv4.icanhazip.com",
	"https://ifconfig.me/ip",
}

var (
	publicIPMu       sync.Mutex
	publicIPOverride string    // 由 -ip / FANOUT_PUBLIC_IP 显式指定，优先级最高
	publicIPCache    string    // 上一次探测成功的结果
	publicIPAt       time.Time // 上次探测时间，用于 TTL
	publicIPFailedAt time.Time
	publicIPProbing  bool
)

const (
	publicIPTTL        = 30 * time.Minute
	publicIPFailureTTL = time.Minute
)

// setPublicIPOverride 记录用户显式指定的母机公网地址，空值表示不覆盖。
func setPublicIPOverride(ip string) {
	publicIPMu.Lock()
	publicIPOverride = strings.TrimSpace(ip)
	publicIPMu.Unlock()
}

// hostPublicIP 返回跑 fanout 这台母机的公网 IPv4。
// 优先用显式覆盖值；否则用缓存（未过期）。缓存失效时后台刷新，避免
// 出口列表请求被外部探测卡住；失败也会短暂缓存，防止页面轮询重复探测。
func hostPublicIP() string {
	publicIPMu.Lock()
	if publicIPOverride != "" {
		ip := publicIPOverride
		publicIPMu.Unlock()
		return ip
	}
	if publicIPCache != "" && time.Since(publicIPAt) < publicIPTTL {
		ip := publicIPCache
		publicIPMu.Unlock()
		return ip
	}
	if publicIPProbing || time.Since(publicIPFailedAt) < publicIPFailureTTL {
		ip := publicIPCache
		publicIPMu.Unlock()
		return ip
	}
	publicIPProbing = true
	publicIPMu.Unlock()

	go refreshPublicIP()
	return ""
}

func refreshPublicIP() {
	ip := probePublicIP()
	publicIPMu.Lock()
	defer publicIPMu.Unlock()
	publicIPProbing = false
	if ip == "" {
		publicIPFailedAt = time.Now()
		return
	}
	publicIPCache = ip
	publicIPAt = time.Now()
	publicIPFailedAt = time.Time{}
}

// probePublicIP 逐个问外部接口，拿到第一个合法的 IPv4 就返回。
func probePublicIP() string {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, url := range publicIPSources {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if readErr != nil {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return ip
		}
	}
	return ""
}

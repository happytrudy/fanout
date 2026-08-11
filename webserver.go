package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// webServer 管理 HTTP 监听，支持在运行时切换端口/监听地址而不重启进程。
// 切换端口或监听地址会新起一个 net.Listener，旧的优雅关闭。
type webServer struct {
	handler http.Handler

	mu   sync.Mutex
	ln   net.Listener
	srv  *http.Server
	addr string
}

func newWebServer(h http.Handler) *webServer {
	return &webServer{handler: h}
}

// serve 用当前 WebSettings 起第一个监听并阻塞。返回时说明监听彻底退出。
func (s *webServer) serve() error {
	cfg := getWebSettings()
	if err := s.reload(cfg); err != nil {
		return err
	}
	// 主 goroutine 就地阻塞，等监听被 reload 或退出替换。
	// 这里靠一个永不返回的 select 挂住：真正的 Serve 在 reload 里各自的 goroutine 跑。
	select {}
}

// reload 切换到新的监听地址：先探测能否绑上，绑得上再关旧的、启新的。
// 绑不上就保持旧监听不动，返回错误让调用方回报给用户。
func (s *webServer) reload(cfg WebSettings) error {
	addr := cfg.listenAddrString()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("无法监听 %s：%w", addr, err)
	}

	s.mu.Lock()
	oldSrv := s.srv
	oldLn := s.ln
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      150 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	s.srv = srv
	s.ln = ln
	s.addr = addr
	s.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP 监听 %s 退出: %v", addr, err)
		}
	}()

	// 关掉旧监听。给正在处理的请求一点收尾时间，
	// 尤其是触发这次 reload 的那个请求本身要先把响应写完。
	if oldSrv != nil {
		go func() {
			time.Sleep(1 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = oldSrv.Shutdown(ctx)
			_ = oldLn.Close()
		}()
	}

	log.Printf("管理界面监听已切换到 %s", addr)
	return nil
}

// applyWebSettings 校验、落盘并切换监听。持久化失败时不会改变线上监听；
// 新监听无法启动时会恢复原有设置文件。
func (s *webServer) applyWebSettings(next WebSettings) error {
	cur := getWebSettings()
	// Callers that only change the Web listener may omit the unrelated inbound
	// range; retain the loaded settings instead of treating zero values as a
	// request for an invalid range.
	if next.InboundPortMin == 0 && next.InboundPortMax == 0 {
		next.InboundPortMin, next.InboundPortMax = cur.InboundPortMin, cur.InboundPortMax
	}
	if err := validatePort(next.Port); err != nil {
		return err
	}
	norm, err := normalizeListenAddr(next.ListenAddr)
	if err != nil {
		return err
	}
	next.ListenAddr = norm
	if err := validatePortRange(next.InboundPortMin, next.InboundPortMax); err != nil {
		return err
	}

	if next == cur {
		return nil
	}

	webSettingsMu.Lock()
	webSettingsCur = next
	webSettingsMu.Unlock()
	if err := saveWebSettings(); err != nil {
		webSettingsMu.Lock()
		webSettingsCur = cur
		webSettingsMu.Unlock()
		return err
	}
	if next.Port == cur.Port && next.ListenAddr == cur.ListenAddr {
		return nil
	}
	if err := s.reload(next); err != nil {
		webSettingsMu.Lock()
		webSettingsCur = cur
		webSettingsMu.Unlock()
		if restoreErr := saveWebSettings(); restoreErr != nil {
			return fmt.Errorf("应用监听设置失败: %w；恢复设置文件失败: %v", err, restoreErr)
		}
		return err
	}
	return nil
}

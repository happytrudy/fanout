package main

import (
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newNativeForEmbeddedTest(t *testing.T, store *nativeStore) *Native {
	t.Helper()
	engine, err := newEmbeddedEngine()
	if err != nil {
		t.Fatal(err)
	}
	native := &Native{
		dir:            t.TempDir(),
		listenAddr:     "127.0.0.1",
		inboundPortMin: inboundPortMinDefault,
		inboundPortMax: inboundPortMaxDefault,
		store:          store,
		engine:         engine,
		configHash:     make(map[int][sha256.Size]byte),
		runtimeError:   make(map[int]string),
	}
	t.Cleanup(native.Close)
	return native
}

func TestNativeInboundTagStable(t *testing.T) {
	cases := []struct {
		ib   nativeInbound
		want string
	}{
		{nativeInbound{Port: 443, Network: "tcp"}, "in-443-tcp"},
		{nativeInbound{Port: 8080, Network: "ws"}, "in-8080-ws"},
		{nativeInbound{Port: 1234}, "in-1234-tcp"}, // 缺省按 tcp
	}
	for _, c := range cases {
		if got := c.ib.tag(); got != c.want {
			t.Errorf("tag() = %q, want %q", got, c.want)
		}
	}
}

func TestBuildSingBoxConfigBindsOnlyLiveTunnels(t *testing.T) {
	up := &Tunnel{Port: 1080, Status: "up", Node: Node{HostName: "jp1"}}
	down := &Tunnel{Port: 1081, Status: "failed", Node: Node{HostName: "jp2"}}
	inbounds := []*nativeInbound{
		{ID: 1, Port: 100, Protocol: "vless", Enable: true, BoundTo: "jp1"},
		{ID: 2, Port: 200, Protocol: "vless", Enable: true, BoundTo: "jp2"},
		{ID: 3, Port: 300, Protocol: "vless", Enable: true},
	}

	cfg := buildSingBoxGatewayConfig(inbounds, []*Tunnel{up, down})

	outs := map[string]bool{}
	for _, o := range cfg["outbounds"].([]any) {
		outs[o.(map[string]any)["tag"].(string)] = true
	}
	if !outs["fanout-jp1"] {
		t.Error("已连通的隧道应当有对应出站")
	}
	if outs["fanout-jp2"] {
		t.Error("未连通的隧道不该生成出站")
	}

	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 4 {
		t.Fatalf("应有 resolve、IPv6 直连、隧道路由和离线出口阻断，实际 %d 条", len(rules))
	}
	if resolve := rules[0].(map[string]any); resolve["action"] != "resolve" || resolve["strategy"] != "prefer_ipv4" {
		t.Errorf("缺少双栈域名优先 IPv4 的解析规则: %#v", resolve)
	}
	if ipv6 := rules[1].(map[string]any); ipv6["ip_version"] != 6 || ipv6["outbound"] != "direct" {
		t.Errorf("缺少 IPv6 目标直连规则: %#v", ipv6)
	}
	if got := rules[2].(map[string]any)["outbound"]; got != "fanout-jp1" {
		t.Errorf("outbound = %v, want fanout-jp1", got)
	}
	if got := rules[3].(map[string]any)["outbound"]; got != "block" {
		t.Errorf("离线绑定出口应阻断 IPv4，outbound = %v", got)
	}
}

func TestBuildSingBoxConfigBlocksOfflineBoundInbound(t *testing.T) {
	inbound := &nativeInbound{ID: 1, Port: 100, Protocol: "vless", Enable: true, BoundTo: "exit-missing"}
	cfg := buildSingBoxGatewayConfig([]*nativeInbound{inbound}, nil)
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(rules))
	}
	rule := rules[2].(map[string]any)
	if rule["outbound"] != "block" || rule["inbound"].([]string)[0] != inbound.tag() {
		t.Fatalf("离线绑定出口未被阻断: %#v", rule)
	}
}

func TestBuildSingBoxConfigHasDirectFallback(t *testing.T) {
	cfg := buildSingBoxGatewayConfig(nil, nil)
	for _, o := range cfg["outbounds"].([]any) {
		m := o.(map[string]any)
		if m["tag"] != "direct" {
			continue
		}
		if m["type"] != "direct" {
			t.Errorf("direct 出站类型错误: %v", m["type"])
		}
		if cfg["route"].(map[string]any)["final"] != "direct" {
			t.Error("未绑定入站应走 direct")
		}
		return
	}
	t.Fatal("没有找到 direct 出站")
}

func TestBuildSingBoxConfigUsesStableRouteID(t *testing.T) {
	tunnel := &Tunnel{
		Port: 1080, RouteID: "exit-fixed", Status: "up",
		Node: Node{HostName: "jp-old"},
	}
	inbound := &nativeInbound{ID: 1, Port: 100, Protocol: "vless", Enable: true, BoundTo: "exit-fixed"}
	for _, host := range []string{"jp-old", "jp-new"} {
		tunnel.setNode(Node{HostName: host})
		cfg := buildSingBoxGatewayConfig([]*nativeInbound{inbound}, []*Tunnel{tunnel})
		out := cfg["outbounds"].([]any)[2].(map[string]any)
		if got := out["tag"]; got != "fanout-exit-fixed" {
			t.Fatalf("outbound tag = %v, want stable route ID", got)
		}
		rule := cfg["route"].(map[string]any)["rules"].([]any)[2].(map[string]any)
		if got := rule["outbound"]; got != "fanout-exit-fixed" {
			t.Fatalf("route outbound = %v, want stable route ID", got)
		}
	}
}

func TestBuildSingBoxConfigSkipsUnboundExit(t *testing.T) {
	tunnel := &Tunnel{Port: 1080, RouteID: "exit-unused", Status: "up", Node: Node{HostName: "jp1"}}
	cfg := buildSingBoxGatewayConfig([]*nativeInbound{{ID: 1, Port: 100, Protocol: "vless", Enable: true}}, []*Tunnel{tunnel})
	for _, item := range cfg["outbounds"].([]any) {
		if item.(map[string]any)["tag"] == "fanout-exit-unused" {
			t.Fatal("未绑定出口不应触发 gateway 配置变更")
		}
	}
}

func TestUpdateInboundRejectsOccupiedPortWithoutMutation(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	occupied := ln.Addr().(*net.TCPAddr).Port
	native := &Native{store: &nativeStore{NextID: 2, Inbounds: []*nativeInbound{{
		ID: 1, Port: 20001, Protocol: "vless", Network: "tcp", Enable: true,
	}}}}
	if err := native.UpdateInbound(1, InboundPatch{Port: &occupied}, nil); err == nil {
		t.Fatal("已占用端口应被拒绝")
	}
	if got := native.store.Inbounds[0].Port; got != 20001 {
		t.Fatalf("端口检查失败后不应修改内存状态，got %d", got)
	}
}

func TestUpdateInboundRejectsPendingTunnelSocksPort(t *testing.T) {
	port := 24567
	native := &Native{store: &nativeStore{NextID: 2, Inbounds: []*nativeInbound{{
		ID: 1, Port: 20001, Protocol: "vless", Network: "tcp", Enable: true,
	}}}}
	tunnel := &Tunnel{Slot: 1, Port: port, Status: "starting"}
	if err := native.UpdateInbound(1, InboundPatch{Port: &port}, []*Tunnel{tunnel}); err == nil {
		t.Fatal("等待启动的公网 SOCKS5 端口应被入站拒绝")
	}
	if got := native.store.Inbounds[0].Port; got != 20001 {
		t.Fatalf("端口冲突后不应修改入站，got %d", got)
	}
}

func TestNativeMutationRollsBackWhenApplyFails(t *testing.T) {
	native := newNativeForEmbeddedTest(t, &nativeStore{NextID: 2, Inbounds: []*nativeInbound{{
		ID: 1, Port: 20001, Protocol: "vless", Network: "tcp", Remark: "old", Enable: true,
		Clients: []nativeClient{{Email: "one", ID: newUUID(), Enable: true}},
	}}})
	_ = native.engine.close()
	remark := "new"
	if err := native.UpdateInbound(1, InboundPatch{Remark: &remark}, nil); err == nil {
		t.Fatal("已关闭的内嵌 Box 应拒绝修改")
	}
	if got := native.store.Inbounds[0].Remark; got != "old" {
		t.Fatalf("应用失败后应回滚备注，got %q", got)
	}
}

func TestNativeRestartsOnlyChangedInbound(t *testing.T) {
	native := newNativeForEmbeddedTest(t, &nativeStore{NextID: 3, Inbounds: []*nativeInbound{
		{ID: 1, Port: 24001, Protocol: "vless", Network: "tcp", Enable: true, Clients: []nativeClient{{Email: "one", ID: newUUID(), Enable: true}}},
		{ID: 2, Port: 24002, Protocol: "vless", Network: "tcp", Enable: true, Clients: []nativeClient{{Email: "two", ID: newUUID(), Enable: true}}},
	}})
	if err := native.apply(nil); err != nil {
		t.Fatal(err)
	}
	first := native.engine.inbounds[1]
	second := native.engine.inbounds[2]
	if err := native.AddClient(1, "new-client", nil); err != nil {
		t.Fatal(err)
	}
	if got := native.engine.inbounds[1].hash; got == first.hash {
		t.Fatal("修改入站 1 凭据后其监听器配置未更新")
	}
	if got := native.engine.inbounds[2].hash; got != second.hash {
		t.Fatal("修改入站 1 不应影响入站 2")
	}
}

func TestNativeReconcilesExitedInboundWithoutRestartingPeers(t *testing.T) {
	native := newNativeForEmbeddedTest(t, &nativeStore{NextID: 3, Inbounds: []*nativeInbound{
		{ID: 1, Port: 24101, Protocol: "vless", Network: "tcp", Enable: true, Clients: []nativeClient{{Email: "one", ID: newUUID(), Enable: true}}},
		{ID: 2, Port: 24102, Protocol: "vless", Network: "tcp", Enable: true, Clients: []nativeClient{{Email: "two", ID: newUUID(), Enable: true}}},
	}})
	if err := native.apply(nil); err != nil {
		t.Fatal(err)
	}
	second := native.engine.inbounds[2]
	port := 24103
	if err := native.UpdateInbound(1, InboundPatch{Port: &port}, nil); err != nil {
		t.Fatal(err)
	}
	if !native.engine.hasInbound(1, "in-24103-tcp") {
		t.Fatal("更新后的入站未在共享 Box 注册")
	}
	if got := native.engine.inbounds[2].hash; got != second.hash {
		t.Fatal("更新入站 1 不应重启入站 2")
	}
}

func TestNativeStoreValidateRejectsDuplicateIDAndTCPListener(t *testing.T) {
	duplicateID := &nativeStore{Inbounds: []*nativeInbound{{ID: 1, Port: 24001}, {ID: 1, Port: 24002}}}
	if err := duplicateID.validate(); err == nil {
		t.Fatal("重复入站 ID 应被拒绝")
	}
	duplicateTCP := &nativeStore{Inbounds: []*nativeInbound{{ID: 1, Port: 24001, Network: "ws"}, {ID: 2, Port: 24001, Network: "grpc"}}}
	if err := duplicateTCP.validate(); err == nil {
		t.Fatal("相同 TCP 监听端口应被拒绝")
	}
	staleNextID := &nativeStore{NextID: 1, Inbounds: []*nativeInbound{{ID: 3, Port: 24001, Protocol: "vless", Network: "tcp"}}}
	if err := staleNextID.validate(); err != nil {
		t.Fatal(err)
	}
	if staleNextID.NextID != 4 {
		t.Fatalf("next_id = %d, want 4", staleNextID.NextID)
	}
}

func TestNativeStoreValidateRejectsInvalidProtocolCombination(t *testing.T) {
	cases := []*nativeInbound{
		{ID: 1, Port: 24001, Protocol: "unknown", Network: "tcp"},
		{ID: 1, Port: 24001, Protocol: "vless", Network: "udp"},
		{ID: 1, Port: 24001, Protocol: "hysteria2", Network: "udp", Security: "none"},
		{ID: 1, Port: 24001, Protocol: "vless", Network: "ws", Security: "reality", Reality: &realityConfig{}},
		{ID: 1, Port: 24001, Protocol: "trojan", Network: "tcp", Security: "tls"},
	}
	for _, inbound := range cases {
		if err := (&nativeStore{Inbounds: []*nativeInbound{inbound}}).validate(); err == nil {
			t.Fatalf("非法持久化入站应被拒绝: %#v", inbound)
		}
	}
}

func TestNativeStoreValidateRejectsInvalidClientCredentials(t *testing.T) {
	cases := []*nativeInbound{
		{ID: 1, Port: 24001, Protocol: "vless", Network: "tcp", Clients: []nativeClient{{Email: "vless", ID: "not-a-uuid", Enable: true}}},
		{ID: 1, Port: 24001, Protocol: "trojan", Network: "tcp", Clients: []nativeClient{{Email: "trojan", Enable: true}}},
		{ID: 1, Port: 24001, Protocol: "tuic", Network: "udp", Security: "tls", TLS: &tlsConfig{CertFile: "cert", KeyFile: "key"}, Clients: []nativeClient{{Email: "tuic", ID: newUUID(), Enable: true}}},
	}
	for _, inbound := range cases {
		if err := (&nativeStore{Inbounds: []*nativeInbound{inbound}}).validate(); err == nil {
			t.Fatalf("非法客户端凭据应被拒绝: %#v", inbound)
		}
	}
}

func TestNativeStoreValidateRejectsInboundWithoutEnabledClient(t *testing.T) {
	store := &nativeStore{Inbounds: []*nativeInbound{{
		ID: 1, Port: 24001, Protocol: "vless", Network: "tcp", Enable: true,
		Clients: []nativeClient{{Email: "disabled", ID: newUUID(), Enable: false}},
	}}}
	if err := store.validate(); err == nil {
		t.Fatal("启用入站没有启用客户端时应被拒绝")
	}
}

func TestUpdateInboundRejectsEnableWithoutClient(t *testing.T) {
	native := &Native{store: &nativeStore{NextID: 2, Inbounds: []*nativeInbound{{
		ID: 1, Port: 24001, Protocol: "vless", Network: "tcp", Enable: false,
		Clients: []nativeClient{{Email: "disabled", ID: newUUID(), Enable: false}},
	}}}}
	enable := true
	if err := native.UpdateInbound(1, InboundPatch{Enable: &enable}, nil); err == nil {
		t.Fatal("没有启用客户端的入站不应允许启用")
	}
}

func TestNativeRejectsEnableBeyondInboundLimit(t *testing.T) {
	inbounds := make([]*nativeInbound, 0, maxNativeInbounds+1)
	for id := 1; id <= maxNativeInbounds; id++ {
		inbounds = append(inbounds, &nativeInbound{ID: id, Port: 25000 + id, Enable: true})
	}
	inbounds = append(inbounds, &nativeInbound{ID: maxNativeInbounds + 1, Port: 26000, Enable: false})
	native := &Native{store: &nativeStore{NextID: maxNativeInbounds + 2, Inbounds: inbounds}}
	enable := true
	if err := native.UpdateInbound(maxNativeInbounds+1, InboundPatch{Enable: &enable}, nil); err == nil {
		t.Fatal("超过入站上限时启用入站应被拒绝")
	}
}

func TestNativeReconcileContinuesAfterInboundFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	badPort := ln.Addr().(*net.TCPAddr).Port
	native := newNativeForEmbeddedTest(t, &nativeStore{NextID: 3, Inbounds: []*nativeInbound{
		{ID: 1, Port: badPort, Protocol: "vless", Network: "tcp", Enable: true, Clients: []nativeClient{{Email: "bad", ID: newUUID(), Enable: true}}},
		{ID: 2, Port: 24302, Protocol: "vless", Network: "tcp", Enable: true, Clients: []nativeClient{{Email: "good", ID: newUUID(), Enable: true}}},
	}})
	if err := native.apply(nil); err == nil {
		t.Fatal("端口冲突入站应导致同步报错")
	}
	list, err := native.Inbounds(nil)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[int]Inbound, len(list))
	for _, inbound := range list {
		byID[inbound.ID] = inbound
	}
	if got := byID[1].RuntimeStatus; got != "stopped" {
		t.Fatalf("失败入站运行状态 = %q, want stopped", got)
	}
	if byID[1].RuntimeError == "" {
		t.Fatal("失败入站应公开最近错误")
	}
	if got := byID[2].RuntimeStatus; got != "running" {
		t.Fatalf("健康入站运行状态 = %q, want running", got)
	}
}

func TestNativeInboundRuntimeReportsEmbeddedListenerError(t *testing.T) {
	native := newNativeForEmbeddedTest(t, &nativeStore{Inbounds: []*nativeInbound{{ID: 1, Enable: true}}})
	native.runtimeError[1] = "listen tcp: address already in use"
	list, err := native.Inbounds(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := list[0].RuntimeStatus; got != "stopped" {
		t.Fatalf("监听失败入站运行状态 = %q, want stopped", got)
	}
	if !strings.Contains(list[0].RuntimeError, "address already in use") {
		t.Fatalf("监听错误 = %q", list[0].RuntimeError)
	}
	detail, err := native.InboundDetail(1, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if detail.RuntimeStatus != list[0].RuntimeStatus || detail.RuntimeError != list[0].RuntimeError {
		t.Fatalf("详情运行状态与列表不一致: detail=%+v list=%+v", detail.Inbound, list[0])
	}
}

func TestNativeMutationSurvivesUnrelatedBrokenInbound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	badPort := ln.Addr().(*net.TCPAddr).Port
	native := newNativeForEmbeddedTest(t, &nativeStore{NextID: 3, Inbounds: []*nativeInbound{
		{ID: 1, Port: badPort, Protocol: "vless", Network: "tcp", Enable: true, Clients: []nativeClient{{Email: "broken", ID: newUUID(), Enable: true}}},
		{ID: 2, Port: 24402, Protocol: "vless", Network: "tcp", Enable: true, Remark: "old", Clients: []nativeClient{{Email: "healthy", ID: newUUID(), Enable: true}}},
	}})
	if err := native.apply(nil); err == nil {
		t.Fatal("初始坏入站应导致同步报错")
	}
	remark := "new"
	if err := native.UpdateInbound(2, InboundPatch{Remark: &remark}, nil); err != nil {
		t.Fatalf("无关坏入站不应阻止健康入站修改: %v", err)
	}
	if got := native.store.byID(2).Remark; got != remark {
		t.Fatalf("健康入站修改未保存，got %q", got)
	}
}

func TestShareLinkPerProtocol(t *testing.T) {
	c := nativeClient{ID: "uuid-1", Password: "pw-1", Email: "e", Enable: true}

	vless := shareLink(&nativeInbound{Port: 100, Protocol: "vless", Remark: "r"}, c, "1.2.3.4")
	if !strings.HasPrefix(vless, "vless://uuid-1@1.2.3.4:100?") {
		t.Errorf("vless 链接格式不对: %s", vless)
	}
	if !strings.Contains(vless, "encryption=none") {
		t.Errorf("vless 需要 encryption=none: %s", vless)
	}

	tro := shareLink(&nativeInbound{Port: 200, Protocol: "trojan", Network: "ws", Path: "/p"}, c, "h")
	if !strings.HasPrefix(tro, "trojan://pw-1@h:200?") {
		t.Errorf("trojan 应当用密码而不是 UUID: %s", tro)
	}
	if !strings.Contains(tro, "path=%2Fp") {
		t.Errorf("ws 链接要带 path: %s", tro)
	}

	h2 := shareLink(&nativeInbound{
		Port: 300, Protocol: "hysteria2", Network: "udp", Security: "tls", Remark: "h2",
		TLS: &tlsConfig{ServerName: "h2.example", SelfSigned: true},
	}, nativeClient{Password: "h2-pass"}, "h")
	if !strings.HasPrefix(h2, "hysteria2://h2-pass@h:300/?") {
		t.Errorf("hysteria2 链接格式不对: %s", h2)
	}
	if !strings.Contains(h2, "sni=h2.example") || !strings.Contains(h2, "insecure=1") {
		t.Errorf("hysteria2 TLS 参数缺失: %s", h2)
	}
	tuic := shareLink(&nativeInbound{
		Port: 301, Protocol: "tuic", Network: "udp", Security: "tls", Remark: "tuic",
		TLS: &tlsConfig{ServerName: "tuic.example"},
	}, nativeClient{ID: "uuid", Password: "pw"}, "h")
	if !strings.HasPrefix(tuic, "tuic://uuid:pw@h:301/?") || !strings.Contains(tuic, "congestion_control=cubic") {
		t.Errorf("tuic 链接格式不对: %s", tuic)
	}
}

func TestCloneRemark(t *testing.T) {
	if got := cloneRemark("线路A", "JP-244"); got != "线路A-JP-244" {
		t.Errorf("cloneRemark = %q", got)
	}
	if got := cloneRemark("", "JP-244"); got != "JP-244" {
		t.Errorf("空备注时应直接用标签，实际 %q", got)
	}
}

func TestVisionCapable(t *testing.T) {
	// Vision is valid only for VLESS + TCP + TLS/REALITY.
	if !visionCapable("vless", "tcp", "reality") {
		t.Error("vless/tcp/reality 应当支持 vision")
	}
	if !visionCapable("vless", "tcp", "tls") {
		t.Error("vless/tcp/tls 应当支持 vision")
	}
	if visionCapable("vless", "ws", "tls") {
		t.Error("ws 不该支持 vision")
	}
	if visionCapable("vless", "tcp", "none") {
		t.Error("没有安全层时不该支持 vision")
	}
	if visionCapable("trojan", "tcp", "tls") {
		t.Error("vision 是 VLESS 专属")
	}
}

func TestSingBoxTransportPerNetwork(t *testing.T) {
	cases := []struct {
		ib      nativeInbound
		wantKey string
		want    any
	}{
		{nativeInbound{Network: "ws", Path: "/p"}, "path", "/p"},
		{nativeInbound{Network: "httpupgrade", Path: "/h"}, "path", "/h"},
		// gRPC 没有 path，Path 字段复用为 serviceName，且不带前导斜杠
		{nativeInbound{Network: "grpc", Path: "/svc"}, "service_name", "svc"},
	}
	for _, c := range cases {
		transport := singBoxTransportJSON(&c.ib)
		if transport == nil {
			t.Errorf("%s 缺少 transport", c.ib.Network)
			continue
		}
		if got := transport[c.wantKey]; got != c.want {
			t.Errorf("%s 的 %s = %v, want %v", c.ib.Network, c.wantKey, got, c.want)
		}
	}
}

func TestSingBoxHysteria2Inbound(t *testing.T) {
	ib := &nativeInbound{
		Protocol: "hysteria2", Network: "udp", Port: 443, Listen: "::", Security: "tls",
		TLS:     &tlsConfig{CertFile: "/x.crt", KeyFile: "/x.key"},
		Clients: []nativeClient{{Password: "secret", Enable: true}},
	}
	cfg := singBoxInboundJSON(ib)
	if cfg["type"] != "hysteria2" || cfg["listen_port"] != 443 {
		t.Fatalf("Hysteria2 入站基本字段错误: %#v", cfg)
	}
	if cfg["listen"] != "::" {
		t.Fatalf("Hysteria2 未使用 IPv6/双栈监听: %#v", cfg)
	}
	users := cfg["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["password"] != "secret" {
		t.Fatalf("Hysteria2 用户密码未写入: %#v", users)
	}
	if _, ok := cfg["transport"]; ok {
		t.Fatal("Hysteria2 不应生成 V2Ray transport")
	}
}

func TestSingBoxTUICInbound(t *testing.T) {
	ib := &nativeInbound{
		Protocol: "tuic", Network: "udp", Port: 443, Security: "tls",
		TLS:     &tlsConfig{CertFile: "/x.crt", KeyFile: "/x.key"},
		Clients: []nativeClient{{ID: "uuid", Password: "secret", Enable: true}},
	}
	users := singBoxInboundJSON(ib)["users"].([]any)
	user := users[0].(map[string]any)
	if user["uuid"] != "uuid" || user["password"] != "secret" {
		t.Fatalf("TUIC 用户凭据未写入: %#v", user)
	}
}

func TestSingBoxCheckHysteria2Inbound(t *testing.T) {
	bin := os.Getenv("FANOUT_SINGBOX_BIN")
	if bin == "" {
		t.Skip("设置 FANOUT_SINGBOX_BIN 后校验实际 sing-box 配置")
	}
	dir := t.TempDir()
	cert, key, err := selfSignedCert(dir, "h2.local")
	if err != nil {
		t.Fatal(err)
	}
	cfg := buildSingBoxGatewayConfig([]*nativeInbound{
		{
			Protocol: "hysteria2", Network: "udp", Port: 14443, Listen: "::", Security: "tls",
			TLS:     &tlsConfig{CertFile: cert, KeyFile: key},
			Clients: []nativeClient{{Password: "secret", Enable: true}},
		},
		{
			Protocol: "tuic", Network: "udp", Port: 14444, Listen: "::", Security: "tls",
			TLS:     &tlsConfig{CertFile: cert, KeyFile: key},
			Clients: []nativeClient{{ID: newUUID(), Password: "secret2", Enable: true}},
		},
	}, nil)
	blob, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hysteria2.json")
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check 失败: %v\n%s", err, out)
	}
}

func TestSingBoxInboundReality(t *testing.T) {
	ib := nativeInbound{
		Network: "tcp", Security: "reality",
		Reality: &realityConfig{
			Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
			PrivateKey: "priv", PublicKey: "pub", ShortIDs: []string{"abcd1234"},
		},
	}
	tlsOptions := singBoxInboundTLSJSON(&ib)
	r, ok := tlsOptions["reality"].(map[string]any)
	if !ok {
		t.Fatal("缺少 reality")
	}
	if r["private_key"] != "priv" {
		t.Errorf("服务端要写私钥，实际 %v", r["private_key"])
	}
	if _, leaked := r["public_key"]; leaked {
		t.Error("服务端配置不该出现 publicKey")
	}
}

func TestShareLinkCarriesSecurityParams(t *testing.T) {
	c := nativeClient{ID: "uuid-1", Enable: true, Flow: "xtls-rprx-vision"}

	re := shareLink(&nativeInbound{
		Port: 100, Protocol: "vless", Network: "tcp", Security: "reality", Remark: "r",
		Reality: &realityConfig{
			ServerNames: []string{"www.cloudflare.com"}, PublicKey: "PBK",
			ShortIDs: []string{"sid1"}, Fingerprint: "chrome",
		},
	}, c, "h")
	for _, want := range []string{"pbk=PBK", "sid=sid1", "fp=chrome",
		"sni=www.cloudflare.com", "flow=xtls-rprx-vision"} {
		if !strings.Contains(re, want) {
			t.Errorf("REALITY 链接缺少 %s: %s", want, re)
		}
	}

	// 自签证书验不过 CA，链接必须带指纹，否则客户端连不上
	tl := shareLink(&nativeInbound{
		Port: 200, Protocol: "vless", Network: "tcp", Security: "tls", Remark: "t",
		TLS: &tlsConfig{ServerName: "demo.local", SelfSigned: true, CertSha256: "AABB"},
	}, nativeClient{ID: "u", Enable: true}, "h")
	if !strings.Contains(tl, "pinSHA256=AABB") {
		t.Errorf("自签 TLS 链接要带证书指纹: %s", tl)
	}
}

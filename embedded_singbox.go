package main

// Build fanout with: -tags "with_gvisor with_quic". OpenVPN system:false
// requires gVisor; Hysteria2 and TUIC require QUIC support.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	sbcertificate "github.com/sagernet/sing-box/adapter/certificate"
	sbendpoint "github.com/sagernet/sing-box/adapter/endpoint"
	sbinbound "github.com/sagernet/sing-box/adapter/inbound"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	sbservice "github.com/sagernet/sing-box/adapter/service"
	sbdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/openvpn"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	SBJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const fanoutDynamicOutboundType = "fanout-dynamic"

// embeddedEngine owns the sole sing-box instance. Inbounds, public SOCKS
// listeners and OpenVPN endpoints are registered dynamically on that Box.
type embeddedEngine struct {
	mu sync.Mutex

	ctx context.Context
	box *sbox.Box

	// routes is immutable after publication. A route is selected from the
	// inbound tag carried in sing-box's InboundContext.
	routes map[string]embeddedRoute

	inbounds map[int]embeddedInboundState
	tunnels  map[int]embeddedTunnelState
}

type embeddedRoute struct {
	endpoint string
	direct   bool
	block    bool
}

type embeddedInboundState struct {
	tag  string
	hash [sha256.Size]byte
}

type embeddedTunnelState struct {
	endpointTag string
	socksTag    string
	routeID     string
}

type fanoutDynamicOutboundOptions struct{}

type fanoutDynamicOutbound struct {
	sboutbound.Adapter
	engine *embeddedEngine
}

func newEmbeddedEngine() (*embeddedEngine, error) {
	engine := &embeddedEngine{
		routes:   make(map[string]embeddedRoute),
		inbounds: make(map[int]embeddedInboundState),
		tunnels:  make(map[int]embeddedTunnelState),
	}

	inboundRegistry := sbinbound.NewRegistry()
	outboundRegistry := sboutbound.NewRegistry()
	endpointRegistry := sbendpoint.NewRegistry()
	// Use the narrowest protocol registry possible. Importing upstream include
	// would pull every optional protocol and service into fanout's binary.
	socks.RegisterInbound(inboundRegistry)
	vless.RegisterInbound(inboundRegistry)
	vmess.RegisterInbound(inboundRegistry)
	trojan.RegisterInbound(inboundRegistry)
	hysteria2.RegisterInbound(inboundRegistry)
	tuic.RegisterInbound(inboundRegistry)
	openvpn.RegisterEndpoint(endpointRegistry)
	// The route table is fanout-owned. sing-box invokes this outbound after it
	// has parsed the inbound protocol and attached its tag to the context.
	sboutbound.Register[fanoutDynamicOutboundOptions](outboundRegistry, fanoutDynamicOutboundType,
		func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ fanoutDynamicOutboundOptions) (adapter.Outbound, error) {
			return &fanoutDynamicOutbound{
				Adapter: sboutbound.NewAdapter(fanoutDynamicOutboundType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
				engine:  engine,
			}, nil
		})

	dnsRegistry := sbdns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	ctx := sbox.Context(context.Background(), inboundRegistry, outboundRegistry, endpointRegistry,
		dnsRegistry, sbservice.NewRegistry(), sbcertificate.NewRegistry())
	engine.ctx = ctx

	box, err := sbox.New(sbox.Options{
		Context: ctx,
		Options: option.Options{
			Log: &option.LogOptions{Level: "warn", Timestamp: true},
			Outbounds: []option.Outbound{{
				Type:    fanoutDynamicOutboundType,
				Tag:     fanoutDynamicOutboundType,
				Options: &fanoutDynamicOutboundOptions{},
			}},
			Route: &option.RouteOptions{Final: fanoutDynamicOutboundType},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("创建内嵌 sing-box 失败: %w", err)
	}
	if err := box.Start(); err != nil {
		return nil, fmt.Errorf("启动内嵌 sing-box 失败: %w", err)
	}
	engine.box = box
	return engine, nil
}

func (o *fanoutDynamicOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer, destination, err := o.endpointFor(ctx, destination)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, destination)
}

func (o *fanoutDynamicOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dialer, destination, err := o.endpointFor(ctx, destination)
	if err != nil {
		return nil, err
	}
	return dialer.ListenPacket(ctx, destination)
}

func (o *fanoutDynamicOutbound) endpointFor(ctx context.Context, destination M.Socksaddr) (N.Dialer, M.Socksaddr, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil || metadata.Inbound == "" {
		return nil, destination, fmt.Errorf("fanout 路由缺少入站标识")
	}
	// An OpenVPN endpoint is also represented as an internal inbound while its
	// userspace stack dials the VPN server. That bootstrap traffic must use the
	// host network, never the endpoint being established.
	if isEmbeddedEndpointInbound(metadata.Inbound) {
		return N.SystemDialer, destination, nil
	}
	o.engine.mu.Lock()
	route, found := o.engine.routes[metadata.Inbound]
	box := o.engine.box
	o.engine.mu.Unlock()
	if !found {
		return nil, destination, fmt.Errorf("入站 %s 没有可用出口", metadata.Inbound)
	}
	if route.block {
		return nil, destination, fmt.Errorf("入站 %s 绑定的出口当前不可用", metadata.Inbound)
	}
	if route.direct || destination.IsIPv6() {
		return N.SystemDialer, destination, nil
	}
	if destination.IsDomain() {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", destination.Fqdn)
		if err != nil {
			return nil, destination, err
		}
		for _, address := range addresses {
			if address.Is4() {
				destination = M.SocksaddrFrom(address, destination.Port)
				break
			}
		}
		if destination.IsDomain() {
			// VPN Gate OpenVPN endpoints are IPv4-only. IPv6-only names retain
			// the historical VPS-direct fallback.
			return N.SystemDialer, destination, nil
		}
	}
	endpoint, found := box.Endpoint().Get(route.endpoint)
	if !found {
		return nil, destination, fmt.Errorf("入站 %s 的出口已移除", metadata.Inbound)
	}
	return endpoint, destination, nil
}

func isEmbeddedEndpointInbound(tag string) bool {
	return strings.HasPrefix(tag, "fanout-openvpn-")
}

func (e *embeddedEngine) close() error {
	e.mu.Lock()
	box := e.box
	e.box = nil
	e.mu.Unlock()
	if box == nil {
		return nil
	}
	return box.Close()
}

func (e *embeddedEngine) hasInbound(id int, tag string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, found := e.inbounds[id]
	return found && state.tag == tag && e.box != nil
}

func (e *embeddedEngine) createInbound(inbound *nativeInbound) error {
	options, err := decodeSingBoxOptions[eoptionInbound](e.ctx, singBoxInboundJSON(inbound))
	if err != nil {
		return fmt.Errorf("解析入站 %d 配置失败: %w", inbound.ID, err)
	}
	if err := e.box.Inbound().Create(e.ctx, e.box.Router(), e.box.LogFactory().NewLogger("inbound"), options.Tag, options.Type, options.Options); err != nil {
		return fmt.Errorf("启动入站 %d 失败: %w", inbound.ID, err)
	}
	return nil
}

func (e *embeddedEngine) removeInbound(tag string) error {
	if _, err := e.box.Inbound().Get(tag); err == false {
		return nil
	}
	if err := e.box.Inbound().Remove(tag); err != nil {
		return fmt.Errorf("停止入站 %s 失败: %w", tag, err)
	}
	return nil
}

func (e *embeddedEngine) syncInbounds(inbounds []*nativeInbound, tunnels []*Tunnel) (map[int]error, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil {
		return nil, fmt.Errorf("内嵌 sing-box 已关闭")
	}

	desired := make(map[int]*nativeInbound, len(inbounds))
	routes := make(map[string]embeddedRoute, len(inbounds)+len(e.tunnels))
	for tag, route := range e.routes {
		if _, isTunnel := e.tunnelRoute(tag); isTunnel {
			routes[tag] = route
		}
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		desired[inbound.ID] = inbound
		routes[inbound.tag()] = e.routeForInbound(inbound, tunnels)
	}
	// Publish routes before a newly created listener can accept a connection.
	// Removed listeners are fail-closed before their sockets are closed below.
	e.routes = routes

	for id, current := range e.inbounds {
		if _, wanted := desired[id]; wanted {
			continue
		}
		if err := e.box.Inbound().Remove(current.tag); err != nil {
			return nil, fmt.Errorf("移除入站 %d 失败: %w", id, err)
		}
		delete(e.inbounds, id)
	}

	failures := make(map[int]error)
	for id, inbound := range desired {
		configHash, err := embeddedInboundHash(inbound)
		if err != nil {
			failures[id] = err
			continue
		}
		current, exists := e.inbounds[id]
		if exists && current.hash == configHash && current.tag == inbound.tag() {
			continue
		}
		// A changed listener using the same tag must release its socket before
		// replacement. This only interrupts that single inbound.
		if exists {
			if err := e.box.Inbound().Remove(current.tag); err != nil {
				failures[id] = fmt.Errorf("停止旧入站失败: %w", err)
				continue
			}
			delete(e.inbounds, id)
		}
		if err := e.createInbound(inbound); err != nil {
			failures[id] = err
			continue
		}
		e.inbounds[id] = embeddedInboundState{tag: inbound.tag(), hash: configHash}
	}

	return failures, nil
}

func (e *embeddedEngine) routeForInbound(inbound *nativeInbound, tunnels []*Tunnel) embeddedRoute {
	if inbound.BoundTo == "" {
		return embeddedRoute{direct: true}
	}
	for _, tunnel := range tunnels {
		state := tunnel.snapshot()
		if tunnelBinding(tunnel) == inbound.BoundTo && state.Status == "up" {
			if managed, found := e.tunnels[state.Slot]; found {
				return embeddedRoute{endpoint: managed.endpointTag}
			}
		}
	}
	return embeddedRoute{block: true}
}

func (e *embeddedEngine) tunnelRoute(tag string) (embeddedTunnelState, bool) {
	for _, tunnel := range e.tunnels {
		if tunnel.socksTag == tag {
			return tunnel, true
		}
	}
	return embeddedTunnelState{}, false
}

func embeddedInboundHash(inbound *nativeInbound) ([sha256.Size]byte, error) {
	config := singBoxInboundJSON(inbound)
	blob, err := json.Marshal(config)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(blob), nil
}

func (e *embeddedEngine) addTunnel(tunnel *Tunnel) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil {
		return fmt.Errorf("内嵌 sing-box 已关闭")
	}
	state := tunnel.snapshot()
	endpointTag := fmt.Sprintf("fanout-openvpn-%d", state.Slot)
	socksTag := fmt.Sprintf("fanout-socks-%d", state.Slot)
	if previous, exists := e.tunnels[state.Slot]; exists {
		nextRoutes := e.blockEndpointRoutes(previous.endpointTag)
		delete(nextRoutes, previous.socksTag)
		e.routes = nextRoutes
		_ = e.box.Inbound().Remove(previous.socksTag)
		_ = e.box.Endpoint().Remove(previous.endpointTag)
		delete(e.tunnels, state.Slot)
	}

	endpointConfig, err := openVPNEndpoint(state.Node.Config, endpointTag)
	if err != nil {
		return fmt.Errorf("转换 VPN Gate 配置失败: %w", err)
	}
	endpointOptions, err := decodeSingBoxOptions[option.Endpoint](e.ctx, endpointConfig)
	if err != nil {
		return fmt.Errorf("解析 OpenVPN endpoint 配置失败: %w", err)
	}
	if err := e.box.Endpoint().Create(e.ctx, e.box.Router(), e.box.LogFactory().NewLogger("openvpn"), endpointOptions.Tag, endpointOptions.Type, endpointOptions.Options); err != nil {
		return fmt.Errorf("启动 OpenVPN endpoint 失败: %w", err)
	}

	socksConfig := map[string]any{
		"type": "socks", "tag": socksTag,
		"listen": "0.0.0.0", "listen_port": state.Port,
	}
	cred := tunnel.credential()
	socksConfig["users"] = []any{map[string]any{"username": cred.User, "password": cred.Pass}}
	socksOptions, err := decodeSingBoxOptions[option.Inbound](e.ctx, socksConfig)
	if err != nil {
		_ = e.box.Endpoint().Remove(endpointTag)
		return fmt.Errorf("解析公网 SOCKS5 配置失败: %w", err)
	}
	// Publish the route before accepting public connections.
	nextRoutes := cloneEmbeddedRoutes(e.routes)
	nextRoutes[socksTag] = embeddedRoute{endpoint: endpointTag}
	e.routes = nextRoutes
	if err := e.box.Inbound().Create(e.ctx, e.box.Router(), e.box.LogFactory().NewLogger("socks"), socksOptions.Tag, socksOptions.Type, socksOptions.Options); err != nil {
		nextRoutes = cloneEmbeddedRoutes(e.routes)
		delete(nextRoutes, socksTag)
		e.routes = nextRoutes
		_ = e.box.Endpoint().Remove(endpointTag)
		return fmt.Errorf("启动公网 SOCKS5 失败: %w", err)
	}
	e.tunnels[state.Slot] = embeddedTunnelState{endpointTag: endpointTag, socksTag: socksTag, routeID: state.RouteID}
	return nil
}

func (e *embeddedEngine) removeTunnel(tunnel *Tunnel) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, found := e.tunnels[tunnel.snapshot().Slot]
	if !found || e.box == nil {
		return
	}
	nextRoutes := e.blockEndpointRoutes(state.endpointTag)
	delete(nextRoutes, state.socksTag)
	e.routes = nextRoutes
	_ = e.box.Inbound().Remove(state.socksTag)
	_ = e.box.Endpoint().Remove(state.endpointTag)
	delete(e.tunnels, tunnel.snapshot().Slot)
}

func (e *embeddedEngine) updateTunnelCredential(tunnel *Tunnel) error {
	// SOCKS authentication is bound to its listener. Recreate only this public
	// SOCKS inbound while leaving the OpenVPN endpoint and proxy inbounds alive.
	e.mu.Lock()
	defer e.mu.Unlock()
	state, found := e.tunnels[tunnel.snapshot().Slot]
	if !found || e.box == nil {
		return fmt.Errorf("OpenVPN endpoint 未运行")
	}
	if _, found := e.box.Inbound().Get(state.socksTag); found {
		if err := e.box.Inbound().Remove(state.socksTag); err != nil {
			return fmt.Errorf("停止旧公网 SOCKS5 失败: %w", err)
		}
	}
	snapshot := tunnel.snapshot()
	cred := tunnel.credential()
	raw := map[string]any{
		"type": "socks", "tag": state.socksTag,
		"listen": "0.0.0.0", "listen_port": snapshot.Port,
		"users": []any{map[string]any{"username": cred.User, "password": cred.Pass}},
	}
	options, err := decodeSingBoxOptions[option.Inbound](e.ctx, raw)
	if err != nil {
		return err
	}
	if err := e.box.Inbound().Create(e.ctx, e.box.Router(), e.box.LogFactory().NewLogger("socks"), options.Tag, options.Type, options.Options); err != nil {
		return fmt.Errorf("启动新公网 SOCKS5 失败: %w", err)
	}
	return nil
}

func (e *embeddedEngine) dialTunnel(ctx context.Context, tunnel *Tunnel, network, address string) (net.Conn, error) {
	e.mu.Lock()
	state, found := e.tunnels[tunnel.snapshot().Slot]
	box := e.box
	e.mu.Unlock()
	if !found || box == nil {
		return nil, fmt.Errorf("OpenVPN endpoint 未运行")
	}
	endpoint, found := box.Endpoint().Get(state.endpointTag)
	if !found {
		return nil, fmt.Errorf("OpenVPN endpoint 未运行")
	}
	destination := M.ParseSocksaddr(address)
	if !destination.IsValid() {
		return nil, fmt.Errorf("目标地址无效: %s", address)
	}
	if destination.IsDomain() {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", destination.Fqdn)
		if err != nil || len(addresses) == 0 {
			return nil, fmt.Errorf("解析 IPv4 目标失败: %w", err)
		}
		destination = M.SocksaddrFrom(addresses[0], destination.Port)
	}
	return endpoint.DialContext(ctx, network, destination)
}

func cloneEmbeddedRoutes(routes map[string]embeddedRoute) map[string]embeddedRoute {
	copyRoutes := make(map[string]embeddedRoute, len(routes))
	for tag, route := range routes {
		copyRoutes[tag] = route
	}
	return copyRoutes
}

// blockEndpointRoutes makes a removed endpoint fail closed until Native has
// published the replacement route after a successful reconnect.
func (e *embeddedEngine) blockEndpointRoutes(endpoint string) map[string]embeddedRoute {
	nextRoutes := cloneEmbeddedRoutes(e.routes)
	for tag, route := range nextRoutes {
		if route.endpoint == endpoint {
			nextRoutes[tag] = embeddedRoute{block: true}
		}
	}
	return nextRoutes
}

// eoptionInbound exists only to keep generic decoding confined to this file.
type eoptionInbound = option.Inbound

func decodeSingBoxOptions[T any](ctx context.Context, raw map[string]any) (T, error) {
	var out T
	blob, err := json.Marshal(raw)
	if err != nil {
		return out, err
	}
	if err := SBJSON.UnmarshalContext(ctx, blob, &out); err != nil {
		return out, err
	}
	return out, nil
}

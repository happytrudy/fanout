package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// nativeClient 是一个可连接的客户端凭据。
// 复制入站时同一个 client 会挂到所有出口上，用户换出口只需要改端口。
type nativeClient struct {
	Email    string `json:"email"`
	ID       string `json:"id"`       // vless/vmess 用 UUID
	Password string `json:"password"` // trojan 用密码
	Enable   bool   `json:"enable"`
	// Flow 只对 VLESS 有意义，取值 "" 或 xtls-rprx-vision。
	// Vision 要求底层是 TCP + TLS/REALITY。
	Flow string `json:"flow,omitempty"`
}

// nativeInbound 是自建模式下的一个入站。
//
// Fields mirror the UI's inbound model.
type nativeInbound struct {
	ID       int    `json:"id"`
	Port     int    `json:"port"`
	Listen   string `json:"listen,omitempty"` // runtime override; empty means IPv4 wildcard
	Protocol string `json:"protocol"`         // vless | vmess | trojan
	Network  string `json:"network"`          // tcp | ws | grpc | httpupgrade | udp (hysteria2)
	Path     string `json:"path"`             // ws/httpupgrade 路径，grpc 用作 serviceName
	Host     string `json:"host"`             // ws/httpupgrade 的 Host 头
	// Security 是传输层安全：none | tls | reality
	Security string         `json:"security"`
	TLS      *tlsConfig     `json:"tls,omitempty"`
	Reality  *realityConfig `json:"reality,omitempty"`
	Remark   string         `json:"remark"`
	Enable   bool           `json:"enable"`
	Clients  []nativeClient `json:"clients"`
	// BoundTo 是持久化的出口 Route ID，空表示直连。
	// 旧版本存的是 hostname 经 sanitizeTag 后的值，加载时自动迁移。
	BoundTo string `json:"bound_to"`
}

// tlsConfig 是标准 TLS 的配置。证书要么由用户提供路径，要么 fanout 生成自签的。
type tlsConfig struct {
	ServerName string `json:"server_name"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	// SelfSigned 记录证书是 fanout 生成的，分享链接要带 allowInsecure
	SelfSigned bool `json:"self_signed"`
	// CertSha256 是证书的 SHA-256 指纹（十六进制）。
	// 自签证书通过分享链接里的指纹建立信任。
	CertSha256 string `json:"cert_sha256,omitempty"`
}

// realityConfig 是 REALITY 的配置。
//
// PublicKey 服务端用不到，但客户端必须填，所以一并存下来供生成分享链接。
type realityConfig struct {
	Dest        string   `json:"dest"` // 借用的真实站点，如 www.microsoft.com:443
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"`
	PublicKey   string   `json:"public_key"`
	ShortIDs    []string `json:"short_ids"`
	Fingerprint string   `json:"fingerprint"` // 客户端指纹，如 chrome
}

// tag identifies this inbound in sing-box routing rules.
func (n *nativeInbound) tag() string {
	return fmt.Sprintf("in-%d-%s", n.Port, n.netOrTCP())
}

func (n *nativeInbound) netOrTCP() string {
	if n.Network == "" {
		return "tcp"
	}
	return n.Network
}

// listenNetwork is the OS transport used by an inbound. WebSocket, gRPC and
// HTTPUpgrade are application transports layered over TCP and therefore share
// the same listening-port namespace.
func (n *nativeInbound) listenNetwork() string {
	return listenerNetwork(n.netOrTCP())
}

func listenerNetwork(network string) string {
	if strings.EqualFold(strings.TrimSpace(network), "udp") {
		return "udp"
	}
	return "tcp"
}

func (n *nativeInbound) listenOrIPv4() string {
	if strings.TrimSpace(n.Listen) == "" {
		return "0.0.0.0"
	}
	return n.Listen
}

func (n *nativeInbound) securityOrNone() string {
	if n.Security == "" {
		return "none"
	}
	return n.Security
}

// nativeStore 是自建模式的持久状态。
type nativeStore struct {
	NextID   int              `json:"next_id"`
	Inbounds []*nativeInbound `json:"inbounds"`
}

func (s *nativeStore) clone() *nativeStore {
	copyStore := &nativeStore{NextID: s.NextID, Inbounds: make([]*nativeInbound, 0, len(s.Inbounds))}
	for _, inbound := range s.Inbounds {
		copyInbound := *inbound
		copyInbound.Clients = append([]nativeClient(nil), inbound.Clients...)
		if inbound.TLS != nil {
			copyTLS := *inbound.TLS
			copyInbound.TLS = &copyTLS
		}
		if inbound.Reality != nil {
			copyReality := *inbound.Reality
			copyReality.ServerNames = append([]string(nil), inbound.Reality.ServerNames...)
			copyReality.ShortIDs = append([]string(nil), inbound.Reality.ShortIDs...)
			copyInbound.Reality = &copyReality
		}
		copyStore.Inbounds = append(copyStore.Inbounds, &copyInbound)
	}
	return copyStore
}

func nativeStatePath(dir string) string { return filepath.Join(dir, "native.json") }

func loadNativeStore(dir string) (*nativeStore, error) {
	blob, err := os.ReadFile(nativeStatePath(dir))
	if os.IsNotExist(err) {
		return &nativeStore{NextID: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var st nativeStore
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", nativeStatePath(dir), err)
	}
	if err := st.validate(); err != nil {
		return nil, fmt.Errorf("校验 %s 失败: %w", nativeStatePath(dir), err)
	}
	return &st, nil
}

// validate rejects ambiguous persisted state before it can be rendered into
// sing-box configurations. NextID is recovered for old files that stored a
// stale counter, because reusing an existing ID would otherwise orphan a
// child process and make subsequent mutations target the wrong inbound.
func (s *nativeStore) validate() error {
	seenIDs := make(map[int]bool, len(s.Inbounds))
	seenListeners := make(map[string]bool, len(s.Inbounds))
	maxID := 0
	for _, inbound := range s.Inbounds {
		if inbound == nil {
			return fmt.Errorf("存在空入站记录")
		}
		if inbound.ID < 1 {
			return fmt.Errorf("入站 ID %d 不合法", inbound.ID)
		}
		if seenIDs[inbound.ID] {
			return fmt.Errorf("入站 ID %d 重复", inbound.ID)
		}
		seenIDs[inbound.ID] = true
		if inbound.Port < 1 || inbound.Port > 65535 {
			return fmt.Errorf("入站 %d 的端口 %d 不合法", inbound.ID, inbound.Port)
		}
		if err := validatePersistedInbound(inbound); err != nil {
			return fmt.Errorf("入站 %d 无效: %w", inbound.ID, err)
		}
		listener := fmt.Sprintf("%s/%d", inbound.listenNetwork(), inbound.Port)
		if seenListeners[listener] {
			return fmt.Errorf("%s 监听重复", listener)
		}
		seenListeners[listener] = true
		if inbound.ID > maxID {
			maxID = inbound.ID
		}
	}
	if s.NextID <= maxID {
		s.NextID = maxID + 1
	}
	if s.NextID < 1 {
		s.NextID = 1
	}
	return nil
}

// validatePersistedInbound checks configuration semantics that cannot be
// inferred from the JSON schema. It deliberately does not probe ports or
// external REALITY destinations: loading state must be deterministic and
// should report a broken record before any child process is started.
func validatePersistedInbound(inbound *nativeInbound) error {
	protocol := strings.ToLower(strings.TrimSpace(inbound.Protocol))
	if !nativeProtocols[protocol] {
		return fmt.Errorf("不支持的协议 %q", inbound.Protocol)
	}
	network := strings.ToLower(strings.TrimSpace(inbound.Network))
	if network == "" {
		network = "tcp"
	}
	// XHTTP was supported by the historical Xray backend. Keep it loadable so
	// openNativeConfigured can disable and annotate it for the user to delete.
	if network == "xhttp" {
		return nil
	}
	if !nativeNetworks[network] {
		return fmt.Errorf("不支持的传输方式 %q", inbound.Network)
	}
	if network == "udp" && protocol != "hysteria2" && protocol != "tuic" {
		return fmt.Errorf("UDP 只适用于 Hysteria2/TUIC")
	}
	if (protocol == "hysteria2" || protocol == "tuic") && network != "udp" {
		return fmt.Errorf("%s 必须使用 UDP/QUIC", protocol)
	}
	security := strings.ToLower(strings.TrimSpace(inbound.Security))
	if security == "" {
		security = "none"
	}
	if !nativeSecurities[security] {
		return fmt.Errorf("不支持的安全层 %q", inbound.Security)
	}
	if (protocol == "hysteria2" || protocol == "tuic") && security != "tls" {
		return fmt.Errorf("%s 必须启用 TLS", protocol)
	}
	if security == "reality" && network != "tcp" && network != "grpc" {
		return fmt.Errorf("REALITY 不支持 %s 传输", network)
	}
	enabledClients := 0
	for _, client := range inbound.Clients {
		if !client.Enable {
			continue
		}
		enabledClients++
		switch protocol {
		case "vless", "vmess":
			if !validUUID(client.ID) {
				return fmt.Errorf("客户端 %q 的 UUID 无效", client.Email)
			}
			if client.Flow != "" && !visionCapable(protocol, network, security) {
				return fmt.Errorf("客户端 %q 的 Vision 配置不适用于该入站", client.Email)
			}
		case "trojan", "hysteria2":
			if strings.TrimSpace(client.Password) == "" {
				return fmt.Errorf("客户端 %q 缺少密码", client.Email)
			}
		case "tuic":
			if !validUUID(client.ID) || strings.TrimSpace(client.Password) == "" {
				return fmt.Errorf("客户端 %q 的 TUIC UUID 或密码无效", client.Email)
			}
		}
	}
	if inbound.Enable && enabledClients == 0 {
		return fmt.Errorf("没有启用的客户端")
	}
	switch security {
	case "tls":
		if inbound.TLS == nil || strings.TrimSpace(inbound.TLS.CertFile) == "" || strings.TrimSpace(inbound.TLS.KeyFile) == "" {
			return fmt.Errorf("TLS 缺少证书或私钥路径")
		}
	case "reality":
		if inbound.Reality == nil || strings.TrimSpace(inbound.Reality.Dest) == "" || strings.TrimSpace(inbound.Reality.PrivateKey) == "" || len(inbound.Reality.ServerNames) == 0 || len(inbound.Reality.ShortIDs) == 0 {
			return fmt.Errorf("REALITY 缺少目标、私钥、server name 或 short ID")
		}
	}
	return nil
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

func (s *nativeStore) enabledInboundCount() int {
	count := 0
	for _, inbound := range s.Inbounds {
		if inbound.Enable {
			count++
		}
	}
	return count
}

func (s *nativeStore) save(dir string) error {
	blob, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeDurableFile(nativeStatePath(dir), blob, 0600)
}

func (s *nativeStore) byID(id int) *nativeInbound {
	for _, ib := range s.Inbounds {
		if ib.ID == id {
			return ib
		}
	}
	return nil
}

func (s *nativeStore) usedPorts(network ...string) map[int]bool {
	used := map[int]bool{}
	for _, ib := range s.Inbounds {
		if len(network) > 0 && network[0] != "" && ib.listenNetwork() != listenerNetwork(network[0]) {
			continue
		}
		used[ib.Port] = true
	}
	return used
}

// sorted 返回按端口排序的入站，让界面顺序稳定。
func (s *nativeStore) sorted() []*nativeInbound {
	out := make([]*nativeInbound, len(s.Inbounds))
	copy(out, s.Inbounds)
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// newUUID creates a UUID v4 accepted by VLESS and VMess.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 随机源不可用时退回一个仍然唯一的形式，避免建站直接失败
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

// randomHex 生成 n 字节的随机十六进制串，用作 trojan 密码与 ws 路径。
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprint(os.Getpid())))
	}
	return hex.EncodeToString(b)
}

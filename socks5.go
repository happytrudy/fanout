package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 最小实现：只支持 CONNECT。
// 域名在本进程内解析，隧道里只跑 TCP，避免依赖隧道内的 UDP/DNS。
//
// 认证走 RFC1929 用户名/口令。端口对公网敞开，没有口令等于谁扫到谁就能用
// 这条家宽出口，所以凭据是必需的而不是可选项。

const (
	socksVer5     = 0x05
	authNone      = 0x00
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
	repGenFail    = 0x01
	repHostUnre   = 0x04
	repCmdNotSupp = 0x07
)

// errIPv6NotSupported 表示拒绝 IPv6 目标：隧道内只有 IPv4。
var errIPv6NotSupported = errors.New("隧道内不支持 IPv6")

// dialSOCKS5 opens one CONNECT stream through an unauthenticated local SOCKS5
// listener. Tunnel-facing sing-box instances listen only on loopback.
func dialSOCKS5(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))

	if _, err := c.Write([]byte{socksVer5, 0x01, authNone}); err != nil {
		return fail(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(c, method); err != nil {
		return fail(err)
	}
	if method[0] != socksVer5 || method[1] != authNone {
		return fail(fmt.Errorf("内部 SOCKS5 拒绝无认证连接"))
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fail(fmt.Errorf("目标端口无效: %q", portText))
	}
	req := []byte{socksVer5, cmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, atypIPv4)
			req = append(req, v4...)
		} else {
			return fail(errIPv6NotSupported)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fail(fmt.Errorf("目标主机名长度无效"))
		}
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return fail(err)
	}
	if head[0] != socksVer5 || head[1] != repSuccess {
		return fail(fmt.Errorf("内部 SOCKS5 连接失败，响应码 %#x", head[1]))
	}
	var addrLen int
	switch head[3] {
	case atypIPv4:
		addrLen = 4
	case atypIPv6:
		addrLen = 16
	case atypDomain:
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil {
			return fail(err)
		}
		addrLen = int(b[0])
	default:
		return fail(fmt.Errorf("内部 SOCKS5 返回未知地址类型 %#x", head[3]))
	}
	if _, err := io.CopyN(io.Discard, c, int64(addrLen+2)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

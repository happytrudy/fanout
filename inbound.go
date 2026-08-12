package main

import "time"

// Inbound is a managed proxy entry point and its bound VPN Gate exit.
type Inbound struct {
	ID       int    `json:"id"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Remark   string `json:"remark"`
	Enable   bool   `json:"enable"`
	Tag      string `json:"tag"`
	BoundTo  string `json:"bound_to"`
	BoundUp  bool   `json:"bound_up"`
	// RuntimeStatus is independent from Enable, which is only the persisted
	// configuration switch.
	RuntimeStatus string    `json:"runtime_status"`
	RuntimeError  string    `json:"runtime_error,omitempty"`
	RetryAt       time.Time `json:"retry_at,omitempty"`
}

type InboundDetail struct {
	Inbound
	Clients []ClientInfo `json:"clients"`
	Links   []string     `json:"links"`
	Listen  string       `json:"listen"`
	Network string       `json:"network"`
	TLS     string       `json:"tls"`
}

type ClientInfo struct {
	Email  string `json:"email"`
	ID     string `json:"id"`
	Enable bool   `json:"enable"`
}

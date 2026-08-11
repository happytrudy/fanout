package main

import "testing"

func TestValidateCred(t *testing.T) {
	ok := []SocksCred{
		{User: "fo123", Pass: "abcDEF234"},
		{User: "u", Pass: "p"},
	}
	for _, c := range ok {
		if err := validateCred(c); err != nil {
			t.Errorf("应通过 %+v: %v", c, err)
		}
	}
	bad := []SocksCred{
		{User: "", Pass: "x"},
		{User: "x", Pass: ""},
		{User: "a:b", Pass: "x"},
		{User: "a b", Pass: "x"},
		{User: "x", Pass: "a@b"},
		{User: "x", Pass: "a/b"},
	}
	for _, c := range bad {
		if err := validateCred(c); err == nil {
			t.Errorf("应拒绝 %+v", c)
		}
	}
}

func TestSocksURL(t *testing.T) {
	got := socksURL("1.2.3.4", 20000, SocksCred{User: "u", Pass: "p"})
	if got != "socks5://u:p@1.2.3.4:20000" {
		t.Fatalf("带凭据 URL 不对: %s", got)
	}
	got = socksURL("1.2.3.4", 20000, SocksCred{})
	if got != "socks5://1.2.3.4:20000" {
		t.Fatalf("无凭据 URL 不对: %s", got)
	}
}

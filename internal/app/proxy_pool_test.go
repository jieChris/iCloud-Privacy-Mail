package app

import (
	"testing"
)

func TestParseSOCKS5ProxyURLAcceptsCompactAndExplicitForms(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		address  string
		username string
		password string
	}{
		{
			name:     "compact",
			raw:      "user:pass@example.com:9000",
			address:  "example.com:9000",
			username: "user",
			password: "pass",
		},
		{
			name:     "socks5",
			raw:      "socks5://user:p%40ss@example.com:9000",
			address:  "example.com:9000",
			username: "user",
			password: "p@ss",
		},
		{
			name:     "socks5h ipv6",
			raw:      "socks5h://user:pass@[2001:db8::1]:1080",
			address:  "[2001:db8::1]:1080",
			username: "user",
			password: "pass",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address, auth, err := parseSOCKS5ProxyURL(tt.raw)
			if err != nil {
				t.Fatalf("parse proxy: %v", err)
			}
			if address != tt.address {
				t.Fatalf("address = %q, want %q", address, tt.address)
			}
			if auth == nil || auth.User != tt.username || auth.Password != tt.password {
				t.Fatalf("auth = %#v, want %q/%q", auth, tt.username, tt.password)
			}
		})
	}
}

func TestParseSOCKS5ProxyURLRejectsInvalidPort(t *testing.T) {
	for _, raw := range []string{
		"user:pass@example.com:0",
		"user:pass@example.com:65536",
		"user:pass@example.com:not-a-port",
		"user:pass@example.com",
		"http://user:pass@example.com:9000",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := parseSOCKS5ProxyURL(raw); err == nil {
				t.Fatalf("expected %q to be rejected", raw)
			}
		})
	}
}

func TestProxyPoolForgetRemovesStickyAssignment(t *testing.T) {
	p, err := NewProxyPool(ProxyPoolConfig{
		Enabled: true,
		Proxies: []ProxyEndpoint{{ID: "proxy-001", URL: "socks5://user:pass@example.com:9000"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Assign("owner:apple@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := p.Assignment("owner:apple@example.com"); got == "" {
		t.Fatal("proxy assignment was not recorded")
	}
	p.Forget("owner:apple@example.com")
	if got := p.Assignment("owner:apple@example.com"); got != "" {
		t.Fatalf("proxy assignment after Forget = %q, want empty", got)
	}
}

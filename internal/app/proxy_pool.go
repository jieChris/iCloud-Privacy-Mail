package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	defaultProxyHealthTimeout   = 12 * time.Second
	defaultProxyFailureCooldown = 2 * time.Minute
	defaultProxyMaxFailures     = 2
)

// ProxyEndpoint is deliberately kept in configuration. Credentials are never
// copied into sessions, API responses, logs, or runtime exports.
type ProxyEndpoint struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type ProxyPoolConfig struct {
	Enabled              bool            `json:"enabled"`
	Strategy             string          `json:"strategy"`
	Proxies              []ProxyEndpoint `json:"proxies"`
	HealthCheckURL       string          `json:"health_check_url"`
	HealthCheckTimeoutMS int             `json:"health_check_timeout_ms"`
	FailureCooldownMS    int             `json:"failure_cooldown_ms"`
	MaxFailures          int             `json:"max_failures"`
}

type proxyPoolEntry struct {
	config           ProxyEndpoint
	address          string
	auth             *proxy.Auth
	client           *http.Client
	failures         int
	quarantinedUntil time.Time
}

// ProxyPool uses the established golang.org/x/net/proxy SOCKS5 dialer and
// owns only pool policy: validation, sticky assignment, and rotation.
type ProxyPool struct {
	mu                 sync.Mutex
	enabled            bool
	strategy           string
	healthCheckURL     string
	healthCheckTimeout time.Duration
	failureCooldown    time.Duration
	maxFailures        int
	entries            map[string]*proxyPoolEntry
	order              []string
	next               int
	assignments        map[string]string
}

func NewProxyPool(cfg ProxyPoolConfig) (*ProxyPool, error) {
	p := &ProxyPool{
		enabled:            cfg.Enabled,
		strategy:           strings.ToLower(strings.TrimSpace(cfg.Strategy)),
		healthCheckURL:     strings.TrimSpace(cfg.HealthCheckURL),
		healthCheckTimeout: durationFromMS(cfg.HealthCheckTimeoutMS, defaultProxyHealthTimeout),
		failureCooldown:    durationFromMS(cfg.FailureCooldownMS, defaultProxyFailureCooldown),
		maxFailures:        cfg.MaxFailures,
		entries:            make(map[string]*proxyPoolEntry),
		assignments:        make(map[string]string),
	}
	if p.strategy == "" {
		p.strategy = "round_robin"
	}
	if p.maxFailures <= 0 {
		p.maxFailures = defaultProxyMaxFailures
	}
	if !p.enabled {
		return p, nil
	}
	for index, endpoint := range cfg.Proxies {
		endpoint.ID = strings.TrimSpace(endpoint.ID)
		if endpoint.ID == "" {
			endpoint.ID = fmt.Sprintf("proxy-%03d", index+1)
		}
		if _, exists := p.entries[endpoint.ID]; exists {
			return nil, fmt.Errorf("duplicate proxy id %q", endpoint.ID)
		}
		address, auth, err := parseSOCKS5ProxyURL(endpoint.URL)
		if err != nil {
			return nil, fmt.Errorf("proxy %s: %w", endpoint.ID, err)
		}
		p.entries[endpoint.ID] = &proxyPoolEntry{config: endpoint, address: address, auth: auth}
		p.order = append(p.order, endpoint.ID)
	}
	if len(p.order) == 0 {
		return nil, errors.New("proxy pool is enabled but contains no usable proxies")
	}
	return p, nil
}

func durationFromMS(value int, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

func parseSOCKS5ProxyURL(raw string) (string, *proxy.Auth, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, errors.New("empty proxy URL")
	}
	// The management UI accepts the compact account:password@host:port form.
	// Normalize the common full-width separator before handing the value to the
	// URL parser; credentials containing reserved characters should be URL-encoded.
	raw = strings.ReplaceAll(raw, "\uFF1A", ":")
	if strings.ContainsAny(raw, "\r\n\t") {
		return "", nil, errors.New("proxy URL must be a single line")
	}
	if !strings.Contains(raw, "://") {
		raw = "socks5h://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", nil, errors.New("invalid proxy URL")
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "socks5" && scheme != "socks5h" {
		return "", nil, fmt.Errorf("proxy scheme must be socks5 or socks5h")
	}
	if u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, errors.New("proxy URL must contain only host, port, and optional credentials")
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if host == "" {
		return "", nil, errors.New("proxy URL must include a host")
	}
	if port == "" {
		return "", nil, errors.New("proxy URL must include a port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", nil, errors.New("proxy port must be a number from 1 to 65535")
	}
	auth := (*proxy.Auth)(nil)
	if u.User != nil {
		if strings.TrimSpace(u.User.Username()) == "" {
			return "", nil, errors.New("proxy username cannot be empty")
		}
		password, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: password}
	}
	return net.JoinHostPort(host, port), auth, nil
}

func (p *ProxyPool) usableEntryLocked(id string, now time.Time) (*proxyPoolEntry, bool) {
	entry, ok := p.entries[strings.TrimSpace(id)]
	if !ok || entry == nil {
		return nil, false
	}
	if !entry.quarantinedUntil.IsZero() && now.Before(entry.quarantinedUntil) {
		return entry, false
	}
	if !entry.quarantinedUntil.IsZero() && !now.Before(entry.quarantinedUntil) {
		entry.quarantinedUntil = time.Time{}
		entry.failures = 0
	}
	return entry, true
}

func (p *ProxyPool) Assignment(key string) string {
	if p == nil || !p.enabled {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.assignments[strings.TrimSpace(key)]
}

// Forget removes a sticky account assignment after the account is deleted.
func (p *ProxyPool) Forget(key string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.assignments, strings.TrimSpace(key))
}

// IsConfigured reports whether id belongs to this pool. It does not expose
// the endpoint or its credentials.
func (p *ProxyPool) IsConfigured(id string) bool {
	if p == nil || !p.enabled {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.entries[strings.TrimSpace(id)]
	return ok
}

// IsAvailable reports whether a configured proxy is outside its failure
// quarantine window.
func (p *ProxyPool) IsAvailable(id string) bool {
	if p == nil || !p.enabled {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.usableEntryLocked(strings.TrimSpace(id), time.Now())
	return ok
}

// Assign returns a sticky proxy for an account. New accounts are allocated in
// round-robin order, skipping proxies in their temporary failure quarantine.
func (p *ProxyPool) Assign(key string) (string, error) {
	if p == nil || !p.enabled {
		return "", nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "default"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if current := strings.TrimSpace(p.assignments[key]); current != "" {
		if _, ok := p.usableEntryLocked(current, time.Now()); ok {
			return current, nil
		}
	}
	for offset := 0; offset < len(p.order); offset++ {
		index := (p.next + offset) % len(p.order)
		id := p.order[index]
		if _, ok := p.usableEntryLocked(id, time.Now()); !ok {
			continue
		}
		p.next = (index + 1) % len(p.order)
		p.assignments[key] = id
		return id, nil
	}
	return "", errors.New("all proxies in the pool are temporarily unavailable")
}

// Rotate moves an account to the next healthy proxy. Existing sessions keep
// their current proxy unless the caller explicitly invokes this method.
func (p *ProxyPool) Rotate(key, current string) (string, error) {
	if p == nil || !p.enabled {
		return "", nil
	}
	key = strings.TrimSpace(key)
	p.mu.Lock()
	defer p.mu.Unlock()
	start := 0
	for index, id := range p.order {
		if id == strings.TrimSpace(current) {
			start = index + 1
			break
		}
	}
	for offset := 0; offset < len(p.order); offset++ {
		id := p.order[(start+offset)%len(p.order)]
		if id == strings.TrimSpace(current) && len(p.order) > 1 {
			continue
		}
		if _, ok := p.usableEntryLocked(id, time.Now()); !ok {
			continue
		}
		p.assignments[key] = id
		return id, nil
	}
	return "", errors.New("no alternate proxy is currently available")
}

func (p *ProxyPool) MarkFailure(id string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.entries[strings.TrimSpace(id)]
	if entry == nil {
		return
	}
	entry.failures++
	if entry.failures >= p.maxFailures {
		entry.quarantinedUntil = time.Now().Add(p.failureCooldown)
	}
}

func (p *ProxyPool) MarkSuccess(id string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry := p.entries[strings.TrimSpace(id)]; entry != nil {
		entry.failures = 0
		entry.quarantinedUntil = time.Time{}
	}
}

func (p *ProxyPool) HTTPClient(id string) (*http.Client, error) {
	if p == nil || !p.enabled {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("proxy pool is enabled but no proxy id was assigned")
	}
	p.mu.Lock()
	entry, ok := p.entries[id]
	if ok && entry.client != nil {
		client := entry.client
		p.mu.Unlock()
		return client, nil
	}
	if !ok {
		p.mu.Unlock()
		return nil, fmt.Errorf("proxy %q is not configured", id)
	}
	auth := entry.auth
	address := entry.address
	p.mu.Unlock()

	dialer, err := proxy.SOCKS5("tcp", address, auth, &net.Dialer{
		Timeout:   20 * time.Second,
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		DialContext:           proxyDialContext(dialer),
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	p.mu.Lock()
	if current := p.entries[id]; current != nil && current.client == nil {
		current.client = client
	} else if current != nil && current.client != nil {
		client = current.client
	}
	p.mu.Unlock()
	return client, nil
}

func proxyDialContext(dialer proxy.Dialer) func(context.Context, string, string) (net.Conn, error) {
	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		result := make(chan struct {
			conn net.Conn
			err  error
		}, 1)
		go func() {
			conn, err := dialer.Dial(network, address)
			result <- struct {
				conn net.Conn
				err  error
			}{conn: conn, err: err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case item := <-result:
			return item.conn, item.err
		}
	}
}

func (p *ProxyPool) HealthCheck(ctx context.Context, id string) error {
	if p == nil || !p.enabled {
		return nil
	}
	client, err := p.HTTPClient(id)
	if err != nil {
		return err
	}
	checkURL := p.healthCheckURL
	if checkURL == "" {
		checkURL = "https://www.icloud.com/"
	}
	timeout := p.healthCheckTimeout
	if timeout <= 0 {
		timeout = defaultProxyHealthTimeout
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(checkCtx, http.MethodHead, checkURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		p.MarkFailure(id)
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		p.MarkFailure(id)
		return fmt.Errorf("proxy health check returned HTTP %d", resp.StatusCode)
	}
	p.MarkSuccess(id)
	return nil
}

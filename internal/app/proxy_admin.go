package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type adminProxyEndpoint struct {
	ID               string `json:"id"`
	URLMasked        string `json:"url_masked"`
	HasCredentials   bool   `json:"has_credentials"`
	Available        bool   `json:"available"`
	FailureCount     int    `json:"failure_count"`
	QuarantinedUntil string `json:"quarantined_until,omitempty"`
}

func cloneProxyPoolConfig(in ProxyPoolConfig) ProxyPoolConfig {
	out := in
	out.Proxies = append([]ProxyEndpoint(nil), in.Proxies...)
	return out
}

func (s *Server) currentProxyPoolConfig() ProxyPoolConfig {
	if s == nil {
		return ProxyPoolConfig{}
	}
	s.proxyPoolMu.RLock()
	defer s.proxyPoolMu.RUnlock()
	return cloneProxyPoolConfig(s.cfg.AppleProxyPool)
}

func (s *Server) proxyPoolSummaries() []adminProxyEndpoint {
	if s == nil {
		return nil
	}
	s.proxyPoolMu.RLock()
	defer s.proxyPoolMu.RUnlock()
	out := make([]adminProxyEndpoint, 0, len(s.cfg.AppleProxyPool.Proxies))
	now := time.Now()
	if s.proxyPool != nil {
		s.proxyPool.mu.Lock()
		defer s.proxyPool.mu.Unlock()
	}
	for _, endpoint := range s.cfg.AppleProxyPool.Proxies {
		item := adminProxyEndpoint{
			ID:             endpoint.ID,
			URLMasked:      maskProxyURL(endpoint.URL),
			HasCredentials: proxyURLHasCredentials(endpoint.URL),
		}
		if s.proxyPool != nil && s.cfg.AppleProxyPool.Enabled {
			if entry := s.proxyPool.entries[endpoint.ID]; entry != nil {
				item.FailureCount = entry.failures
				item.Available = !s.proxyPool.enabled || entry.quarantinedUntil.IsZero() || !now.Before(entry.quarantinedUntil)
				if !entry.quarantinedUntil.IsZero() && now.Before(entry.quarantinedUntil) {
					item.QuarantinedUntil = formatTime(entry.quarantinedUntil)
				}
			} else {
				item.Available = false
			}
		}
		out = append(out, item)
	}
	return out
}

func maskProxyURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "\uFF1A", ":")
	if !strings.Contains(raw, "://") {
		raw = "socks5h://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "SOCKS5 节点（地址格式异常）"
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "socks5" && scheme != "socks5h" {
		scheme = "socks5h"
	}
	host := u.Hostname()
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	if u.User != nil {
		return scheme + "://***:***@" + host
	}
	return scheme + "://" + host
}

func proxyURLHasCredentials(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "socks5h://" + raw
	}
	u, err := url.Parse(raw)
	return err == nil && u.User != nil && u.User.Username() != ""
}

func validateProxyPoolConfig(cfg ProxyPoolConfig) error {
	strategy := strings.ToLower(strings.TrimSpace(cfg.Strategy))
	if strategy != "" && strategy != "round_robin" {
		return errCode("proxy_strategy_unsupported", "当前只支持 round_robin 代理分配策略", false)
	}
	if strings.TrimSpace(cfg.HealthCheckURL) != "" {
		u, err := url.Parse(strings.TrimSpace(cfg.HealthCheckURL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errCode("proxy_health_url_invalid", "代理健康检查地址必须是有效的 HTTP(S) 地址", false)
		}
	}
	test := cloneProxyPoolConfig(cfg)
	if !test.Enabled && len(test.Proxies) == 0 {
		return nil
	}
	for index, endpoint := range test.Proxies {
		if strings.TrimSpace(endpoint.ID) == "" {
			endpoint.ID = fmt.Sprintf("proxy-%03d", index+1)
		}
		if len(endpoint.ID) > 100 {
			return errCode("proxy_id_invalid", fmt.Sprintf("第 %d 个代理的 ID 不能超过 100 个字符", index+1), false)
		}
		if strings.TrimSpace(endpoint.URL) == "" {
			return errCode("proxy_url_missing", fmt.Sprintf("第 %d 个代理缺少 SOCKS5 地址", index+1), false)
		}
		if _, _, err := parseSOCKS5ProxyURL(endpoint.URL); err != nil {
			return errCode("proxy_url_invalid", fmt.Sprintf("第 %d 个代理地址无效：%s", index+1, err.Error()), false)
		}
	}
	test.Enabled = true
	_, err := NewProxyPool(test)
	return err
}

func safeProxyConfigError(err error) error {
	if err == nil {
		return nil
	}
	var coded codedError
	if errors.As(err, &coded) {
		return err
	}
	return errCode("proxy_pool_invalid", "代理池配置无效，请检查 SOCKS5 地址、端口和认证信息", false)
}

func persistProxyPoolConfig(path string, poolCfg ProxyPoolConfig) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("服务没有配置可写入的 config.json 路径")
	}
	raw := make(map[string]json.RawMessage)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("读取服务配置失败：%w", err)
		}
	}
	encoded, err := json.Marshal(poolCfg)
	if err != nil {
		return err
	}
	raw["apple_proxy_pool"] = encoded
	output, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".proxy.tmp"
	if err := os.WriteFile(tmp, append(output, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EBUSY) {
		_ = os.Remove(tmp)
		return err
	}
	// systemd's ReadWritePaths can expose config.json as a writable mount
	// point. Renaming over that mount returns EBUSY, so update the existing
	// inode in place while retaining its ownership and permissions.
	target, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_, writeErr := target.Write(output)
	if writeErr == nil {
		writeErr = target.Sync()
	}
	closeErr := target.Close()
	_ = os.Remove(tmp)
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (s *Server) applyProxyPoolConfig(poolCfg ProxyPoolConfig) error {
	if err := validateProxyPoolConfig(poolCfg); err != nil {
		return err
	}
	if strings.TrimSpace(poolCfg.Strategy) == "" {
		poolCfg.Strategy = "round_robin"
	}
	poolCfg.Strategy = strings.ToLower(strings.TrimSpace(poolCfg.Strategy))
	pool, err := NewProxyPool(poolCfg)
	if err != nil {
		return err
	}
	s.proxyPoolMu.Lock()
	defer s.proxyPoolMu.Unlock()
	if err := persistProxyPoolConfig(s.cfg.ConfigPath, poolCfg); err != nil {
		if s.logger != nil {
			s.logger.Error("persist Apple proxy pool failed", "err", err)
		}
		return errCode("proxy_pool_persist_failed", "代理池配置保存失败，请检查 config.json 写权限", true)
	}
	s.cfg.AppleProxyPool = cloneProxyPoolConfig(poolCfg)
	s.proxyPool = pool
	s.proxyPoolErr = nil
	return nil
}

func (s *Server) handleAdminProxyPool(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusForbidden, errCode("admin_required", "需要管理员权限", false))
		return
	}
	cfg := s.currentProxyPoolConfig()
	_, poolErr := s.proxyPoolSnapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"success":                 true,
		"enabled":                 cfg.Enabled,
		"strategy":                firstNonEmpty(cfg.Strategy, "round_robin"),
		"health_check_url":        cfg.HealthCheckURL,
		"health_check_timeout_ms": cfg.HealthCheckTimeoutMS,
		"failure_cooldown_ms":     cfg.FailureCooldownMS,
		"max_failures":            cfg.MaxFailures,
		"configured":              poolErr == nil,
		"config_error":            publicProxyConfigError(poolErr),
		"proxies":                 s.proxyPoolSummaries(),
	})
}

func publicProxyConfigError(err error) string {
	if err == nil {
		return ""
	}
	return safeProxyConfigError(err).Error()
}

func (s *Server) handleSaveAdminProxyPool(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusForbidden, errCode("admin_required", "需要管理员权限", false))
		return
	}
	var payload struct {
		Enabled              *bool  `json:"enabled"`
		Strategy             string `json:"strategy"`
		HealthCheckURL       string `json:"health_check_url"`
		HealthCheckTimeoutMS *int   `json:"health_check_timeout_ms"`
		FailureCooldownMS    *int   `json:"failure_cooldown_ms"`
		MaxFailures          *int   `json:"max_failures"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	cfg := s.currentProxyPoolConfig()
	if payload.Enabled != nil {
		cfg.Enabled = *payload.Enabled
	}
	if strings.TrimSpace(payload.Strategy) != "" {
		cfg.Strategy = strings.TrimSpace(payload.Strategy)
	}
	if strings.TrimSpace(payload.HealthCheckURL) != "" {
		cfg.HealthCheckURL = strings.TrimSpace(payload.HealthCheckURL)
	}
	if payload.HealthCheckTimeoutMS != nil {
		cfg.HealthCheckTimeoutMS = *payload.HealthCheckTimeoutMS
	}
	if payload.FailureCooldownMS != nil {
		cfg.FailureCooldownMS = *payload.FailureCooldownMS
	}
	if payload.MaxFailures != nil {
		cfg.MaxFailures = *payload.MaxFailures
	}
	if err := s.applyProxyPoolConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, safeProxyConfigError(err))
		return
	}
	s.initializeProxyAssignments()
	s.writeAdminProxyPoolResponse(w)
}

func (s *Server) writeAdminProxyPoolResponse(w http.ResponseWriter) {
	cfg := s.currentProxyPoolConfig()
	_, poolErr := s.proxyPoolSnapshot()
	writeJSON(w, 200, map[string]any{
		"success":                 true,
		"enabled":                 cfg.Enabled,
		"strategy":                firstNonEmpty(cfg.Strategy, "round_robin"),
		"health_check_url":        cfg.HealthCheckURL,
		"health_check_timeout_ms": cfg.HealthCheckTimeoutMS,
		"failure_cooldown_ms":     cfg.FailureCooldownMS,
		"max_failures":            cfg.MaxFailures,
		"configured":              poolErr == nil,
		"config_error":            publicProxyConfigError(poolErr),
		"proxies":                 s.proxyPoolSummaries(),
	})
}

func (s *Server) handleSaveAdminProxyEndpoint(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, 403, errCode("admin_required", "需要管理员权限", false))
		return
	}
	var payload ProxyEndpoint
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, 400, err)
		return
	}
	payload.ID = strings.TrimSpace(payload.ID)
	payload.URL = strings.TrimSpace(payload.URL)
	if len(payload.ID) > 100 {
		writeError(w, http.StatusBadRequest, errCode("proxy_id_invalid", "代理 ID 不能超过 100 个字符", false))
		return
	}
	cfg := s.currentProxyPoolConfig()
	if payload.ID == "" {
		if payload.URL == "" {
			writeError(w, http.StatusBadRequest, errCode("proxy_url_missing", "新增代理必须填写 SOCKS5 地址", false))
			return
		}
		payload.ID = nextProxyID(cfg.Proxies)
	}
	found := false
	for i := range cfg.Proxies {
		if cfg.Proxies[i].ID != payload.ID {
			continue
		}
		found = true
		if strings.TrimSpace(payload.URL) == "" {
			payload.URL = cfg.Proxies[i].URL
		}
		cfg.Proxies[i] = payload
		break
	}
	if !found {
		if payload.URL == "" {
			writeError(w, http.StatusBadRequest, errCode("proxy_url_missing", "新增代理必须填写 SOCKS5 地址", false))
			return
		}
		cfg.Proxies = append(cfg.Proxies, payload)
	}
	if err := s.applyProxyPoolConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, safeProxyConfigError(err))
		return
	}
	s.initializeProxyAssignments()
	s.writeAdminProxyPoolResponse(w)
}

func nextProxyID(proxies []ProxyEndpoint) string {
	used := make(map[string]struct{}, len(proxies))
	for _, endpoint := range proxies {
		if id := strings.TrimSpace(endpoint.ID); id != "" {
			used[id] = struct{}{}
		}
	}
	for index := 1; ; index++ {
		id := fmt.Sprintf("proxy-%03d", index)
		if _, exists := used[id]; !exists {
			return id
		}
	}
}

type proxyImportLine struct {
	Line  int
	Value string
}

type proxyBatchFailure struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

func splitProxyImportLines(raw string) []proxyImportLine {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]proxyImportLine, 0, len(lines))
	for index, line := range lines {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, proxyImportLine{Line: index + 1, Value: line})
	}
	return out
}

func (s *Server) handleBatchSaveAdminProxyEndpoints(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusForbidden, errCode("admin_required", "需要管理员权限", false))
		return
	}
	var payload struct {
		Text string `json:"text"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	lines := splitProxyImportLines(payload.Text)
	if len(lines) == 0 {
		writeError(w, http.StatusBadRequest, errCode("proxy_batch_empty", "请至少填写一行 SOCKS5 代理地址", false))
		return
	}
	cfg := s.currentProxyPoolConfig()
	failures := make([]proxyBatchFailure, 0)
	imported := 0
	for _, line := range lines {
		raw := line.Value
		if _, _, err := parseSOCKS5ProxyURL(raw); err != nil {
			failures = append(failures, proxyBatchFailure{Line: line.Line, Message: err.Error()})
			continue
		}
		cfg.Proxies = append(cfg.Proxies, ProxyEndpoint{ID: nextProxyID(cfg.Proxies), URL: raw})
		imported++
	}
	if imported == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"success":  false,
			"code":     "proxy_batch_invalid",
			"message":  "没有可导入的有效代理地址",
			"imported": 0,
			"failed":   failures,
		})
		return
	}
	if err := s.applyProxyPoolConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, safeProxyConfigError(err))
		return
	}
	s.initializeProxyAssignments()
	s.writeAdminProxyBatchResponse(w, imported, failures)
}

func (s *Server) writeAdminProxyBatchResponse(w http.ResponseWriter, imported int, failures []proxyBatchFailure) {
	cfg := s.currentProxyPoolConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"message":  fmt.Sprintf("已导入 %d 个代理节点", imported),
		"imported": imported,
		"failed":   failures,
		"proxies":  s.proxyPoolSummaries(),
		"enabled":  cfg.Enabled,
	})
}

func (s *Server) handleDeleteAdminProxy(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusForbidden, errCode("admin_required", "需要管理员权限", false))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	cfg := s.currentProxyPoolConfig()
	filtered := cfg.Proxies[:0]
	found := false
	for _, endpoint := range cfg.Proxies {
		if endpoint.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, endpoint)
	}
	if !found {
		writeError(w, http.StatusNotFound, errCode("proxy_not_found", "代理节点不存在", false))
		return
	}
	cfg.Proxies = filtered
	if err := s.applyProxyPoolConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, safeProxyConfigError(err))
		return
	}
	s.initializeProxyAssignments()
	s.writeAdminProxyPoolResponse(w)
}

func (s *Server) handleTestAdminProxy(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusForbidden, errCode("admin_required", "需要管理员权限", false))
		return
	}
	var payload struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	payload.ID = strings.TrimSpace(payload.ID)
	payload.URL = strings.TrimSpace(payload.URL)
	if payload.URL == "" {
		for _, endpoint := range s.currentProxyPoolConfig().Proxies {
			if endpoint.ID == payload.ID {
				payload.URL = endpoint.URL
				break
			}
		}
	}
	if payload.URL == "" {
		writeError(w, http.StatusBadRequest, errCode("proxy_url_missing", "缺少待测试的 SOCKS5 地址", false))
		return
	}
	if _, _, err := parseSOCKS5ProxyURL(payload.URL); err != nil {
		writeError(w, http.StatusBadRequest, errCode("proxy_url_invalid", "代理地址无效："+err.Error(), false))
		return
	}
	cfg := s.currentProxyPoolConfig()
	cfg.Enabled = true
	cfg.Proxies = []ProxyEndpoint{{ID: firstNonEmpty(payload.ID, "proxy-test"), URL: payload.URL}}
	pool, err := NewProxyPool(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, safeProxyConfigError(err))
		return
	}
	if err := pool.HealthCheck(context.Background(), cfg.Proxies[0].ID); err != nil {
		writeError(w, http.StatusBadGateway, errCode("proxy_test_failed", "代理测试失败，请检查地址、认证信息和网络连通性", true))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "代理连接测试成功", "url_masked": maskProxyURL(payload.URL)})
}

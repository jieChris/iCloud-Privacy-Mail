package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminProxyPoolCRUDPersistsWithoutExposingCredentials(t *testing.T) {
	store := newTestStore(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"port":8787,"apple_proxy_pool":{"enabled":false,"strategy":"round_robin","proxies":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{
		ConfigPath: configPath,
		AppleProxyPool: ProxyPoolConfig{
			Enabled:  false,
			Strategy: "round_robin",
		},
	}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")

	response := doProxyAdminRequest(t, handler, adminCookie, http.MethodPost, "/api/admin/proxy-pool/proxies", `{"id":"proxy-test-01","url":"socks5h://secret-user:secret-pass@127.0.0.1:9000"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("add proxy = %d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "secret-user") || strings.Contains(response.Body.String(), "secret-pass") {
		t.Fatalf("proxy credentials leaked in response: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "***:***@127.0.0.1:9000") {
		t.Fatalf("masked proxy URL missing from response: %s", response.Body.String())
	}

	var config map[string]any
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	pool, ok := config["apple_proxy_pool"].(map[string]any)
	if !ok || pool["proxies"] == nil || !strings.Contains(string(data), "secret-pass") {
		t.Fatalf("proxy config was not persisted: %s", data)
	}

	response = doProxyAdminRequest(t, handler, adminCookie, http.MethodPost, "/api/admin/proxy-pool/proxies", `{"id":"proxy-test-01","url":""}`)
	if response.Code != http.StatusOK {
		t.Fatalf("preserve proxy credentials = %d body=%s", response.Code, response.Body.String())
	}
	data, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "secret-pass") {
		t.Fatalf("empty update replaced stored proxy credentials: %s", data)
	}

	response = doProxyAdminRequest(t, handler, adminCookie, http.MethodPut, "/api/admin/proxy-pool", `{"enabled":false}`)
	if response.Code != http.StatusOK {
		t.Fatalf("disable proxy pool = %d body=%s", response.Code, response.Body.String())
	}
	response = doProxyAdminRequest(t, handler, adminCookie, http.MethodDelete, "/api/admin/proxy-pool/proxy-test-01", "")
	if response.Code != http.StatusOK {
		t.Fatalf("delete proxy = %d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminProxyPoolRejectsNonAdmin(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	_, _ = registerTestUser(t, handler, "admin", "admin123")
	userCookie, _ := registerTestUser(t, handler, "normal", "normal123")
	response := doProxyAdminRequest(t, handler, userCookie, http.MethodGet, "/api/admin/proxy-pool", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("non-admin proxy pool status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminProxyPoolAllowsAutomaticIDAndBatchImport(t *testing.T) {
	store := newTestStore(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"port":8787,"apple_proxy_pool":{"enabled":false,"strategy":"round_robin","proxies":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{
		ConfigPath:     configPath,
		AppleProxyPool: ProxyPoolConfig{Strategy: "round_robin"},
	}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")

	response := doProxyAdminRequest(t, handler, adminCookie, http.MethodPost, "/api/admin/proxy-pool/proxies", `{"url":"user:pass@example.com:9000"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("automatic ID add = %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"id":"proxy-001"`) {
		t.Fatalf("automatic ID missing from response: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "user") || strings.Contains(response.Body.String(), "pass") {
		t.Fatalf("credentials leaked in response: %s", response.Body.String())
	}

	response = doProxyAdminRequest(t, handler, adminCookie, http.MethodPost, "/api/admin/proxy-pool/proxies/batch", `{"text":"# first\nuser2:pass2@example.net:9001\n\ninvalid\nuser3:pass3@example.org:9002"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("batch import = %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"imported":2`) || !strings.Contains(response.Body.String(), `"line":4`) {
		t.Fatalf("batch result missing counts or original line number: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "pass2") || strings.Contains(response.Body.String(), "pass3") {
		t.Fatalf("batch credentials leaked in response: %s", response.Body.String())
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "user2") || !strings.Contains(string(data), "user3") {
		t.Fatalf("batch proxies were not persisted: %s", data)
	}
}

func doProxyAdminRequest(t *testing.T, handler http.Handler, cookie *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	record := httptest.NewRecorder()
	handler.ServeHTTP(record, req)
	return record
}

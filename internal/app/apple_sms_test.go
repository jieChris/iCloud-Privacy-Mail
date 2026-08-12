package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAppleSMSLink(t *testing.T) {
	for _, raw := range []string{
		"+19858008317|http://a.62-us.com/api/get_sms?key=secret-key",
		"+19858008317----http://a.62-us.com/api/get_sms?key=secret-key",
	} {
		link, err := ParseAppleSMSLink(raw)
		if err != nil {
			t.Fatalf("ParseAppleSMSLink(%q): %v", raw, err)
		}
		if link.PhoneNumber != "+19858008317" || link.URL == "" {
			t.Fatalf("link = %+v", link)
		}
	}
	if _, err := ParseAppleSMSLink("19858008317|http://example.com/code"); !isCodedError(err, "invalid_sms_phone") {
		t.Fatalf("invalid phone error = %v", err)
	}
	if _, err := ParseAppleSMSLink("+19858008317|ftp://example.com/code"); !isCodedError(err, "invalid_sms_link") {
		t.Fatalf("invalid URL error = %v", err)
	}
}

func TestNormalizeAppleTwoFactorMethodDefaultsToPhone(t *testing.T) {
	if got := normalizeAppleTwoFactorMethod(""); got != appleTwoFactorMethodPhone {
		t.Fatalf("empty method = %q, want %q", got, appleTwoFactorMethodPhone)
	}
	if got := normalizeAppleTwoFactorMethod("unknown"); got != appleTwoFactorMethodPhone {
		t.Fatalf("unknown method = %q, want %q", got, appleTwoFactorMethodPhone)
	}
	if got := normalizeAppleTwoFactorMethod("trusted_device"); got != appleTwoFactorMethodTrustedDevice {
		t.Fatalf("explicit trusted device = %q, want %q", got, appleTwoFactorMethodTrustedDevice)
	}
}

func TestDefaultCreateSettingsUsePhoneTwoFactor(t *testing.T) {
	settings := defaultCreateSettings("owner-1")
	if settings.AppleAccountTwoFactorMethod != appleTwoFactorMethodPhone {
		t.Fatalf("Apple Account default method = %q, want %q", settings.AppleAccountTwoFactorMethod, appleTwoFactorMethodPhone)
	}
	if settings.ICloudWebTwoFactorMethod != appleTwoFactorMethodPhone {
		t.Fatalf("iCloud Web default method = %q, want %q", settings.ICloudWebTwoFactorMethod, appleTwoFactorMethodPhone)
	}
}

func TestFetchAppleSMSCodeParsesJSONAndPendingResponse(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			_, _ = w.Write([]byte(`{"data":{"message":"Apple 验证码：246810"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"等待短信"}`))
	}))
	defer ts.Close()
	link := AppleSMSLink{PhoneNumber: "+19858008317", URL: ts.URL + "/code?key=secret-key"}
	code, err := fetchAppleSMSCodeWithClient(context.Background(), ts.Client(), link)
	if err != nil || code != "246810" {
		t.Fatalf("code = %q err = %v, want 246810", code, err)
	}
	_, err = fetchAppleSMSCodeWithClient(context.Background(), ts.Client(), link)
	if !isCodedError(err, "apple_sms_code_pending") {
		t.Fatalf("pending error = %v, want apple_sms_code_pending", err)
	}
}

func TestAppleLoginCredentialsAreNotPublicOrExported(t *testing.T) {
	credentials, err := newAppleLoginCredentials(
		"user@example.com",
		"password-secret",
		"+19858008317|http://a.62-us.com/api/get_sms?key=url-secret",
		appleTwoFactorMethodPhone,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := withAppleLoginCredentials(ICloudSession{AppleID: "user@example.com"}, credentials)
	publicRaw, err := json.Marshal(publicSession(&session))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicRaw), "password-secret") || strings.Contains(string(publicRaw), "url-secret") {
		t.Fatalf("public session leaked credentials: %s", publicRaw)
	}
	exportRaw, err := json.Marshal(sanitizeICloudSessionForExport(session))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exportRaw), "password-secret") || strings.Contains(string(exportRaw), "url-secret") || strings.Contains(string(exportRaw), "apple_login") {
		t.Fatalf("export session leaked credentials: %s", exportRaw)
	}
	merged := mergeICloudSession(session, ICloudSession{AppleID: session.AppleID})
	if merged.AppleLogin == nil || merged.AppleLogin.Password != "password-secret" {
		t.Fatalf("merge lost persisted credentials: %+v", merged.AppleLogin)
	}
}

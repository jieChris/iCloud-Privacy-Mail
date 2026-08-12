package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	appleSMSFetchTimeout = 8 * time.Second
	appleSMSPollInterval = 2 * time.Second
	appleSMSWaitTimeout  = 90 * time.Second
)

type AppleSMSLink struct {
	PhoneNumber string
	URL         string
}

var appleSMSPhonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

func ParseAppleSMSLink(raw string) (AppleSMSLink, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AppleSMSLink{}, nil
	}
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(raw, "----", 2)
	}
	if len(parts) != 2 {
		return AppleSMSLink{}, errCode("invalid_sms_link", "短信链接格式应为：手机号|短信链接", false)
	}
	phone := normalizeAppleSMSPhone(parts[0])
	if !appleSMSPhonePattern.MatchString(phone) {
		return AppleSMSLink{}, errCode("invalid_sms_phone", "手机号必须是国际格式，例如 +19858008317", false)
	}
	parsed, err := url.Parse(strings.TrimSpace(parts[1]))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return AppleSMSLink{}, errCode("invalid_sms_link", "短信链接必须是完整的 http 或 https 地址", false)
	}
	return AppleSMSLink{PhoneNumber: phone, URL: parsed.String()}, nil
}

func normalizeAppleSMSPhone(value string) string {
	value = strings.TrimSpace(value)
	value = strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(value)
	return value
}

func (l AppleSMSLink) Empty() bool {
	return strings.TrimSpace(l.URL) == ""
}

func (l AppleSMSLink) String() string {
	if l.Empty() {
		return ""
	}
	return strings.TrimSpace(l.PhoneNumber) + "|" + strings.TrimSpace(l.URL)
}

func FetchAppleSMSCode(ctx context.Context, link AppleSMSLink) (string, error) {
	return fetchAppleSMSCodeWithClient(ctx, &http.Client{Timeout: appleSMSFetchTimeout}, link)
}

func fetchAppleSMSCodeWithClient(ctx context.Context, client *http.Client, link AppleSMSLink) (string, error) {
	if link.Empty() {
		return "", errCode("apple_sms_link_missing", "未配置手机号短信链接", false)
	}
	if client == nil {
		client = &http.Client{Timeout: appleSMSFetchTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link.URL, nil)
	if err != nil {
		return "", errCode("apple_sms_fetch_failed", "读取短信链接失败", true)
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "icloud-privacy-mail/"+currentVersionInfo().Version)
	resp, err := client.Do(req)
	if err != nil {
		return "", errCode("apple_sms_fetch_failed", "读取短信链接失败", true)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", errCode("apple_sms_fetch_failed", "读取短信链接响应失败", true)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errCode("apple_sms_fetch_failed", fmt.Sprintf("短信链接返回 HTTP %d", resp.StatusCode), true)
	}
	if code := extractAppleSMSCode(body); code != "" {
		return code, nil
	}
	return "", errCode("apple_sms_code_pending", "短信验证码尚未到达", true)
}

func waitAppleSMSCode(ctx context.Context, client *http.Client, link AppleSMSLink, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = appleSMSWaitTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		code, err := fetchAppleSMSCodeWithClient(waitCtx, client, link)
		if err == nil {
			return code, nil
		}
		lastErr = err
		if waitCtx.Err() != nil {
			break
		}
		timer := time.NewTimer(appleSMSPollInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errCode("apple_sms_code_pending", "短信验证码尚未到达", true)
}

func extractAppleSMSCode(data []byte) string {
	var payload any
	if json.Unmarshal(data, &payload) == nil {
		if code := findAppleSMSCode(payload, 0); code != "" {
			return code
		}
	}
	return extractOTP(string(data))
}

func findAppleSMSCode(value any, depth int) string {
	if depth > 12 {
		return ""
	}
	switch item := value.(type) {
	case string:
		if validOTP(strings.TrimSpace(item)) {
			return strings.TrimSpace(item)
		}
		return extractOTP(item)
	case []any:
		for _, child := range item {
			if code := findAppleSMSCode(child, depth+1); code != "" {
				return code
			}
		}
	case map[string]any:
		priority := []string{"code", "otp", "sms_code", "smsCode", "verificationCode", "securityCode", "message", "text", "content", "data", "result"}
		for _, key := range priority {
			if child, ok := item[key]; ok {
				if code := findAppleSMSCode(child, depth+1); code != "" {
					return code
				}
			}
		}
		for key, child := range item {
			if strings.EqualFold(key, "phone") || strings.Contains(strings.ToLower(key), "phone") {
				continue
			}
			if code := findAppleSMSCode(child, depth+1); code != "" {
				return code
			}
		}
	}
	return ""
}

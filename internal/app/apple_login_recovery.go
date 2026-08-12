package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

func newAppleLoginCredentials(appleID, password, smsRaw, method string) (*AppleLoginCredentials, error) {
	appleID = strings.ToLower(strings.TrimSpace(appleID))
	if appleID == "" || strings.TrimSpace(password) == "" {
		return nil, errCode("apple_credentials_missing", "缺少 Apple ID 或密码", false)
	}
	link, err := ParseAppleSMSLink(smsRaw)
	if err != nil {
		return nil, err
	}
	return &AppleLoginCredentials{
		AppleID:         appleID,
		Password:        password,
		PhoneNumber:     link.PhoneNumber,
		SMSLink:         link.String(),
		TwoFactorMethod: normalizeAppleTwoFactorMethod(method),
		UpdatedAt:       time.Now(),
	}, nil
}

func appleLoginCredentialsForSession(session ICloudSession) (*AppleLoginCredentials, bool) {
	if session.AppleLogin == nil || strings.TrimSpace(session.AppleLogin.Password) == "" {
		return nil, false
	}
	credentials := *session.AppleLogin
	credentials.AppleID = strings.ToLower(strings.TrimSpace(firstNonEmpty(credentials.AppleID, session.AppleID)))
	credentials.ProxyID = strings.TrimSpace(firstNonEmpty(credentials.ProxyID, session.ProxyID))
	credentials.TwoFactorMethod = normalizeAppleTwoFactorMethod(credentials.TwoFactorMethod)
	if strings.TrimSpace(credentials.SMSLink) != "" {
		if link, err := ParseAppleSMSLink(credentials.SMSLink); err == nil {
			credentials.PhoneNumber = link.PhoneNumber
			credentials.SMSLink = link.String()
		}
	}
	return &credentials, true
}

func withAppleLoginCredentials(session ICloudSession, credentials *AppleLoginCredentials) ICloudSession {
	session.AppleLogin = cloneAppleLoginCredentials(credentials)
	if credentials != nil {
		session.ProxyID = firstNonEmpty(session.ProxyID, credentials.ProxyID)
	}
	return session
}

func credentialsFromPending(pending appleAuthPending) *AppleLoginCredentials {
	return cloneAppleLoginCredentials(pending.Credentials)
}

func pendingSMSLink(pending appleAuthPending) (AppleSMSLink, error) {
	if pending.Credentials == nil {
		return AppleSMSLink{}, errCode("apple_sms_link_missing", "未配置手机号短信链接", false)
	}
	return ParseAppleSMSLink(pending.Credentials.SMSLink)
}

func (s *Server) handleFetchICloudProtocol2FACode(w http.ResponseWriter, r *http.Request) {
	s.handleFetchPendingSMSCode(w, r, s.icloudProtocolLogins)
}

func (s *Server) handleFetchAppleAccount2FACode(w http.ResponseWriter, r *http.Request) {
	s.handleFetchPendingSMSCode(w, r, s.appleAccountLogins)
}

func (s *Server) handleFetchPendingSMSCode(w http.ResponseWriter, r *http.Request, store *appleAuthPendingStore) {
	var payload struct {
		PendingID string `json:"pending_id"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pending, ok := store.get(payload.PendingID)
	if !ok {
		writeError(w, http.StatusBadRequest, errCode("apple_login_pending_expired", "待验证登录已过期，请重新输入账号密码发起登录", true))
		return
	}
	link, err := pendingSMSLink(pending)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	code, err := FetchAppleSMSCode(r.Context(), link)
	if err != nil {
		if isCodedError(err, "apple_sms_code_pending") {
			writeJSON(w, http.StatusOK, map[string]any{
				"success": false,
				"pending": true,
				"code":    "",
				"message": "短信验证码尚未到达",
			})
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"pending": false,
		"code":    code,
	})
}

func codeForPending(ctx context.Context, client appleAuthLoginClient, pending appleAuthPending, code string) (string, error) {
	code = strings.TrimSpace(code)
	if code != "" {
		return code, nil
	}
	link, err := pendingSMSLink(pending)
	if err != nil {
		return "", errCode("invalid_2fa_code", "请输入 6 位验证码，或先配置手机号短信链接", false)
	}
	var waitClient *http.Client
	if client != nil {
		waitClient = client.HTTPClient()
	}
	return waitAppleSMSCode(ctx, waitClient, link, appleSMSWaitTimeout)
}

func isAppleAccountManage502(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "http 502") &&
		(strings.Contains(lower, "刷新管理 token") || strings.Contains(lower, "account/manage"))
}

func (s *Server) fallbackAppleAccountToICloudWeb(ctx context.Context, ownerID string, credentials *AppleLoginCredentials) (ICloudSession, appleAuthStartResult, error) {
	if credentials == nil || strings.TrimSpace(credentials.Password) == "" {
		return ICloudSession{}, appleAuthStartResult{}, errCode("apple_auto_relogin_unavailable", "未保存 Apple 账号密码，无法回退旧接口登录", true)
	}
	ownerID = strings.TrimSpace(ownerID)
	appleID := strings.ToLower(strings.TrimSpace(credentials.AppleID))
	for _, existing := range s.sessionsForOwner(ownerID, "") {
		if !iCloudWebLoginSaved(existing) || !strings.EqualFold(strings.TrimSpace(existing.AppleID), appleID) {
			continue
		}
		existing, err := s.ensureSessionProxy(existing)
		if err != nil {
			continue
		}
		checked, err := s.verifyAppleLoginSession(ctx, existing, LoginStateICloudWeb)
		if err != nil {
			continue
		}
		checked.OwnerID = ownerID
		checked.AccountID = existing.AccountID
		checked = withAppleLoginCredentials(checked, credentials)
		checked.LastCheckedAt = time.Now()
		checked.LastCheckOK = true
		checked.LastStatusMessage = "新接口管理接口不可用，已复用旧接口登录态"
		return checked, appleAuthStartResult{}, nil
	}

	client, proxyID, err := s.newAppleAuthClientForAccount(ownerID, appleID, credentials.ProxyID)
	if err != nil {
		return ICloudSession{}, appleAuthStartResult{}, err
	}
	credentials.ProxyID = proxyID
	result, err := client.StartLogin(
		ctx,
		credentials.AppleID,
		credentials.Password,
		s.cfg.ICloudDefaultHost,
		s.cfg.ICloudClientID,
		s.icloudProtocolLogins,
		credentials.TwoFactorMethod,
	)
	if err != nil {
		return ICloudSession{}, appleAuthStartResult{}, err
	}
	if result.Needs2FA {
		if !s.icloudProtocolLogins.setCredentials(result.PendingID, credentials) {
			return ICloudSession{}, appleAuthStartResult{}, errCode("apple_login_pending_expired", "旧接口回退登录待验证状态已失效", true)
		}
		return ICloudSession{}, result, nil
	}
	result.Session = withSessionProxy(withAppleLoginCredentials(result.Session, credentials), proxyID)
	result.Session.OwnerID = ownerID
	checked, err := s.verifyAppleLoginSession(ctx, result.Session, LoginStateICloudWeb)
	if err != nil {
		return ICloudSession{}, appleAuthStartResult{}, err
	}
	checked.OwnerID = ownerID
	return checked, result, nil
}

func (s *Server) autoReloginICloudWebFallback(ctx context.Context, session ICloudSession, credentials *AppleLoginCredentials) (ICloudSession, error) {
	recovered, result, err := s.fallbackAppleAccountToICloudWeb(ctx, session.OwnerID, credentials)
	if err != nil {
		return session, err
	}
	if result.Needs2FA {
		pending, ok := s.icloudProtocolLogins.get(result.PendingID)
		if !ok {
			return session, errCode("apple_login_pending_expired", "旧接口自动回退登录待验证状态已失效", true)
		}
		client, proxyID, clientErr := s.newAppleAuthClientForAccount(session.OwnerID, credentials.AppleID, firstNonEmpty(credentials.ProxyID, session.ProxyID))
		if clientErr != nil {
			return session, clientErr
		}
		credentials.ProxyID = proxyID
		for attempt := 1; attempt <= 3; attempt++ {
			code, codeErr := codeForPending(ctx, client, pending, "")
			if codeErr != nil {
				s.icloudProtocolLogins.delete(result.PendingID)
				return session, codeErr
			}
			recovered, err = client.Submit2FA(ctx, pending, code)
			if err == nil {
				s.icloudProtocolLogins.delete(result.PendingID)
				recovered = withSessionProxy(recovered, proxyID)
				recovered, err = s.verifyAppleLoginSession(ctx, recovered, LoginStateICloudWeb)
				if err != nil {
					return session, err
				}
				break
			}
			if !isCodedError(err, "apple_2fa_failed") && !isCodedError(err, "invalid_2fa_code") {
				s.icloudProtocolLogins.delete(result.PendingID)
				return session, err
			}
			if attempt == 3 {
				s.icloudProtocolLogins.delete(result.PendingID)
				return session, err
			}
			if err := waitAppleLoginRetry(ctx); err != nil {
				s.icloudProtocolLogins.delete(result.PendingID)
				return session, err
			}
		}
	}
	recovered.OwnerID = session.OwnerID
	recovered.AccountID = firstNonEmpty(recovered.AccountID, session.AccountID)
	recovered = withAppleLoginCredentials(recovered, credentials)
	recovered.LastCheckedAt = time.Now()
	recovered.LastCheckOK = true
	recovered.LastStatusMessage = "新接口管理接口不可用，已自动回退旧接口登录"
	return mergeICloudSession(withSessionProxy(session, credentials.ProxyID), recovered), nil
}

func (s *Server) verifyAppleLoginSession(ctx context.Context, session ICloudSession, kind string) (ICloudSession, error) {
	var err error
	session, err = s.ensureSessionProxy(session)
	if err != nil {
		return session, err
	}
	client, err := s.newICloudClientForSession(session)
	if err != nil {
		return session, err
	}
	return verifyAppleLoginSessionWithClient(ctx, client, session, kind)
}

func verifyAppleLoginSession(ctx context.Context, session ICloudSession, kind string) (ICloudSession, error) {
	return verifyAppleLoginSessionWithClient(ctx, NewICloudClient(), session, kind)
}

func verifyAppleLoginSessionWithClient(ctx context.Context, client *ICloudClient, session ICloudSession, kind string) (ICloudSession, error) {
	now := time.Now()
	switch kind {
	case LoginStateAppleAccount:
		state, ok := appleAccountLoginState(session)
		if !ok {
			return session, errCode("apple_login_state_check_failed", "新接口登录成功但未生成可用的 Apple Account 登录态", true)
		}
		checked, err := client.KeepAliveAppleAccountManageState(ctx, state)
		if err != nil {
			return session, errCode("apple_login_state_check_failed", "新接口登录成功但登录态检测失败："+err.Error(), true)
		}
		checked.LastCheckedAt = now
		checked.LastCheckOK = true
		checked.LastStatusMessage = "新接口登录态检测正常"
		session = withAppleAccountLoginState(session, checked)
	case LoginStateICloudWeb:
		if !iCloudWebLoginSaved(session) {
			return session, errCode("apple_login_state_check_failed", "旧接口登录成功但未生成可用的 iCloud 登录态", true)
		}
		validated, err := client.ValidateICloudWebSession(ctx, session)
		if err != nil {
			return session, errCode("apple_login_state_check_failed", "旧接口登录成功但登录态检测失败："+err.Error(), true)
		}
		session = validated
		state, _ := iCloudWebLoginState(session)
		state.LastCheckedAt = now
		state.LastCheckOK = true
		state.LastStatusMessage = "旧接口登录态检测正常"
		session = withICloudWebLoginState(session, state)
	default:
		return session, errCode("apple_login_state_check_failed", "未知 Apple 登录接口，无法检测登录态", false)
	}
	session.LastCheckedAt = now
	session.LastCheckOK = true
	session.LastStatusMessage = "Apple 登录态检测正常"
	return session, nil
}

func shouldAutoRelogin(err error) bool {
	if err == nil {
		return false
	}
	if isCodedError(err, "apple_account_auth_failed") || isCodedError(err, "icloud_validate_failed") || isCodedError(err, "icloud_session_missing") {
		return true
	}
	lower := strings.ToLower(err.Error())
	for _, marker := range []string{
		"http 401",
		"http 403",
		"authentication failed",
		"session expired",
		"session has expired",
		"登录态已失效",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (s *Server) autoReloginSession(ctx context.Context, session ICloudSession) (ICloudSession, error) {
	return s.autoReloginSessionKind(ctx, session, "")
}

func (s *Server) autoReloginSessionKind(ctx context.Context, session ICloudSession, preferredKind string) (ICloudSession, error) {
	credentials, ok := appleLoginCredentialsForSession(session)
	if !ok {
		return session, errCode("apple_auto_relogin_unavailable", "未保存 Apple 账号密码，无法自动重登录", true)
	}
	state, hasAppleAccount := appleAccountLoginState(session)
	if preferredKind == LoginStateICloudWeb && iCloudWebLoginSaved(session) {
		hasAppleAccount = false
	}
	if !hasAppleAccount && !iCloudWebLoginSaved(session) {
		return session, errCode("apple_auto_relogin_unavailable", "未找到可恢复的 Apple 登录接口", true)
	}
	key := appleAccountOperationKey(session, state)
	release, err := acquireAppleAccountOperationGate(ctx, key)
	if err != nil {
		return session, err
	}
	defer release()

	proxyID := firstNonEmpty(credentials.ProxyID, session.ProxyID, state.ProxyID)
	client, assignedProxyID, clientErr := s.newAppleAuthClientForAccount(session.OwnerID, credentials.AppleID, proxyID)
	if clientErr != nil {
		return session, clientErr
	}
	credentials.ProxyID = assignedProxyID
	var result appleAuthStartResult
	var pendingStore *appleAuthPendingStore
	if hasAppleAccount {
		pendingStore = s.appleAccountLogins
		result, err = client.StartAppleAccountManageLogin(ctx, credentials.AppleID, credentials.Password, pendingStore, credentials.TwoFactorMethod)
	} else {
		pendingStore = s.icloudProtocolLogins
		result, err = client.StartLogin(ctx, credentials.AppleID, credentials.Password, s.cfg.ICloudDefaultHost, s.cfg.ICloudClientID, pendingStore, credentials.TwoFactorMethod)
	}
	if err != nil {
		if isProxyTransportFailure(err) {
			s.markProxyFailure(assignedProxyID)
		}
		if hasAppleAccount && isAppleAccountManage502(err) {
			return s.autoReloginICloudWebFallback(ctx, session, credentials)
		}
		return session, err
	}
	if result.Needs2FA {
		if !pendingStore.setCredentials(result.PendingID, credentials) {
			return session, errCode("apple_login_pending_expired", "自动重登录待验证状态已失效", true)
		}
		pending, pendingOK := pendingStore.get(result.PendingID)
		if !pendingOK {
			return session, errCode("apple_login_pending_expired", "自动重登录待验证状态已失效", true)
		}
		for attempt := 1; attempt <= 3; attempt++ {
			code, codeErr := codeForPending(ctx, client, pending, "")
			if codeErr != nil {
				pendingStore.delete(result.PendingID)
				return session, codeErr
			}
			if hasAppleAccount {
				result.Session, err = client.SubmitAppleAccountManage2FA(ctx, pending, code, nil)
			} else {
				result.Session, err = client.Submit2FA(ctx, pending, code)
			}
			if err == nil {
				pendingStore.delete(result.PendingID)
				break
			}
			if hasAppleAccount && isAppleAccountManage502(err) {
				s.markProxyFailure(assignedProxyID)
				pendingStore.delete(result.PendingID)
				return s.autoReloginICloudWebFallback(ctx, session, credentials)
			}
			if !isCodedError(err, "apple_2fa_failed") && !isCodedError(err, "invalid_2fa_code") {
				pendingStore.delete(result.PendingID)
				return session, err
			}
			if attempt == 3 {
				pendingStore.delete(result.PendingID)
				return session, err
			}
			if err := waitAppleLoginRetry(ctx); err != nil {
				pendingStore.delete(result.PendingID)
				return session, err
			}
		}
	}

	result.Session.OwnerID = session.OwnerID
	result.Session.AccountID = session.AccountID
	result.Session = withSessionProxy(withAppleLoginCredentials(result.Session, credentials), assignedProxyID)
	result.Session.LastCheckedAt = time.Now()
	result.Session.LastCheckOK = true
	result.Session.LastStatusMessage = "登录态已自动重登录"
	return mergeICloudSession(session, result.Session), nil
}

func stripAppleLoginCredentials(session *ICloudSession) {
	if session != nil {
		session.AppleLogin = nil
	}
}

func sanitizeICloudSessionForExport(session ICloudSession) ICloudSession {
	out := cloneICloudSession(session)
	stripAppleLoginCredentials(&out)
	return out
}

func sanitizeICloudSessionsForExport(sessions []ICloudSession) []ICloudSession {
	out := make([]ICloudSession, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, sanitizeICloudSessionForExport(session))
	}
	return out
}

func isAutoReloginFailure(err error) bool {
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && shouldAutoRelogin(err)
}

func waitAppleLoginRetry(ctx context.Context) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

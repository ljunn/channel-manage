package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type remoteSession struct {
	Authorization string
	RefreshToken  string
	Cookie        string
	UserID        string
	SessionID     string
}

func newRemoteHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if envBool("ALLOW_PRIVATE_UPSTREAMS", false) {
				return dialer.DialContext(ctx, network, address)
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, resolved := range addresses {
				if unsafeRemoteIP(resolved.IP) {
					continue
				}
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				err = dialErr
			}
			if err == nil {
				err = fmt.Errorf("remote address is blocked")
			}
			return nil, err
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func unsafeRemoteIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func validateRemoteURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return "", &apiError{Status: 400, Code: "INVALID_REMOTE_URL", Message: "平台地址无效"}
	}
	if parsed.Scheme != "https" && !(envBool("ALLOW_INSECURE_UPSTREAMS", false) && parsed.Scheme == "http") {
		return "", &apiError{Status: 400, Code: "REMOTE_URL_BLOCKED", Message: "平台地址必须使用 HTTPS"}
	}
	if !envBool("ALLOW_PRIVATE_UPSTREAMS", false) {
		addresses, lookupErr := net.DefaultResolver.LookupIPAddr(context.Background(), parsed.Hostname())
		if lookupErr != nil {
			return "", &apiError{Status: 400, Code: "REMOTE_UNAVAILABLE", Message: "无法解析平台地址"}
		}
		for _, address := range addresses {
			if unsafeRemoteIP(address.IP) {
				return "", &apiError{Status: 400, Code: "REMOTE_URL_BLOCKED", Message: "平台地址不能指向本机或内网"}
			}
		}
	}
	parsed.Path, parsed.RawQuery, parsed.Fragment = "", "", ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func (a *App) remoteJSON(ctx context.Context, baseURL, method, path string, session remoteSession, body any) (any, http.Header, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, baseURL+path, reader)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "channel-manage/"+Version)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if session.Authorization != "" {
		request.Header.Set("Authorization", session.Authorization)
	}
	if session.Cookie != "" {
		request.Header.Set("Cookie", session.Cookie)
	}
	if session.UserID != "" {
		request.Header.Set("New-Api-User", session.UserID)
	}
	if session.SessionID != "" {
		request.Header.Set("X-Auth-Session", session.SessionID)
	}
	response, err := a.httpClient.Do(request)
	if err != nil {
		return nil, nil, &apiError{Status: 502, Code: "REMOTE_UNAVAILABLE", Message: "无法连接远端平台"}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, response.Header, err
	}
	var value any
	if len(data) > 0 && json.Unmarshal(data, &value) != nil {
		return nil, response.Header, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端返回了无法识别的数据"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := fmt.Sprintf("远端请求失败 (%d)", response.StatusCode)
		if record, ok := value.(map[string]any); ok {
			if remoteMessage := text(record["message"], ""); remoteMessage != "" {
				message = remoteMessage
			}
			if remoteReason := text(record["reason"], ""); remoteReason != "" {
				message = remoteReason + ": " + message
			}
			if remoteCode := text(record["code"], ""); remoteCode != "" {
				message = remoteCode + ": " + message
			}
			if remoteError, ok := record["error"].(map[string]any); ok {
				message = text(remoteError["message"], message)
			}
		}
		code := "REMOTE_REJECTED"
		if response.StatusCode == http.StatusTooManyRequests {
			code = "REMOTE_RATE_LIMITED"
		} else if response.StatusCode == http.StatusUnauthorized {
			code = "REMOTE_UNAUTHORIZED"
		}
		return value, response.Header, &apiError{Status: 502, Code: code, Message: message}
	}
	return value, response.Header, nil
}

type sub2APITokenPair struct {
	AccessToken  string
	RefreshToken string
}

func (a *App) refreshSub2APIToken(ctx context.Context, baseURL, refreshToken string) (sub2APITokenPair, error) {
	value, _, err := a.remoteJSON(ctx, baseURL, http.MethodPost, "/api/v1/auth/refresh", remoteSession{}, map[string]string{"refresh_token": refreshToken})
	if err != nil {
		if !remoteRouteUnavailable(err) {
			return sub2APITokenPair{}, err
		}
		value, _, err = a.remoteJSON(ctx, baseURL, http.MethodPost, "/auth/refresh", remoteSession{}, map[string]string{"refresh_token": refreshToken})
		if err != nil {
			return sub2APITokenPair{}, err
		}
	}
	data, err := sub2APIResponseData(value)
	if err != nil {
		return sub2APITokenPair{}, err
	}
	record, ok := data.(map[string]any)
	if !ok {
		return sub2APITokenPair{}, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端刷新令牌响应不兼容"}
	}
	pair := sub2APITokenPair{
		AccessToken:  text(record["access_token"], ""),
		RefreshToken: text(record["refresh_token"], refreshToken),
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		return sub2APITokenPair{}, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端刷新令牌响应缺少令牌"}
	}
	return pair, nil
}

func (a *App) refreshNewAPISession(ctx context.Context, baseURL string, session remoteSession) (remoteSession, error) {
	value, headers, err := a.remoteJSON(ctx, baseURL, http.MethodPost, "/api/user/auth/refresh", session, nil)
	if err != nil {
		return remoteSession{}, err
	}
	data, err := unwrapEnvelope(value, "NEW_API")
	if err != nil {
		return remoteSession{}, err
	}
	record, ok := data.(map[string]any)
	if !ok {
		return remoteSession{}, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端刷新会话响应不兼容"}
	}
	accessToken := text(record["access_token"], "")
	if accessToken == "" {
		return remoteSession{}, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端刷新会话响应缺少令牌"}
	}
	if cookie := responseCookie(headers); cookie != "" {
		session.Cookie = cookie
	}
	if nested, ok := record["session"].(map[string]any); ok {
		session.SessionID = text(nested["sid"], session.SessionID)
	}
	session.Authorization = "Bearer " + accessToken
	return session, nil
}

func sub2APIResponseData(value any) (any, error) {
	envelope, ok := value.(map[string]any)
	if !ok {
		return value, nil
	}
	if _, hasCode := envelope["code"]; hasCode {
		code, codeOK := number(envelope["code"])
		if !codeOK || code != 0 {
			return nil, &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: text(envelope["message"], "远端拒绝请求")}
		}
		return envelope["data"], nil
	}
	if success, hasSuccess := envelope["success"].(bool); hasSuccess {
		if !success {
			return nil, &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: text(envelope["message"], "远端拒绝请求")}
		}
		if data, hasData := envelope["data"]; hasData {
			return data, nil
		}
	}
	return value, nil
}

func remoteUnauthorized(err error) bool {
	var typed *apiError
	return errors.As(err, &typed) && typed.Code == "REMOTE_UNAUTHORIZED"
}

func remoteRateLimited(err error) bool {
	var typed *apiError
	return errors.As(err, &typed) && typed.Code == "REMOTE_RATE_LIMITED"
}

func remoteAuthenticationExpired(err error) bool {
	var typed *apiError
	if !errors.As(err, &typed) {
		return false
	}
	if typed.Code == "REMOTE_UNAUTHORIZED" {
		return true
	}
	message := strings.ToLower(typed.Message)
	return typed.Code == "REMOTE_REJECTED" && (strings.Contains(message, "token expired") ||
		strings.Contains(message, "invalid token") || strings.Contains(message, "invalid refresh") ||
		strings.Contains(message, "refresh token") || strings.Contains(message, "令牌失效") ||
		strings.Contains(message, "令牌过期"))
}

func remoteRouteUnavailable(err error) bool {
	var typed *apiError
	if !errors.As(err, &typed) {
		return false
	}
	message := strings.ToLower(typed.Message)
	return typed.Code == "SCHEMA_CHANGED" || strings.Contains(message, "(404)") || strings.Contains(message, "not found")
}

func unwrapEnvelope(value any, platform string) (any, error) {
	if platform == "SUB2API" {
		return sub2APIResponseData(value)
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端返回格式不兼容"}
	}
	success, ok := record["success"].(bool)
	if !ok || !success {
		return nil, &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: text(record["message"], "远端拒绝请求")}
	}
	return record["data"], nil
}

func (a *App) loginRemote(ctx context.Context, baseURL, platform, username, password string) (remoteSession, error) {
	if platform == "SUB2API" {
		var value any
		var headers http.Header
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			value, headers, err = a.remoteJSON(ctx, baseURL, http.MethodPost, "/api/v1/auth/login", remoteSession{}, map[string]any{"email": username, "password": password, "not_in_cn_confirmed": true})
			if !remoteRateLimited(err) || attempt == 2 {
				break
			}
			if err := waitRemoteLoginRetry(ctx, headers, attempt); err != nil {
				return remoteSession{}, err
			}
		}
		if err != nil {
			if !remoteRouteUnavailable(err) {
				return remoteSession{}, err
			}
			value, headers, err = a.remoteJSON(ctx, baseURL, http.MethodPost, "/auth/login", remoteSession{}, map[string]string{"email": username, "password": password})
			if err != nil {
				return remoteSession{}, err
			}
		}
		data, err := sub2APIResponseData(value)
		if err != nil {
			return remoteSession{}, err
		}
		record, ok := data.(map[string]any)
		accessToken := text(record["access_token"], text(record["token"], ""))
		if !ok || accessToken == "" {
			return remoteSession{}, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端登录响应不兼容"}
		}
		return remoteSession{
			Authorization: "Bearer " + accessToken,
			RefreshToken:  text(record["refresh_token"], ""),
			Cookie:        responseCookie(headers),
		}, nil
	}
	value, headers, err := a.remoteJSON(ctx, baseURL, http.MethodPost, "/api/user/login", remoteSession{}, map[string]string{"username": username, "password": password})
	if err != nil {
		return remoteSession{}, err
	}
	data, err := unwrapEnvelope(value, platform)
	if err != nil {
		return remoteSession{}, err
	}
	record, ok := data.(map[string]any)
	if !ok {
		return remoteSession{}, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端登录响应不兼容"}
	}
	if required, _ := record["require_2fa"].(bool); required {
		return remoteSession{}, &apiError{Status: 409, Code: "REMOTE_2FA_REQUIRED", Message: "远端账号已开启两步验证，暂不支持自动登录"}
	}
	if accessToken := text(record["access_token"], ""); accessToken != "" {
		userID := ""
		if user, ok := record["user"].(map[string]any); ok {
			if id, ok := number(user["id"]); ok {
				userID = strconv.Itoa(int(id))
			}
		}
		sessionID := ""
		if session, ok := record["session"].(map[string]any); ok {
			sessionID = text(session["sid"], "")
		}
		return remoteSession{Authorization: "Bearer " + accessToken, Cookie: responseCookie(headers), UserID: userID, SessionID: sessionID}, nil
	}
	cookie := strings.Split(headers.Get("Set-Cookie"), ";")[0]
	id, _ := number(record["id"])
	if cookie == "" || id <= 0 {
		return remoteSession{}, &apiError{Status: 502, Code: "AUTHENTICATION", Message: "远端登录失败"}
	}
	return remoteSession{Cookie: cookie, UserID: strconv.Itoa(int(id))}, nil
}

func waitRemoteLoginRetry(ctx context.Context, headers http.Header, attempt int) error {
	delay := time.Duration(attempt+1) * time.Second
	if seconds, err := strconv.Atoi(headers.Get("Retry-After")); err == nil && seconds >= 0 {
		delay = time.Duration(seconds) * time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sessionFromCredential(credential sourceCredentials) remoteSession {
	authorization := ""
	if credential.AccessToken != "" {
		authorization = "Bearer " + credential.AccessToken
	}
	return remoteSession{
		Authorization: authorization,
		RefreshToken:  credential.RefreshToken,
		Cookie:        credential.Cookie,
		UserID:        credential.UserID,
		SessionID:     credential.SessionID,
	}
}

func credentialHasSession(credential sourceCredentials) bool {
	return credential.AccessToken != "" || credential.Cookie != ""
}

func applySessionToCredential(credential *sourceCredentials, session remoteSession) {
	credential.AccessToken = strings.TrimPrefix(session.Authorization, "Bearer ")
	credential.RefreshToken = session.RefreshToken
	credential.Cookie = session.Cookie
	credential.UserID = session.UserID
	credential.SessionID = session.SessionID
}

func responseCookie(headers http.Header) string {
	cookies := []string{}
	for _, value := range headers.Values("Set-Cookie") {
		if pair := strings.TrimSpace(strings.Split(value, ";")[0]); pair != "" {
			cookies = append(cookies, pair)
		}
	}
	return strings.Join(cookies, "; ")
}

func (a *App) logoutRemote(ctx context.Context, baseURL string, session remoteSession) {
	if session.SessionID == "" || session.Cookie == "" || session.Authorization == "" {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, _, _ = a.remoteJSON(requestCtx, baseURL, http.MethodPost, "/api/user/auth/logout", session, nil)
}

func number(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case json.Number:
		result, err := typed.Float64()
		return result, err == nil
	case string:
		result, err := strconv.ParseFloat(typed, 64)
		return result, err == nil
	default:
		return 0, false
	}
}

func text(value any, fallback string) string {
	if result, ok := value.(string); ok && strings.TrimSpace(result) != "" {
		return result
	}
	return fallback
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return []string{}
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		switch typed := item.(type) {
		case string:
			result = append(result, typed)
		case float64:
			result = append(result, strconv.Itoa(int(typed)))
		}
	}
	return result
}

func timeoutContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 30*time.Second)
}

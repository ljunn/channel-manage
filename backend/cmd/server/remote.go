package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	Cookie        string
	UserID        string
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
		return value, response.Header, &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: fmt.Sprintf("远端请求失败 (%d)", response.StatusCode)}
	}
	return value, response.Header, nil
}

func unwrapEnvelope(value any, platform string) (any, error) {
	record, ok := value.(map[string]any)
	if !ok {
		return nil, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端返回格式不兼容"}
	}
	if platform == "SUB2API" {
		code, ok := number(record["code"])
		if !ok || code != 0 {
			return nil, &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: text(record["message"], "远端拒绝请求")}
		}
		return record["data"], nil
	}
	success, ok := record["success"].(bool)
	if !ok || !success {
		return nil, &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: text(record["message"], "远端拒绝请求")}
	}
	return record["data"], nil
}

func (a *App) loginRemote(ctx context.Context, baseURL, platform, username, password string) (remoteSession, error) {
	if platform == "SUB2API" {
		value, _, err := a.remoteJSON(ctx, baseURL, http.MethodPost, "/api/v1/auth/login", remoteSession{}, map[string]any{"email": username, "password": password, "not_in_cn_confirmed": true})
		if err != nil {
			return remoteSession{}, err
		}
		data, err := unwrapEnvelope(value, platform)
		if err != nil {
			return remoteSession{}, err
		}
		record, ok := data.(map[string]any)
		if !ok || text(record["access_token"], "") == "" {
			return remoteSession{}, &apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "远端登录响应不兼容"}
		}
		return remoteSession{Authorization: "Bearer " + text(record["access_token"], "")}, nil
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
	cookie := strings.Split(headers.Get("Set-Cookie"), ";")[0]
	id, _ := number(record["id"])
	if cookie == "" || id <= 0 {
		return remoteSession{}, &apiError{Status: 502, Code: "AUTHENTICATION", Message: "远端登录失败"}
	}
	return remoteSession{Cookie: cookie, UserID: strconv.Itoa(int(id))}, nil
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

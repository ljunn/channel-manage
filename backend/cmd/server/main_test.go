package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialEncryptionRoundTrip(t *testing.T) {
	app := &App{cryptoKey: deriveCryptoKey("this-is-a-long-test-secret")}
	plain := []byte(`{"username":"ops@example.com","password":"secret"}`)
	encrypted, err := app.encryptSecret(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(encrypted) == string(plain) {
		t.Fatal("secret was stored as plaintext")
	}
	decrypted, err := app.decryptSecret(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decrypted, plain) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}
}

func TestCredentialEncryptionRejectsWrongKey(t *testing.T) {
	first := &App{cryptoKey: deriveCryptoKey("first-secret")}
	second := &App{cryptoKey: deriveCryptoKey("second-secret")}
	encrypted, err := first.encryptSecret([]byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.decryptSecret(encrypted); err == nil {
		t.Fatal("wrong key decrypted credential")
	}
}

func TestValidateRemoteURLRejectsUnsafeTargets(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_UPSTREAMS", "false")
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "false")
	for _, value := range []string{"http://example.com", "https://127.0.0.1", "https://10.0.0.2", "file:///etc/passwd"} {
		if _, err := validateRemoteURL(value); err == nil {
			t.Errorf("expected %q to be rejected", value)
		}
	}
}

func TestValidateRemoteURLNormalizesOrigin(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("requires external DNS")
	}
	value, err := validateRemoteURL("https://example.com/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if value != "https://example.com" {
		t.Fatalf("got %q", value)
	}
}

func TestUnwrapEnvelope(t *testing.T) {
	value, err := unwrapEnvelope(map[string]any{"code": float64(0), "message": "ok", "data": map[string]any{"id": float64(1)}}, "SUB2API")
	if err != nil {
		t.Fatal(err)
	}
	if value.(map[string]any)["id"] != float64(1) {
		t.Fatalf("unexpected value: %#v", value)
	}
	if _, err := unwrapEnvelope(map[string]any{"success": false}, "NEW_API"); err == nil {
		t.Fatal("failed response was accepted")
	}
	direct := []any{map[string]any{"id": float64(1)}}
	value, err = unwrapEnvelope(direct, "SUB2API")
	if err != nil || len(value.([]any)) != 1 {
		t.Fatalf("direct Sub2API response was not accepted: %#v, %v", value, err)
	}
}

func TestAPIErrorIncludesActionableMessage(t *testing.T) {
	err := (&apiError{Status: 502, Code: "REMOTE_REJECTED", Message: "AUTH_SESSION_LIMIT: Conflict"}).Error()
	if err != "REMOTE_REJECTED: AUTH_SESSION_LIMIT: Conflict" {
		t.Fatalf("unexpected error text: %q", err)
	}
}

func TestStableKey(t *testing.T) {
	first := stableKey("account", "SET_SCHEDULABLE", "true")
	if first != stableKey("account", "SET_SCHEDULABLE", "true") {
		t.Fatal("key is not stable")
	}
	if first == stableKey("account", "SET_SCHEDULABLE", "false") {
		t.Fatal("different actions shared a key")
	}
}

func TestUnsafeRemoteIP(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "::1"} {
		if !unsafeRemoteIP(net.ParseIP(value)) {
			t.Errorf("expected %s to be unsafe", value)
		}
	}
	if unsafeRemoteIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public IP was blocked")
	}
}

func TestPercentile(t *testing.T) {
	if got := percentile([]int{40, 10, 30, 20}, .95); got != 40 {
		t.Fatalf("p95=%v", got)
	}
	if got := percentile(nil, .5); got != nil {
		t.Fatalf("empty percentile=%v", got)
	}
}

func TestSourceValueDivisor(t *testing.T) {
	tests := []struct {
		numerator, denominator, want float64
	}{{0, 0, 1}, {1, 10, 10}, {2, 10, 5}, {10, 1, .1}}
	for _, test := range tests {
		got, err := sourceValueDivisor(test.numerator, test.denominator)
		if err != nil || got != test.want {
			t.Fatalf("sourceValueDivisor(%v,%v)=(%v,%v), want %v", test.numerator, test.denominator, got, err, test.want)
		}
	}
	if _, err := sourceValueDivisor(1, 0); err == nil {
		t.Fatal("zero denominator was accepted")
	}
}

func TestLoginRemoteSupportsModernNewAPI(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/login" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		http.SetCookie(w, &http.Cookie{Name: "new_api_refresh", Value: "refresh-value", Path: "/api/user/auth"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"access_token":"dashboard-token","user":{"id":42},"session":{"sid":"session-id"}}}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	session, err := app.loginRemote(context.Background(), server.URL, "NEW_API", "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	if session.Authorization != "Bearer dashboard-token" || session.UserID != "42" || session.SessionID != "session-id" || !strings.Contains(session.Cookie, "new_api_refresh=") {
		t.Fatalf("unexpected session: %#v", session)
	}
}

func TestLoginRemoteReportsNewAPISessionLimit(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"code":"AUTH_SESSION_LIMIT","message":"Conflict"}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	_, err := app.loginRemote(context.Background(), server.URL, "NEW_API", "user", "password")
	apiErr, ok := err.(*apiError)
	if !ok || !strings.Contains(apiErr.Message, "AUTH_SESSION_LIMIT") {
		t.Fatalf("expected session limit error, got %v", err)
	}
}

func TestLoginRemoteSupportsFlatSub2APILogin(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/login":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		case "/auth/login":
			_, _ = w.Write([]byte(`{"access_token":"flat-token"}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	session, err := app.loginRemote(context.Background(), server.URL, "SUB2API", "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	if session.Authorization != "Bearer flat-token" {
		t.Fatalf("unexpected session: %#v", session)
	}
}

func TestRemoteJSONMarksSub2APIAdminRequests(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Admin-UI-Request") != "1" {
			t.Fatalf("missing admin UI request header: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"items":[]}}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	if _, _, err := app.remoteJSON(context.Background(), server.URL, http.MethodGet, "/api/v1/admin/groups", remoteSession{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLoginRemoteRetriesRateLimitAndReturnsTokenPair(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"Too many requests, please try again later"}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"access-token","refresh_token":"refresh-token"}}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}

	session, err := app.loginRemote(context.Background(), server.URL, "SUB2API", "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	if session.Authorization != "Bearer access-token" || session.RefreshToken != "refresh-token" {
		t.Fatalf("unexpected session: %#v", session)
	}
	if requests != 2 {
		t.Fatalf("login requests=%d, want 2", requests)
	}
}

func TestRemoteRateLimitedClassification(t *testing.T) {
	err := &apiError{Status: 502, Code: "REMOTE_RATE_LIMITED", Message: "Too many requests"}
	if !remoteRateLimited(err) {
		t.Fatal("rate limit error was not classified")
	}
	if remoteRateLimited(&apiError{Status: 502, Code: "REMOTE_REJECTED"}) {
		t.Fatal("ordinary remote rejection was classified as a rate limit")
	}
}

func TestRemoteRouteFallbackRequiresNotFound(t *testing.T) {
	if !remoteRouteUnavailable(&apiError{Status: 502, Code: "REMOTE_NOT_FOUND", Message: "not found"}) {
		t.Fatal("not found response did not allow route fallback")
	}
	for _, err := range []error{
		&apiError{Status: 502, Code: "SCHEMA_CHANGED", Message: "not found in response body"},
		&apiError{Status: 502, Code: "REMOTE_INVALID_RESPONSE", Message: "text/html"},
		&apiError{Status: 502, Code: "REMOTE_RATE_LIMITED", Message: "too many requests"},
	} {
		if remoteRouteUnavailable(err) {
			t.Fatalf("unexpected route fallback for %v", err)
		}
	}
}

func TestLoginRemoteDoesNotHideSub2APIAuthenticationError(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	fallbackCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth/login" {
			fallbackCalled = true
			t.Fatal("flat login fallback must not run after an authentication failure")
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"reason":"INVALID_CREDENTIALS","message":"invalid email or password"}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	_, err := app.loginRemote(context.Background(), server.URL, "SUB2API", "user", "password")
	if err == nil || !strings.Contains(err.Error(), "INVALID_CREDENTIALS: invalid email or password") || fallbackCalled {
		t.Fatalf("expected original authentication error, got %v", err)
	}
}

func TestLoginRemoteDoesNotFallbackAfterHTMLRateLimit(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	fallbackCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/login" {
			fallbackCalled = true
			t.Fatal("flat login fallback must not run after rate limiting")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`<html><title>Too Many Requests</title></html>`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	_, err := app.loginRemote(context.Background(), server.URL, "SUB2API", "user", "password")
	if !remoteRateLimited(err) || fallbackCalled || !strings.Contains(err.Error(), "/api/v1/auth/login") || !strings.Contains(err.Error(), "text/html") {
		t.Fatalf("expected original HTML rate limit, got %v", err)
	}
}

func TestLoginRemoteDoesNotFallbackAfterHTMLSuccessResponse(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	fallbackCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/login" {
			fallbackCalled = true
			t.Fatal("flat login fallback must not run after an invalid success response")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><title>Verification required</title></html>`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	_, err := app.loginRemote(context.Background(), server.URL, "SUB2API", "user", "password")
	apiErr, ok := err.(*apiError)
	if !ok || apiErr.Code != "REMOTE_INVALID_RESPONSE" || fallbackCalled || !strings.Contains(apiErr.Message, "/api/v1/auth/login") || !strings.Contains(apiErr.Message, "text/html") {
		t.Fatalf("expected actionable invalid response error, got %v", err)
	}
}

func TestRefreshSub2APITokenRotatesPair(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/refresh" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"new-access","refresh_token":"new-refresh"}}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	pair, err := app.refreshSub2APIToken(context.Background(), server.URL, "old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken != "new-access" || pair.RefreshToken != "new-refresh" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestRefreshSub2APITokenSupportsFlatRoute(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/refresh":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		case "/auth/refresh":
			_, _ = w.Write([]byte(`{"access_token":"flat-access","refresh_token":"flat-refresh"}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	pair, err := app.refreshSub2APIToken(context.Background(), server.URL, "old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken != "flat-access" || pair.RefreshToken != "flat-refresh" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestRefreshSub2APITokenDoesNotFallbackAfterRateLimit(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	flatCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth/refresh" {
			flatCalled = true
			t.Fatal("flat refresh fallback must not run after rate limiting")
		}
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"Too many requests"}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	_, err := app.refreshSub2APIToken(context.Background(), server.URL, "refresh-token")
	if !remoteRateLimited(err) || flatCalled {
		t.Fatalf("expected original rate limit, got %v", err)
	}
}

func TestRefreshNewAPISessionRotatesAccessAndCookie(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/auth/refresh" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("X-Auth-Session") != "session-id" {
			t.Fatalf("missing session header: %q", r.Header.Get("X-Auth-Session"))
		}
		if cookie, err := r.Cookie("new_api_refresh"); err != nil || cookie.Value != "old-refresh" {
			t.Fatalf("missing refresh cookie: %v %#v", err, cookie)
		}
		http.SetCookie(w, &http.Cookie{Name: "new_api_refresh", Value: "new-refresh", Path: "/api/user/auth"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"access_token":"new-access","session":{"sid":"session-id"}}}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	session, err := app.refreshNewAPISession(context.Background(), server.URL, remoteSession{
		Authorization: "Bearer old-access",
		Cookie:        "new_api_refresh=old-refresh",
		SessionID:     "session-id",
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Authorization != "Bearer new-access" || !strings.Contains(session.Cookie, "new_api_refresh=new-refresh") {
		t.Fatalf("unexpected refreshed session: %#v", session)
	}
}

func TestSessionCredentialRoundTripSupportsTokenAndCookieVariants(t *testing.T) {
	for _, session := range []remoteSession{
		{Authorization: "Bearer access", RefreshToken: "refresh"},
		{Authorization: "Bearer access", Cookie: "new_api_refresh=cookie", UserID: "42", SessionID: "sid"},
		{Cookie: "session=legacy", UserID: "7"},
	} {
		credential := sourceCredentials{Username: "user", Password: "password"}
		applySessionToCredential(&credential, session)
		if got := sessionFromCredential(credential); !reflect.DeepEqual(got, session) {
			t.Fatalf("session round trip mismatch: got %#v want %#v", got, session)
		}
	}
}

func TestPageRecordsSupportsPagedAndFlatResponses(t *testing.T) {
	flat := []any{map[string]any{"id": float64(1)}}
	if len(pageRecords(flat)) != 1 || len(pageRecords(map[string]any{"items": flat})) != 1 {
		t.Fatal("token page records were not normalized")
	}
}

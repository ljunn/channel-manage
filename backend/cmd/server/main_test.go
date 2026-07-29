package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestCreateRemoteManagedAccountsCreatesOneAccountPerTargetGroup(t *testing.T) {
	requests := []map[string]any{}
	var mu sync.Mutex
	active := 0
	maxActive := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/accounts" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		requests = append(requests, payload)
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		groupIDs := payload["group_ids"].([]any)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code":0,"data":{"id":%d}}`, int(groupIDs[0].(float64)))))
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	targetGroups := []deploymentTargetGroup{
		{ID: "local-1", Name: "低倍率", RemoteID: 11},
		{ID: "local-2", Name: "高质量", RemoteID: 22},
	}
	accounts, err := app.createRemoteManagedAccounts(context.Background(), server.URL, remoteSession{}, "https://source.example", "SUB2API", "源站", "分组 A", "sk-test", []string{"gpt-test"}, targetGroups, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 || len(requests) != 2 {
		t.Fatalf("expected two independent accounts, got accounts=%d requests=%d", len(accounts), len(requests))
	}
	if maxActive < 2 {
		t.Fatalf("expected account creation to run concurrently, max active requests=%d", maxActive)
	}
	requestsByGroup := map[int]map[string]any{}
	for _, request := range requests {
		groupIDs, ok := request["group_ids"].([]any)
		if !ok || len(groupIDs) != 1 {
			t.Fatalf("account has invalid group_ids: %#v", request["group_ids"])
		}
		requestsByGroup[int(groupIDs[0].(float64))] = request
	}
	for index, targetGroup := range targetGroups {
		request := requestsByGroup[targetGroup.RemoteID]
		if request == nil {
			t.Fatalf("target group %d was not created", targetGroup.RemoteID)
		}
		if !strings.Contains(request["name"].(string), targetGroups[index].Name) {
			t.Fatalf("account %d name does not identify target group: %q", index, request["name"])
		}
		if int(request["priority"].(float64)) != 1000 {
			t.Fatalf("account %d priority=%v, want 1000", index, request["priority"])
		}
		if int(request["concurrency"].(float64)) != 1000 {
			t.Fatalf("account %d concurrency=%v, want 1000", index, request["concurrency"])
		}
		credentials := request["credentials"].(map[string]any)
		if credentials["base_url"] != "https://source.example/v1" {
			t.Fatalf("account %d base_url=%v, want published source API endpoint", index, credentials["base_url"])
		}
	}
}

func TestCreateRemoteManagedAccountsReturnsSuccessesWhenOneTargetFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		groupID := int(payload["group_ids"].([]any)[0].(float64))
		w.Header().Set("Content-Type", "application/json")
		if groupID == 22 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"code":1,"message":"create failed"}`))
			return
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code":0,"data":{"id":%d}}`, groupID)))
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	accounts, err := app.createRemoteManagedAccounts(context.Background(), server.URL, remoteSession{}, "https://source.example", "SUB2API", "源站", "分组 A", "sk-test", []string{"gpt-test"}, []deploymentTargetGroup{{ID: "local-1", Name: "成功", RemoteID: 11}, {ID: "local-2", Name: "失败", RemoteID: 22}}, 1000, 1000)
	if err == nil || !strings.Contains(err.Error(), "失败") {
		t.Fatalf("expected target-specific failure, got %v", err)
	}
	if len(accounts) != 1 || accounts[0].RemoteID != "11" {
		t.Fatalf("successful account must be returned for rollback: %#v", accounts)
	}
}

func TestDeploymentErrorExplainsInsufficientBalance(t *testing.T) {
	err := deploymentError("UPSTREAM_MODEL_READ_FAILED", "Pro分组", &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: "INSUFFICIENT_BALANCE: Insufficient account balance"})
	apiErr, ok := err.(*apiError)
	if !ok || apiErr.Status != http.StatusConflict || !strings.Contains(apiErr.Message, "源站账户余额不足") || !strings.Contains(apiErr.Message, "Pro分组") {
		t.Fatalf("unexpected deployment error: %#v", err)
	}
}

func TestManagedObjectNameFitsNewAPITokenLimit(t *testing.T) {
	name := managedObjectName("CCMAX自营3可外接", "svip-bug-team-250刀", "12345678")
	if len(name) > 50 {
		t.Fatalf("managed key name is %d bytes, want at most 50: %q", len(name), name)
	}
	if !strings.HasSuffix(name, "-12345678") {
		t.Fatalf("managed key name must retain its unique suffix: %q", name)
	}
}

func TestDeploymentErrorExplainsTokenNameLimit(t *testing.T) {
	err := deploymentError("UPSTREAM_KEY_CREATE_FAILED", "CCMAX自营3可外接", &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: "Token name is too long"})
	apiErr, ok := err.(*apiError)
	if !ok || apiErr.Status != http.StatusUnprocessableEntity || !strings.Contains(apiErr.Message, "50 字节") {
		t.Fatalf("unexpected deployment error: %#v", err)
	}
}

func TestDiscoverSourceAPIBaseURL(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_UPSTREAMS", "true")
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer apiServer.Close()
	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/settings/public" {
			t.Fatalf("unexpected public settings path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"code":0,"data":{"api_base_url":%q}}`, apiServer.URL)))
	}))
	defer panelServer.Close()

	app := &App{httpClient: panelServer.Client()}
	baseURL, err := app.discoverSourceAPIBaseURL(context.Background(), Source{Platform: "SUB2API", BaseURL: panelServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	if baseURL != apiServer.URL {
		t.Fatalf("discovered base URL=%q, want %q", baseURL, apiServer.URL)
	}
}

func TestDeploymentErrorExplainsPanelDomain(t *testing.T) {
	err := deploymentError("UPSTREAM_MODEL_READ_FAILED", "Codex - Pro - B", &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: "The API endpoint is not served from the panel domain. Please use the published API endpoint for this service."})
	apiErr, ok := err.(*apiError)
	if !ok || apiErr.Status != http.StatusUnprocessableEntity || !strings.Contains(apiErr.Message, "面板域名不提供 API") {
		t.Fatalf("unexpected deployment error: %#v", err)
	}
}

func TestMarketQualityScoreUsesAvailableMetrics(t *testing.T) {
	if score := marketQualityScore(sql.NullFloat64{Float64: 40, Valid: true}, sql.NullFloat64{Float64: 80, Valid: true}, sql.NullFloat64{Float64: 100, Valid: true}); score != 90 {
		t.Fatalf("combined score=%v, want 90", score)
	}
	if score := marketQualityScore(sql.NullFloat64{Float64: 40, Valid: true}, sql.NullFloat64{}, sql.NullFloat64{Float64: 75, Valid: true}); score != 75 {
		t.Fatalf("business fallback=%v, want 75", score)
	}
	if score := marketQualityScore(sql.NullFloat64{Float64: 40, Valid: true}, sql.NullFloat64{}, sql.NullFloat64{}); score != 40 {
		t.Fatalf("current score fallback=%v, want 40", score)
	}
}

func TestCompareReleaseVersions(t *testing.T) {
	if compareReleaseVersions("0.1.19", "0.1.20") >= 0 || compareReleaseVersions("v1.2.3", "1.2.3") != 0 || compareReleaseVersions("2.0.0", "1.9.9") <= 0 {
		t.Fatal("release version comparison is incorrect")
	}
}

func TestUpdateRepositoryAndReleaseURLValidation(t *testing.T) {
	if !validRepository("ljunn/channel-manage") || validRepository("ljunn/channel/manage") || validRepository("ljunn/channel manage") {
		t.Fatal("repository validation is incorrect")
	}
	for _, value := range []string{"https://github.com/ljunn/channel-manage/releases/download/v1/a.tar.gz", "https://objects.githubusercontent.com/release/a"} {
		if err := validateReleaseURL(value); err != nil {
			t.Fatalf("trusted release URL rejected: %v", err)
		}
	}
	if err := validateReleaseURL("https://example.com/update.tar.gz"); err == nil {
		t.Fatal("untrusted release URL was accepted")
	}
}

func TestVerifyUpdateChecksum(t *testing.T) {
	directory := t.TempDir()
	archive := filepath.Join(directory, "release.tar.gz")
	checksums := filepath.Join(directory, "checksums.txt")
	content := []byte("verified release")
	if err := os.WriteFile(archive, content, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	if err := os.WriteFile(checksums, []byte(fmt.Sprintf("%x  channel-manage_1.0.0_linux_amd64.tar.gz\n", hash)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpdateChecksum(archive, checksums, "channel-manage_1.0.0_linux_amd64.tar.gz"); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpdateChecksum(archive, checksums, "wrong.tar.gz"); err == nil {
		t.Fatal("missing checksum entry was accepted")
	}
}

func TestSyncTargetAccountPriority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/admin/accounts/42" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]int
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["priority"] != 1007 {
			t.Fatalf("priority=%d, want 1007", payload["priority"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"id":42}}`))
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	if err := app.syncTargetAccountPriority(context.Background(), server.URL, "42", remoteSession{}, 1007); err != nil {
		t.Fatal(err)
	}
}

func TestSyncTargetAccountConcurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/admin/accounts/42" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]int
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["concurrency"] != 1000 {
			t.Fatalf("concurrency=%d, want 1000", payload["concurrency"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"id":42}}`))
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	if err := app.syncTargetAccountNumbers(context.Background(), server.URL, "42", remoteSession{}, map[string]int{"concurrency": 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRejectionReasonsUsesTargetGroupMultiplier(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{MinSuccessRate: 95, MinSamples: 5})
	eligible := managedPolicyCandidate{
		State: "HEALTHY", SourceMultiplier: sql.NullFloat64{Float64: .5, Valid: true}, TargetMultiplier: sql.NullFloat64{Float64: .5, Valid: true},
		SuccessRate: sql.NullFloat64{Float64: 100, Valid: true}, Samples: 5,
	}
	if reasons := policyRejectionReasons(eligible, config); len(reasons) != 0 {
		t.Fatalf("equal source and target multipliers should be eligible: %#v", reasons)
	}
	eligible.SourceMultiplier.Float64 = .51
	reasons := policyRejectionReasons(eligible, config)
	if len(reasons) != 1 || !strings.Contains(reasons[0], "超过目标分组上限") {
		t.Fatalf("source multiplier above target limit was not rejected: %#v", reasons)
	}
}

func TestRankManagedAccountsByPriceFromPriority1000(t *testing.T) {
	items := []managedPolicyCandidate{
		eligiblePolicyCandidate("expensive", .8, 240),
		eligiblePolicyCandidate("cheap", .2, 900),
		eligiblePolicyCandidate("middle", .5, 120),
	}
	priorities := rankManagedAccounts(items, policyConfig{Mode: "PRICE", MinSuccessRate: 95, MinSamples: 5})
	if priorities["cheap"] != 1000 || priorities["middle"] != 1001 || priorities["expensive"] != 1002 {
		t.Fatalf("unexpected price ranking: %#v", priorities)
	}
}

func TestRankManagedAccountsBySpeedFromPriority1000(t *testing.T) {
	items := []managedPolicyCandidate{
		eligiblePolicyCandidate("slow", .1, 900),
		eligiblePolicyCandidate("fast", .8, 120),
		eligiblePolicyCandidate("middle", .5, 240),
	}
	priorities := rankManagedAccounts(items, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5})
	if priorities["fast"] != 1000 || priorities["middle"] != 1001 || priorities["slow"] != 1002 {
		t.Fatalf("unexpected speed ranking: %#v", priorities)
	}
}

func TestRankManagedAccountsExcludesIneligibleChannels(t *testing.T) {
	healthy := eligiblePolicyCandidate("healthy", .2, 120)
	unhealthy := eligiblePolicyCandidate("unhealthy", .1, 100)
	unhealthy.State = "OFFLINE"
	priorities := rankManagedAccounts([]managedPolicyCandidate{unhealthy, healthy}, policyConfig{Mode: "PRICE", MinSuccessRate: 95, MinSamples: 5})
	if priorities["healthy"] != 1000 {
		t.Fatalf("eligible account did not start at 1000: %#v", priorities)
	}
	if _, exists := priorities["unhealthy"]; exists {
		t.Fatalf("ineligible account was ranked: %#v", priorities)
	}
}

func eligiblePolicyCandidate(id string, sourceMultiplier, firstTokenP95 float64) managedPolicyCandidate {
	return managedPolicyCandidate{
		ID: id, State: "HEALTHY", Samples: 5,
		SourceMultiplier: sql.NullFloat64{Float64: sourceMultiplier, Valid: true},
		TargetMultiplier: sql.NullFloat64{Float64: 1, Valid: true},
		SuccessRate:      sql.NullFloat64{Float64: 100, Valid: true},
		FirstTokenP95:    sql.NullFloat64{Float64: firstTokenP95, Valid: true},
	}
}

func TestPolicyRejectsManualMultiplierLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/policies", strings.NewReader(`{"name":"test","config":{"maxMultiplier":1}}`))
	err := (&App{}).createPolicy(httptest.NewRecorder(), request)
	apiErr, ok := err.(*apiError)
	if !ok || apiErr.Code != "INVALID_JSON" {
		t.Fatalf("manual multiplier limit was accepted: %v", err)
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

func TestSub2APIGroupMultiplierPrefersAvailableGroupRate(t *testing.T) {
	record := map[string]any{"rate_multiplier": float64(.12)}
	rates := map[string]any{"43": float64(.5)}
	value := sub2APIGroupMultiplier(record, rates, "43")
	if value == nil || *value != .12 {
		t.Fatalf("unexpected available group multiplier: %v", value)
	}
	delete(record, "rate_multiplier")
	value = sub2APIGroupMultiplier(record, rates, "43")
	if value == nil || *value != .5 {
		t.Fatalf("unexpected legacy rate multiplier: %v", value)
	}
	for _, field := range []string{"rate", "ratio", "multiplier", "group_ratio"} {
		value = sub2APIGroupMultiplier(map[string]any{field: ".25"}, map[string]any{}, "43")
		if value == nil || *value != .25 {
			t.Fatalf("unexpected %s multiplier: %v", field, value)
		}
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

func TestRemoteJSONReportsOversizedResponse(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", maxRemoteResponseBytes)))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	_, _, err := app.remoteJSON(context.Background(), server.URL, http.MethodGet, "/large", remoteSession{}, nil)
	apiErr, ok := err.(*apiError)
	if !ok || apiErr.Code != "REMOTE_RESPONSE_TOO_LARGE" {
		t.Fatalf("expected oversized response error, got %v", err)
	}
}

func TestFetchPagedUsesBoundedPageSize(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("page_size") != "100" {
			t.Fatalf("unexpected page size: %s", r.URL.Query().Get("page_size"))
		}
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"items":[{"id":` + page + `}],"pages":2}}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	items, err := app.fetchPaged(context.Background(), server.URL, "/api/v1/admin/groups", remoteSession{})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(items) != 2 {
		t.Fatalf("requests=%d items=%d", requests, len(items))
	}
}

func TestFetchTargetAssetsDoesNotReadAccounts(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/admin/system/version":
			_, _ = w.Write([]byte(`{"code":0,"data":{"version":"test"}}`))
		case "/api/v1/admin/groups":
			_, _ = w.Write([]byte(`{"code":0,"data":{"items":[],"pages":1}}`))
		default:
			t.Fatalf("unexpected target asset request: %s", r.URL.String())
		}
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	version, groups, err := app.fetchTargetAssets(context.Background(), server.URL, remoteSession{})
	if err != nil {
		t.Fatal(err)
	}
	if version != "test" || len(groups) != 0 {
		t.Fatalf("version=%q groups=%d", version, len(groups))
	}
	if !reflect.DeepEqual(paths, []string{"/api/v1/admin/system/version", "/api/v1/admin/groups"}) {
		t.Fatalf("unexpected target asset paths: %#v", paths)
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

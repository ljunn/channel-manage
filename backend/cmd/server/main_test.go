package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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

func TestValidateSourceURLAllowsPublicHTTPIPOnly(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_UPSTREAMS", "false")
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "false")

	value, err := validateSourceURL("http://1.1.1.1:8080/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if value != "http://1.1.1.1:8080" {
		t.Fatalf("got %q", value)
	}
	if _, err := validateRemoteURL("http://1.1.1.1"); err == nil {
		t.Error("expected a non-source HTTP endpoint to be rejected")
	}
	for _, value := range []string{"http://127.0.0.1:8080", "http://10.0.0.2", "http://100.64.0.1"} {
		if _, err := validateSourceURL(value); err == nil {
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
	stopped := map[string]bool{}
	var mu sync.Mutex
	active := 0
	maxActive := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/schedulable") {
			var payload map[string]bool
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(r.URL.Path, "/")
			mu.Lock()
			stopped[parts[len(parts)-2]] = !payload["schedulable"]
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"updated":true}}`))
			return
		}
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
		{ID: "local-1", Name: "低倍率", Platform: "anthropic", RemoteID: 11, DisabledModels: []string{"claude-test"}},
		{ID: "local-2", Name: "高质量", Platform: "grok", RemoteID: 22},
	}
	accounts, err := app.createRemoteManagedAccounts(context.Background(), server.URL, remoteSession{}, "https://source.example", "源站", "分组 A", "sk-test", []string{"claude-test", "claude-allowed", "grok-test"}, targetGroups, .37, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 || len(requests) != 2 {
		t.Fatalf("expected two independent accounts, got accounts=%d requests=%d", len(accounts), len(requests))
	}
	if !stopped["11"] || !stopped["22"] {
		t.Fatalf("new accounts were not explicitly stopped: %#v", stopped)
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
		if request["rate_multiplier"].(float64) != .37 {
			t.Fatalf("account %d rate_multiplier=%v, want 0.37", index, request["rate_multiplier"])
		}
		if request["platform"] != targetGroup.Platform {
			t.Fatalf("account %d platform=%v, want target group platform %s", index, request["platform"], targetGroup.Platform)
		}
		credentials := request["credentials"].(map[string]any)
		expectedBaseURL := "https://source.example/v1"
		if targetGroup.Platform == "anthropic" {
			expectedBaseURL = "https://source.example"
		}
		if credentials["base_url"] != expectedBaseURL {
			t.Fatalf("account %d base_url=%v, want %s", index, credentials["base_url"], expectedBaseURL)
		}
	}
	credentials := requestsByGroup[11]["credentials"].(map[string]any)
	mapping := credentials["model_mapping"].(map[string]any)
	if _, exists := mapping["claude-test"]; exists || mapping["claude-allowed"] != "claude-allowed" {
		t.Fatalf("disabled model was sent to target account: %#v", mapping)
	}
}

func TestAccountBaseURLMatchesTargetPlatform(t *testing.T) {
	tests := []struct {
		name, sourceBase, platform, want string
	}{
		{"openai adds version", "https://source.example", "openai", "https://source.example/v1"},
		{"openai keeps version", "https://source.example/v1/", "openai", "https://source.example/v1"},
		{"grok adds version", "https://source.example", "grok", "https://source.example/v1"},
		{"anthropic uses root", "https://source.example", "anthropic", "https://source.example"},
		{"anthropic removes version", "https://source.example/v1/", "claude", "https://source.example"},
		{"gemini removes version", "https://source.example/v1", "gemini", "https://source.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := accountBaseURL(test.sourceBase, test.platform); got != test.want {
				t.Fatalf("accountBaseURL(%q, %q)=%q, want %q", test.sourceBase, test.platform, got, test.want)
			}
		})
	}
}

func TestCreateRemoteManagedAccountsReturnsSuccessesWhenOneTargetFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/schedulable") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":0,"data":{"updated":true}}`))
			return
		}
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
	accounts, err := app.createRemoteManagedAccounts(context.Background(), server.URL, remoteSession{}, "https://source.example", "源站", "分组 A", "sk-test", []string{"gpt-test"}, []deploymentTargetGroup{{ID: "local-1", Name: "成功", Platform: "openai", RemoteID: 11}, {ID: "local-2", Name: "失败", Platform: "openai", RemoteID: 22}}, .5, 1000, 1000)
	if err == nil || !strings.Contains(err.Error(), "失败") {
		t.Fatalf("expected target-specific failure, got %v", err)
	}
	if len(accounts) != 1 || accounts[0].RemoteID != "11" {
		t.Fatalf("successful account must be returned for rollback: %#v", accounts)
	}
}

func TestManagedPlatformUsesTargetGroupType(t *testing.T) {
	tests := map[string]string{
		"openai":    "openai",
		"anthropic": "anthropic",
		"claude":    "anthropic",
		"grok":      "grok",
		"gork":      "grok",
		"gemini":    "gemini",
		"":          "openai",
	}
	for input, expected := range tests {
		if actual := managedPlatform(input); actual != expected {
			t.Fatalf("managedPlatform(%q)=%q, want %q", input, actual, expected)
		}
	}
}

func TestManagedActionLocksAreScopedPerAccount(t *testing.T) {
	app := &App{}
	first := app.managedActionLock("account-a")
	if first != app.managedActionLock("account-a") {
		t.Fatal("同一托管账号应复用同一个动作锁")
	}
	if first == app.managedActionLock("account-b") {
		t.Fatal("不同托管账号不应共享动作锁")
	}
}

func TestRateMultiplierNeedsSync(t *testing.T) {
	if rateMultiplierNeedsSync(.32, true, .32) {
		t.Fatal("matching account rate was treated as drift")
	}
	if !rateMultiplierNeedsSync(1, true, .32) {
		t.Fatal("default account rate was not treated as drift")
	}
	if !rateMultiplierNeedsSync(0, false, .32) {
		t.Fatal("missing account rate was not treated as drift")
	}
}

func TestBalanceForecastUsesMedianConsumptionAndIgnoresRecharge(t *testing.T) {
	start := time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC)
	samples := []balanceSample{
		{Balance: 100, CapturedAt: start},
		{Balance: 90, CapturedAt: start.Add(time.Hour)},
		{Balance: 70, CapturedAt: start.Add(2 * time.Hour)},
		{Balance: 170, CapturedAt: start.Add(3 * time.Hour)},
		{Balance: 160, CapturedAt: start.Add(4 * time.Hour)},
		{Balance: 150, CapturedAt: start.Add(5 * time.Hour)},
		{Balance: 140, CapturedAt: start.Add(6 * time.Hour)},
	}
	forecast := calculateBalanceForecast(samples)
	if !forecast.Known || forecast.BurnRate != 10 || forecast.EtaHours != 14 {
		t.Fatalf("unexpected balance forecast: %#v", forecast)
	}
}

func TestBalanceAlertUsesStrictConfiguredThreshold(t *testing.T) {
	if !balanceBelowAlertThreshold(9.99, 10) {
		t.Fatal("balance below threshold was not detected")
	}
	if balanceBelowAlertThreshold(10, 10) {
		t.Fatal("balance equal to threshold must not alert")
	}
	if balanceBelowAlertThreshold(10.01, 10) {
		t.Fatal("balance above threshold must not alert")
	}
	if balanceBelowAlertThreshold(1, 0) {
		t.Fatal("non-positive threshold must not alert")
	}
}

func TestDeploymentErrorExplainsInsufficientBalance(t *testing.T) {
	err := deploymentError("UPSTREAM_MODEL_READ_FAILED", "Pro分组", &apiError{Status: 502, Code: "REMOTE_REJECTED", Message: "INSUFFICIENT_BALANCE: Insufficient account balance"})
	apiErr, ok := err.(*apiError)
	if !ok || apiErr.Status != http.StatusConflict || !strings.Contains(apiErr.Message, "源站账户余额不足") || !strings.Contains(apiErr.Message, "Pro分组") {
		t.Fatalf("unexpected deployment error: %#v", err)
	}
}

func TestClassifyProbeFailureNamesBalanceExhaustionDirectly(t *testing.T) {
	errorType, summary := classifyProbeFailure(&apiError{Status: 502, Code: "REMOTE_REJECTED", Message: "INSUFFICIENT_BALANCE: Insufficient account balance"})
	if errorType != "BALANCE_EXHAUSTED" || summary != "源站账户余额不足" {
		t.Fatalf("balance error was not classified clearly: %q %q", errorType, summary)
	}
	for _, message := range []string{"quota exhausted", "账户余额不足", "balance not enough"} {
		if !insufficientBalanceError(fmt.Errorf("%s", message)) {
			t.Fatalf("balance marker %q was not recognized", message)
		}
	}
}

func TestEventEmailGuidanceIsActionable(t *testing.T) {
	guidance := eventEmailGuidanceFor("SOURCE_BALANCE", false)
	content := formatEventEmail("event-1", "P0", "源站账户余额不足", "数据源：vincent", time.Date(2026, 7, 29, 4, 5, 6, 0, time.UTC), guidance)
	for _, expected := range []string{"发生了什么", "影响", "你需要做什么", "系统会自动做什么", "请登录", "自动恢复", "vincent"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("email is missing %q:\n%s", expected, content)
		}
	}
	for _, category := range []string{"SOURCE_BALANCE", "GROUP_AVAILABILITY"} {
		if !(&App{}).eventEmailEnabled(context.Background(), category, "P1") {
			t.Fatalf("category %s was not allowed to send email", category)
		}
	}
	for _, category := range []string{"SOURCE_BALANCE", "GROUP_AVAILABILITY", "SOURCE_SCAN"} {
		if (&App{}).eventEmailEnabled(context.Background(), category, "恢复") {
			t.Fatalf("recovery event for %s must not send email", category)
		}
	}
	modelGuidance := eventEmailGuidanceFor("ACCOUNT_MODEL_SYNC", false)
	if modelGuidance.Scene != "账号模型映射校正失败" || !strings.Contains(modelGuidance.Action, "写入权限") {
		t.Fatalf("model correction guidance is incomplete: %#v", modelGuidance)
	}
	rateGuidance := eventEmailGuidanceFor("ACCOUNT_RATE_SYNC", false)
	if rateGuidance.Scene != "账号倍率校正失败" || !strings.Contains(rateGuidance.Action, "写入权限") {
		t.Fatalf("rate correction guidance is incomplete: %#v", rateGuidance)
	}
	if emailDeliveryKind("恢复") != "recovery" || emailDeliveryKind("P0") != "p0" {
		t.Fatal("email delivery idempotency keys must use stable ASCII kinds")
	}
}

func TestBalanceEmailSubjectNamesSourceAndBalance(t *testing.T) {
	guidance := eventEmailGuidanceFor("SOURCE_BALANCE", false)
	tests := []struct {
		severity string
		title    string
		detail   string
		want     string
	}{
		{"P0", "账户可用余额已耗尽", "数据源：微信 。\n当前余额：-0.06 USD", "[P0] 微信余额不足，当前 -0.06 USD"},
		{"P1", "账户可用余额预计 3.2 小时后耗尽", "数据源：vincent\n当前余额：12.00 USD\n预计剩余：3.2 小时", "[P1] vincent余额预计不足，当前 12.00 USD，预计剩余 3.2 小时"},
		{"恢复", "账户可用余额已耗尽已恢复", "数据源：微信 。\n当前余额：-0.06 USD", "[恢复] 微信余额已恢复"},
	}
	for _, test := range tests {
		if got := eventEmailSubject(test.severity, "SOURCE_BALANCE", test.title, test.detail, guidance); got != test.want {
			t.Fatalf("eventEmailSubject() = %q, want %q", got, test.want)
		}
	}
	otherGuidance := eventEmailGuidanceFor("SOURCE_SCAN", false)
	if got := eventEmailSubject("P1", "SOURCE_SCAN", "同步失败", "数据源：微信", otherGuidance); got != "[P1][数据源扫描失败] 同步失败" {
		t.Fatalf("non-balance subject changed: %q", got)
	}
}

func TestBalanceEmailKeepsOnlyRechargeFields(t *testing.T) {
	detail := "数据源：微信\n充值地址：https://example.com/billing\n充值账号：vi****nt\n当前余额：12.00 USD\n实际消耗速度：3.00 USD / 小时（中位数）\n预计耗尽时间：2026-08-03 18:30\n建议最低充值：50.00 USD\n判定依据：连续 2 次扫描均低于预警线"
	content := formatBalanceEmail("P1", detail, time.Now())
	for _, expected := range []string{"当前余额：12.00 USD", "建议充值：至少 50.00 USD", "预计耗尽：2026-08-03 18:30", "充值账号：vi****nt", "前往充值：https://example.com/billing"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("balance email is missing %q:\n%s", expected, content)
		}
	}
	for _, unwanted := range []string{"实际消耗速度", "判定依据", "系统参考", "事件 ID", "系统会自动做什么"} {
		if strings.Contains(content, unwanted) {
			t.Fatalf("balance email contains unwanted %q:\n%s", unwanted, content)
		}
	}
}

func TestSourceStabilityAssessmentUsesOperationalSignals(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		input sourceQualityInput
		want  string
	}{
		{"insufficient", sourceQualityInput{CreatedAt: now.Add(-24 * time.Hour), ProbeSamples: 30, ProbeSuccessRate: sql.NullFloat64{Float64: 100, Valid: true}}, sourceStabilityInsufficient},
		{"unstable", sourceQualityInput{CreatedAt: now.Add(-8 * 24 * time.Hour), BusinessRequests: 1200, BusinessSuccessRate: sql.NullFloat64{Float64: 85, Valid: true}}, sourceStabilityUnstable},
		{"degraded", sourceQualityInput{CreatedAt: now.Add(-4 * 24 * time.Hour), BusinessRequests: 300, BusinessSuccessRate: sql.NullFloat64{Float64: 95, Valid: true}}, sourceStabilityDegraded},
		{"stable", sourceQualityInput{CreatedAt: now.Add(-8 * 24 * time.Hour), BusinessRequests: 1200, BusinessSuccessRate: sql.NullFloat64{Float64: 99.8, Valid: true}, FirstTokenP95Ms: sql.NullFloat64{Float64: 1800, Valid: true}}, sourceStabilityStable},
		{"business-overrides-probe", sourceQualityInput{CreatedAt: now.Add(-8 * 24 * time.Hour), ProbeSamples: 200, ProbeSuccessRate: sql.NullFloat64{Float64: 20, Valid: true}, BusinessRequests: 1200, BusinessSuccessRate: sql.NullFloat64{Float64: 99.8, Valid: true}}, sourceStabilityStable},
		{"slow-first-response", sourceQualityInput{CreatedAt: now.Add(-8 * 24 * time.Hour), BusinessRequests: 1200, BusinessSuccessRate: sql.NullFloat64{Float64: 99.8, Valid: true}, FirstTokenP95Ms: sql.NullFloat64{Float64: 12_000, Valid: true}}, sourceStabilityUnstable},
		{"slow-probe-first-response-fallback", sourceQualityInput{CreatedAt: now.Add(-8 * 24 * time.Hour), ProbeSamples: 200, ProbeSuccessRate: sql.NullFloat64{Float64: 99, Valid: true}, ProbeFirstTokenP95Ms: sql.NullFloat64{Float64: 12_000, Valid: true}}, sourceStabilityUnstable},
		{"business-first-response-preferred", sourceQualityInput{CreatedAt: now.Add(-8 * 24 * time.Hour), ProbeSamples: 200, ProbeSuccessRate: sql.NullFloat64{Float64: 99, Valid: true}, ProbeFirstTokenP95Ms: sql.NullFloat64{Float64: 20_000, Valid: true}, BusinessRequests: 1200, BusinessSuccessRate: sql.NullFloat64{Float64: 99.8, Valid: true}, FirstTokenP95Ms: sql.NullFloat64{Float64: 1000, Valid: true}}, sourceStabilityStable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _, reasons := assessSourceStability(test.input, now)
			if got != test.want || len(reasons) == 0 {
				t.Fatalf("assessSourceStability() = %q, %v; want %q with reasons", got, reasons, test.want)
			}
		})
	}
}

func TestSourceProfileBalanceSupportsSub2APICreditBalance(t *testing.T) {
	for _, profile := range []map[string]any{
		{"balance": 12.5},
		{"credit_balance": 9.913731},
		{"creditBalance": "7.25"},
	} {
		if value, ok := sourceProfileBalance(profile); !ok || value <= 0 {
			t.Fatalf("sourceProfileBalance(%v) = %.6f, %v", profile, value, ok)
		}
	}
	if _, ok := sourceProfileBalance(map[string]any{"name": "missing"}); ok {
		t.Fatal("missing balance field was accepted")
	}
}

func TestUntrustedSourceIsAlwaysRejectedBySchedulingPolicy(t *testing.T) {
	candidate := managedPolicyCandidate{
		SourceUntrusted:  true,
		State:            "HEALTHY",
		SourceMultiplier: sql.NullFloat64{Float64: 0.5, Valid: true},
		TargetMultiplier: sql.NullFloat64{Float64: 1, Valid: true},
		Samples:          10,
		SuccessRate:      sql.NullFloat64{Float64: 100, Valid: true},
		RecentSuccesses:  recoverySuccessSamples,
	}
	reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 95, MinSamples: 5})
	if len(reasons) != 1 || reasons[0] != "数据源已被人工标记为不可信" {
		t.Fatalf("untrusted source was not rejected clearly: %v", reasons)
	}
	if candidateCanRecoverWithProbe(candidate, policyConfig{}) {
		t.Fatal("untrusted source was scheduled for recovery probes")
	}
}

func TestPausedSourceIsAlwaysRejectedBySchedulingPolicy(t *testing.T) {
	candidate := managedPolicyCandidate{
		SourcePaused:     true,
		State:            "HEALTHY",
		SourceMultiplier: sql.NullFloat64{Float64: 0.5, Valid: true},
		TargetMultiplier: sql.NullFloat64{Float64: 1, Valid: true},
		Samples:          10,
		SuccessRate:      sql.NullFloat64{Float64: 100, Valid: true},
		RecentSuccesses:  recoverySuccessSamples,
	}
	reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 95, MinSamples: 5})
	if len(reasons) != 1 || reasons[0] != "数据源已人工暂停调度" {
		t.Fatalf("paused source was not rejected clearly: %v", reasons)
	}
	if candidateCanRecoverWithProbe(candidate, policyConfig{}) {
		t.Fatal("paused source was scheduled for recovery probes")
	}
}

func TestPolicyRejectsManagedAccountWithFailedSyncStatus(t *testing.T) {
	candidate := eligiblePolicyCandidate("sync-failed", .2, 120)
	candidate.SyncStatus = "FAILED"
	reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 95, MinSamples: 5})
	if len(reasons) != 1 || !strings.Contains(reasons[0], "同步状态为 FAILED") {
		t.Fatalf("failed sync account remained eligible: %#v", reasons)
	}
}

func TestPolicyRejectsManagedAccountWithConfirmedBusinessFailure(t *testing.T) {
	candidate := eligiblePolicyCandidate("business-failed", .2, 120)
	candidate.BusinessConfirmedFailure = true
	candidate.StateReason = "测试模型 gpt-5.5：抽样请求失败 (403)"
	reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 1, MinSamples: 5})
	if len(reasons) != 1 || !strings.Contains(reasons[0], "已确认失败") {
		t.Fatalf("confirmed business failure remained eligible: %#v", reasons)
	}
}

func TestPolicyRejectsImmediateProbeFailureDespiteHealthySevenDayRate(t *testing.T) {
	candidate := eligiblePolicyCandidate("deleted-group", .2, 120)
	candidate.SuccessRate = sql.NullFloat64{Float64: 100, Valid: true}
	candidate.StateReason = "GROUP_DELETED: API Key 所属分组已删除"
	reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 1, MinSamples: 5})
	if len(reasons) != 1 || !strings.Contains(reasons[0], "已确认失败") {
		t.Fatalf("deleted group remained eligible: %#v", reasons)
	}
}

func TestSourceScanFailuresBlockOnlyActionableOrStaleSources(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if reason := sourceSchedulingBlockReason("ACTIVE", "FAILED", "session expired/no credentials", sql.NullTime{Time: now, Valid: true}, 900, now); reason == "" {
		t.Fatal("authentication failure did not block scheduling")
	}
	if reason := sourceSchedulingBlockReason("ACTIVE", "FAILED", "temporary upstream timeout", sql.NullTime{Time: now.Add(-5 * time.Minute), Valid: true}, 900, now); reason != "" {
		t.Fatalf("fresh transient scan failure was blocked: %s", reason)
	}
	if reason := sourceSchedulingBlockReason("ACTIVE", "FAILED", "temporary upstream timeout", sql.NullTime{Time: now.Add(-31 * time.Minute), Valid: true}, 900, now); reason == "" {
		t.Fatal("stale scan failure did not block scheduling")
	}
}

func TestManagedAccountGoneErrorRecognizesRemoteDeletion(t *testing.T) {
	if !managedAccountGoneError("REMOTE_NOT_FOUND: ACCOUNT_NOT_FOUND: account not found") {
		t.Fatal("remote account deletion was not recognized")
	}
	if managedAccountGoneError("REMOTE_UNAVAILABLE: upstream timeout") {
		t.Fatal("transient remote outage was treated as account deletion")
	}
}

func TestRemoteRequestIDNormalizesStringAndNumericIDs(t *testing.T) {
	if got := remoteRequestID("request-1"); got != "request-1" {
		t.Fatalf("string request ID=%q", got)
	}
	if got := remoteRequestID(float64(42)); got != "42" {
		t.Fatalf("numeric request ID=%q", got)
	}
	if got := remoteRequestID(nil); got != "" {
		t.Fatalf("missing request ID=%q", got)
	}
}

func TestSourceEventDedupeFindsOnlyMappedSource(t *testing.T) {
	if got := sourceIDFromEvent("SOURCE_BALANCE", "source-balance:source-1"); got != "source-1" {
		t.Fatalf("sourceIDFromEvent() = %q", got)
	}
	if got := sourceIDFromEvent("TARGET_SYNC", "target-sync:target-1"); got != "" {
		t.Fatalf("target event unexpectedly mapped to source %q", got)
	}
}

func TestSendEmailRetriesTemporaryProviderFailureWithStableIdempotencyKey(t *testing.T) {
	requests := 0
	keys := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if requests == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mail-id"}`))
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Test server certificate.
	serverAddress := server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	app := &App{httpClient: &http.Client{Transport: transport}}
	err := app.sendEmail(context.Background(), emailNotificationConfig{APIKey: "key", FromEmail: "from@example.com", ToEmail: "to@example.com"}, "subject", "content", "event/id/p0")
	if err != nil || requests != 2 || !reflect.DeepEqual(keys, []string{"event/id/p0", "event/id/p0"}) {
		t.Fatalf("unexpected email retry result: err=%v requests=%d keys=%v", err, requests, keys)
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

func TestSyncTargetAccountSchedulableUsesDedicatedEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/accounts/42/schedulable" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if !payload["schedulable"] {
			t.Fatal("schedulable state was not sent")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"id":42}}`))
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	if err := app.syncTargetAccountSchedulable(context.Background(), server.URL, "42", remoteSession{}, true); err != nil {
		t.Fatal(err)
	}
}

func TestCreateFallbackAccountUsesFreshCreateEndpoint(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/accounts":
			if r.Header.Get("Idempotency-Key") != "fallback-create" {
				t.Fatalf("create idempotency key=%q", r.Header.Get("Idempotency-Key"))
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["name"] != "[托管] 源站 / 慢分组 / Pro #22" {
				t.Fatalf("fresh account name=%v", payload["name"])
			}
			if priority, _ := number(payload["priority"]); int(priority) != 900000 {
				t.Fatalf("priority=%v", payload["priority"])
			}
			credentials, _ := payload["credentials"].(map[string]any)
			mapping, _ := credentials["model_mapping"].(map[string]any)
			if len(mapping) != 1 || mapping["original-model"] != "original-target" {
				t.Fatalf("model mapping was not preserved: %#v", mapping)
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"id":84}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/accounts/84/schedulable":
			if r.Header.Get("Idempotency-Key") != "" {
				t.Fatalf("schedulable request reused create idempotency key")
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"id":84}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	id, err := app.createRemoteManagedAccountWithMappingIdempotent(context.Background(), server.URL, remoteSession{}, "https://source.example", "openai", "sk-test", map[string]string{"original-model": "original-target"}, []int{22}, "[托管] 源站 / 慢分组 / Pro #22", .2, 900000, 1000, "fallback-create")
	if err != nil {
		t.Fatal(err)
	}
	if id != "84" || requests != 2 {
		t.Fatalf("id=%q requests=%d", id, requests)
	}
}

func TestFetchRemoteAccountModelMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/accounts/42" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"credentials":{"model_mapping":{"model-a":"upstream-a","model-b":"upstream-b"}}}}`))
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	mapping, err := app.fetchRemoteAccountModelMapping(context.Background(), server.URL, "42", remoteSession{})
	if err != nil {
		t.Fatal(err)
	}
	if len(mapping) != 2 || mapping["model-a"] != "upstream-a" || mapping["model-b"] != "upstream-b" {
		t.Fatalf("unexpected model mapping: %#v", mapping)
	}
}

func TestActionFailureEventKeyDeduplicatesByManagedAccountAndAction(t *testing.T) {
	first := actionFailureEventKey("managed-1", "RECREATE_FALLBACK")
	second := actionFailureEventKey("managed-1", "RECREATE_FALLBACK")
	if first != second || first != "action-failure:managed-1:RECREATE_FALLBACK" {
		t.Fatalf("unexpected failure event keys %q %q", first, second)
	}
}

func TestPolicyRejectionReasonsUsesTargetGroupMultiplier(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{MinSuccessRate: 95, MinSamples: 5})
	eligible := managedPolicyCandidate{
		State: "HEALTHY", Schedulable: true, SourceMultiplier: sql.NullFloat64{Float64: .5, Valid: true}, TargetMultiplier: sql.NullFloat64{Float64: .5, Valid: true},
		SuccessRate: sql.NullFloat64{Float64: 100, Valid: true}, Samples: 5,
	}
	if reasons := policyRejectionReasons(eligible, config); len(reasons) != 1 || !strings.Contains(reasons[0], "未允许等倍率") {
		t.Fatalf("equal source and target multipliers should be rejected by default: %#v", reasons)
	}
	config.AllowEqualMultiplier = true
	if reasons := policyRejectionReasons(eligible, config); len(reasons) != 0 {
		t.Fatalf("equal source and target multipliers should be eligible when enabled: %#v", reasons)
	}
	eligible.SourceMultiplier.Float64 = .51
	reasons := policyRejectionReasons(eligible, config)
	if len(reasons) != 1 || !strings.Contains(reasons[0], "超过目标分组上限") {
		t.Fatalf("source multiplier above target limit was not rejected: %#v", reasons)
	}
}

func TestCalculateDynamicMultiplierUsesLowestBoundGroup(t *testing.T) {
	items := []managedPolicyCandidate{
		{SourceGroup: "较高价", SourceMultiplier: sql.NullFloat64{Float64: .08, Valid: true}},
		{SourceGroup: "最低价", SourceMultiplier: sql.NullFloat64{Float64: .06, Valid: true}},
		{SourceGroup: "缺少价格"},
	}
	percent := policyConfig{Mode: "PRICE", DynamicMultiplierEnabled: true, DynamicMultiplierType: dynamicMultiplierPercent, DynamicMultiplierValue: 5}
	quote, ok := calculateDynamicMultiplier(items, percent)
	if !ok || quote.SourceGroup != "最低价" || quote.Lowest != .06 || quote.Desired != .07 {
		t.Fatalf("unexpected percentage quote: %#v, ok=%v", quote, ok)
	}

	fixed := policyConfig{Mode: "PRICE", DynamicMultiplierEnabled: true, DynamicMultiplierType: dynamicMultiplierFixed, DynamicMultiplierValue: .01}
	quote, ok = calculateDynamicMultiplier(items, fixed)
	if !ok || quote.Desired != .07 {
		t.Fatalf("unexpected fixed quote: %#v, ok=%v", quote, ok)
	}
}

func TestCalculateDynamicMultiplierPercentRoundsUpByOneCent(t *testing.T) {
	config := policyConfig{Mode: "PRICE", DynamicMultiplierEnabled: true, DynamicMultiplierType: dynamicMultiplierPercent, DynamicMultiplierValue: 5}
	quote, ok := calculateDynamicMultiplier([]managedPolicyCandidate{{SourceGroup: "A", SourceMultiplier: sql.NullFloat64{Float64: .06, Valid: true}}}, config)
	if !ok || quote.Desired != .07 {
		t.Fatalf("0.063 should round up to 0.07, got %#v", quote)
	}

	config.DynamicMultiplierValue = 20
	quote, ok = calculateDynamicMultiplier([]managedPolicyCandidate{{SourceGroup: "B", SourceMultiplier: sql.NullFloat64{Float64: .05, Valid: true}}}, config)
	if !ok || quote.Desired != .06 {
		t.Fatalf("an exact cent must not be rounded to the next cent, got %#v", quote)
	}

	quote, ok = calculateDynamicMultiplier([]managedPolicyCandidate{{SourceGroup: "免费", SourceMultiplier: sql.NullFloat64{Float64: 0, Valid: true}}}, config)
	if !ok || quote.Desired != dynamicMultiplierStep {
		t.Fatalf("dynamic target multiplier must remain at least 0.01, got %#v", quote)
	}
}

func TestValidateDynamicMultiplierRequiresPriceModeAndMinimumValue(t *testing.T) {
	config := policyConfig{Mode: "SPEED", DynamicMultiplierEnabled: true, DynamicMultiplierType: dynamicMultiplierFixed, DynamicMultiplierValue: .01}
	if err := validateDynamicMultiplierConfig(config); err == nil {
		t.Fatal("speed-first policy accepted dynamic multiplier")
	}
	config.Mode = "PRICE"
	config.DynamicMultiplierValue = 0
	if normalized := normalizePolicyConfig(config); validateDynamicMultiplierConfig(normalized) == nil {
		t.Fatal("enabled dynamic multiplier accepted a missing value")
	}
	config.DynamicMultiplierValue = .001
	if err := validateDynamicMultiplierConfig(config); err == nil {
		t.Fatal("dynamic multiplier accepted a value below 0.01")
	}
	config.DynamicMultiplierValue = .01
	if err := validateDynamicMultiplierConfig(config); err != nil {
		t.Fatalf("valid dynamic multiplier was rejected: %v", err)
	}
}

func TestUpdateRemoteTargetGroupMultiplierUsesSub2APIGroupEndpoint(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/admin/groups/17" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Admin-UI-Request") != "1" {
			t.Fatal("dynamic group update was not marked as an admin UI request")
		}
		var payload map[string]float64
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["rate_multiplier"] != .07 {
			t.Fatalf("unexpected payload: %#v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"id":17,"rate_multiplier":0.07}}`))
	}))
	defer server.Close()

	app := &App{httpClient: newRemoteHTTPClient()}
	if err := app.updateRemoteTargetGroupMultiplier(context.Background(), server.URL, "17", remoteSession{}, .07); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRemoteTargetGroupMultiplierRejectsSub2APIBusinessError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"message":"倍率不可用"}`))
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	err := app.updateRemoteTargetGroupMultiplier(context.Background(), server.URL, "17", remoteSession{}, .07)
	if err == nil || !strings.Contains(err.Error(), "倍率不可用") {
		t.Fatalf("business rejection was not propagated: %v", err)
	}
}

func TestExtractCacheUsageUsesNormalizedAdminFields(t *testing.T) {
	usage, ok := extractCacheUsage(map[string]any{"input_tokens": 2000, "cache_read_tokens": 1200, "cache_creation_tokens": 400})
	if !ok || usage.InputTokens != 2000 || usage.CacheReadTokens != 1200 || usage.CacheCreationTokens != 400 {
		t.Fatalf("unexpected normalized cache usage: %#v, ok=%v", usage, ok)
	}
	if _, ok := extractCacheUsage(map[string]any{"input_tokens": 1000, "cache_read_tokens": 700}); ok {
		t.Fatal("usage without all normalized cache fields must remain unknown")
	}
}

func TestCacheReadRatioIncludesAllNormalizedInputClasses(t *testing.T) {
	score, total, ok := cacheReadRatio(400, 100, 500)
	if !ok || total != 1000 || score != .5 {
		t.Fatalf("score=%v total=%d ok=%v, want .5 over 1000 tokens", score, total, ok)
	}
}

func TestManagedCacheStateNeedsDistinctWindowsAndBothGaps(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{CacheMode: cacheModeDeprioritize, CacheMinRequests: 10, CacheMinInputTokens: 100, CacheAbsoluteGap: .10, CacheRelativeGap: .25})
	now := time.Now().Truncate(cacheMetricWindow)
	candidate := managedPolicyCandidate{CacheState: cacheStateNormal, CacheScore: sql.NullFloat64{Float64: .20, Valid: true}, CacheSamples: 10, CacheInputTokens: 100, CacheMetricSource: "TARGET_USAGE", CacheMetricAt: sql.NullTime{Time: now, Valid: true}, CacheStateChangedAt: sql.NullTime{Time: now.Add(-time.Hour), Valid: true}}
	for index := 0; index < config.CacheBadSnapshots; index++ {
		candidate.CacheMetricAt = sql.NullTime{Time: now.Add(time.Duration(index) * cacheMetricWindow), Valid: true}
		updated, changed := nextManagedCacheState(candidate, config, .50, true, now.Add(time.Duration(index)*cacheMetricWindow))
		if !changed || updated.CacheState != cacheStateObserving {
			if index != config.CacheBadSnapshots-1 || updated.CacheState != cacheStateLow || !updated.CachePenaltyActive {
				t.Fatalf("snapshot %d should advance cache degradation: %#v changed=%v", index, updated, changed)
			}
		}
		candidate = updated
	}
	if candidate.CacheState != cacheStateLow || !candidate.CachePenaltyActive {
		t.Fatalf("cache degradation should require configured confirmations: %#v", candidate)
	}
	duplicate, changed := nextManagedCacheState(candidate, config, .50, true, now.Add(11*time.Minute))
	if changed || duplicate.CacheBadSnapshots != candidate.CacheBadSnapshots {
		t.Fatalf("the same metric window must not be counted twice: %#v changed=%v", duplicate, changed)
	}
	for _, test := range []struct {
		score, reference float64
	}{{score: .38, reference: .50}, {score: .14, reference: .20}} {
		nearThreshold := candidate
		nearThreshold.CachePenaltyActive = false
		nearThreshold.CacheState = cacheStateNormal
		nearThreshold.CacheBadSnapshots = 0
		nearThreshold.CacheEvaluatedAt = sql.NullTime{}
		nearThreshold.CacheMetricAt = sql.NullTime{Time: now.Add(time.Hour), Valid: true}
		nearThreshold.CacheScore = sql.NullFloat64{Float64: test.score, Valid: true}
		updated, _ := nextManagedCacheState(nearThreshold, config, test.reference, true, now.Add(time.Hour))
		if updated.CacheState != cacheStateObserving || updated.CacheBadSnapshots != 0 {
			t.Fatalf("only one threshold must not count as low cache: %#v", updated)
		}
	}
}

func TestRankManagedAccountsPutsLowCacheAfterNormal(t *testing.T) {
	normal := eligiblePolicyCandidate("normal-cache", .2, 1000)
	low := eligiblePolicyCandidate("low-cache", .2, 1100)
	observing := eligiblePolicyCandidate("observing-cache", .2, 1200)
	observing.LatencyState = latencyStateObserving
	observing.CacheState = cacheStateLow
	low.CacheState = cacheStateLow
	low.CachePenaltyActive = true
	low.CacheScore = sql.NullFloat64{Float64: .10, Valid: true}
	low.CacheSamples = 50
	low.CacheInputTokens = 50000
	low.CacheMetricSource = "TARGET_USAGE"
	config := policyConfig{Mode: "PRICE", CacheMode: cacheModeDeprioritize, MinSuccessRate: 95, MinSamples: 5}
	priorities := planManagedAccountsAt([]managedPolicyCandidate{low, observing, normal}, config, time.Date(2026, 8, 23, 5, 30, 0, 0, time.UTC)).Priorities
	if priorities["normal-cache"] != 1000 || priorities["observing-cache"] < observingPriorityStart || priorities["low-cache"] < cacheDeprioritizedStart {
		t.Fatalf("low cache account was not placed in deprioritized band: %#v", priorities)
	}
}

func TestCacheReferenceUsesSameCohortAndLeavesCandidateOut(t *testing.T) {
	now := time.Now().Truncate(cacheMetricWindow)
	config := normalizePolicyConfig(policyConfig{CacheMode: cacheModeObserve, CacheMinRequests: 10, CacheMinInputTokens: 100})
	candidate := managedPolicyCandidate{ID: "candidate", CacheMetricModel: "model-a", CacheMetricRequestType: "stream", CacheMetricAt: sql.NullTime{Time: now, Valid: true}}
	items := []managedPolicyCandidate{candidate}
	for index, score := range []float64{.40, .50, .60} {
		items = append(items, managedPolicyCandidate{ID: fmt.Sprintf("peer-%d", index), CacheMetricModel: "model-a", CacheMetricRequestType: "stream", CacheScore: sql.NullFloat64{Float64: score, Valid: true}, CacheSamples: 10, CacheInputTokens: 100, CacheMetricSource: "TARGET_USAGE", CacheMetricAt: sql.NullTime{Time: now, Valid: true}})
	}
	items = append(items, managedPolicyCandidate{ID: "wrong-model", CacheMetricModel: "model-b", CacheMetricRequestType: "stream", CacheScore: sql.NullFloat64{Float64: .01, Valid: true}, CacheSamples: 10, CacheInputTokens: 100, CacheMetricSource: "TARGET_USAGE", CacheMetricAt: sql.NullTime{Time: now, Valid: true}})
	reference, ok := cacheReferenceScore(candidate, items, config, now)
	if !ok || reference != .50 {
		t.Fatalf("reference=%v ok=%v, want leave-one-out cohort median .50", reference, ok)
	}
	if _, ok := cacheReferenceScore(candidate, items[:3], config, now); ok {
		t.Fatal("fewer than three comparable peers must not produce an automatic baseline")
	}
}

func TestCacheStaleEvidencePreservesPenalty(t *testing.T) {
	now := time.Now()
	config := normalizePolicyConfig(policyConfig{CacheMode: cacheModeDeprioritize, CacheMinRequests: 10, CacheMinInputTokens: 100})
	candidate := managedPolicyCandidate{CacheState: cacheStateLow, CachePenaltyActive: true, CacheScore: sql.NullFloat64{Float64: .1, Valid: true}, CacheSamples: 10, CacheInputTokens: 100, CacheMetricSource: "TARGET_USAGE", CacheMetricAt: sql.NullTime{Time: now.Add(-time.Hour), Valid: true}, CacheEvaluatedAt: sql.NullTime{Time: now.Add(-time.Hour), Valid: true}, CacheBadSnapshots: 3, CachePenalizedAt: sql.NullTime{Time: now.Add(-time.Hour), Valid: true}}
	updated, changed := nextManagedCacheState(candidate, config, 0, false, now)
	if !changed || updated.CacheState != cacheStateStale || !updated.CachePenaltyActive || updated.CacheBadSnapshots != 3 {
		t.Fatalf("stale evidence must preserve an active penalty: %#v changed=%v", updated, changed)
	}
}

func TestCacheRecoveryRequiresNewWindowsAndHold(t *testing.T) {
	now := time.Now().Truncate(cacheMetricWindow)
	config := normalizePolicyConfig(policyConfig{CacheMode: cacheModeDeprioritize, CacheMinRequests: 10, CacheMinInputTokens: 100, CacheGoodSnapshots: 3})
	candidate := managedPolicyCandidate{CacheState: cacheStateLow, CachePenaltyActive: true, CacheScore: sql.NullFloat64{Float64: .50, Valid: true}, CacheSamples: 10, CacheInputTokens: 100, CacheMetricSource: "TARGET_USAGE", CachePenalizedAt: sql.NullTime{Time: now.Add(-cacheStateRecoveryHold), Valid: true}}
	for index := 0; index < config.CacheGoodSnapshots; index++ {
		candidate.CacheMetricAt = sql.NullTime{Time: now.Add(time.Duration(index) * cacheMetricWindow), Valid: true}
		candidate, _ = nextManagedCacheState(candidate, config, .50, true, now.Add(time.Duration(index)*cacheMetricWindow))
	}
	if candidate.CachePenaltyActive || candidate.CacheState != cacheStateNormal {
		t.Fatalf("three positive windows after the hold should recover: %#v", candidate)
	}
}

func TestCacheExplorationRotatesOnePenalizedAccount(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{CacheMode: cacheModeDeprioritize})
	normal := eligiblePolicyCandidate("normal", .2, 1000)
	lowA := eligiblePolicyCandidate("low-a", .2, 2000)
	lowB := eligiblePolicyCandidate("low-b", .2, 3000)
	lowA.CachePenaltyActive, lowB.CachePenaltyActive = true, true
	plan := planManagedAccountsAt([]managedPolicyCandidate{normal, lowA, lowB}, config, time.Date(2026, 8, 23, 4, 2, 0, 0, time.UTC))
	if len(plan.Exploration) != 1 {
		t.Fatalf("expected exactly one exploration account: %#v", plan.Exploration)
	}
	for id := range plan.Exploration {
		if plan.Priorities[id] != config.PriorityStart {
			t.Fatalf("exploration account priority=%d, want %d", plan.Priorities[id], config.PriorityStart)
		}
	}
	outside := planManagedAccountsAt([]managedPolicyCandidate{normal, lowA, lowB}, config, time.Date(2026, 8, 23, 4, 30, 0, 0, time.UTC))
	if len(outside.Exploration) != 0 || outside.Priorities["low-a"] < cacheDeprioritizedStart || outside.Priorities["low-b"] < cacheDeprioritizedStart {
		t.Fatalf("penalized accounts must stay in their band outside exploration: %#v", outside)
	}
}

func TestFetchRecentUsageRecordsStopsAtCutoff(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")
	now := time.Date(2026, 8, 23, 5, 10, 0, 0, time.UTC)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v1/admin/usage" || r.URL.Query().Get("account_id") != "42" || r.URL.Query().Get("page_size") != "100" {
			t.Fatalf("unexpected usage request: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"data":{"items":[{"account_id":42,"created_at":"2026-08-23T05:08:00Z","input_tokens":100,"cache_creation_tokens":10,"cache_read_tokens":90},{"account_id":42,"created_at":"2026-08-23T05:00:00Z","input_tokens":100,"cache_creation_tokens":0,"cache_read_tokens":0}],"pages":9}}`))
	}))
	defer server.Close()
	app := &App{httpClient: newRemoteHTTPClient()}
	items, err := app.fetchRecentUsageRecords(context.Background(), server.URL, "42", now.Add(-cacheMetricWindow), now, remoteSession{})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || len(items) != 1 {
		t.Fatalf("requests=%d items=%d, want one bounded page and one recent record", requests, len(items))
	}
}

func TestPolicyRecoveryAcceptsThreeRecentSuccesses(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{MinSuccessRate: 95, MinSamples: 10})
	recovering := managedPolicyCandidate{
		State: "HEALTHY", Samples: 10, RecentSuccesses: recoverySuccessSamples,
		SourceMultiplier: sql.NullFloat64{Float64: .2, Valid: true},
		TargetMultiplier: sql.NullFloat64{Float64: .5, Valid: true},
		SuccessRate:      sql.NullFloat64{Float64: 70, Valid: true},
	}
	if reasons := policyRejectionReasons(recovering, config); len(reasons) != 0 {
		t.Fatalf("recent consecutive successes should recover scheduling: %#v", reasons)
	}
	recovering.RecentSuccesses--
	if reasons := policyRejectionReasons(recovering, config); len(reasons) != 1 || !strings.Contains(reasons[0], "最近探测成功") {
		t.Fatalf("insufficient recovery successes should remain rejected: %#v", reasons)
	}
}

func TestPolicyRejectsConfirmedSlowLatencyState(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: 10_000})
	candidate := eligiblePolicyCandidate("slow", .2, 10_001)
	reasons := policyRejectionReasons(candidate, config)
	if len(reasons) != 1 || !strings.Contains(reasons[0], "持续偏慢") {
		t.Fatalf("slow first-token candidate should be rejected by policy: %#v", reasons)
	}
	candidate.LatencyState = latencyStateNormal
	if reasons := policyRejectionReasons(candidate, config); len(reasons) != 0 {
		t.Fatalf("normal latency state should remain eligible: %#v", reasons)
	}
}

func TestFastRecoveryExcludesManualHoldAndMultiplierViolation(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{MinSuccessRate: 95, MinSamples: 10})
	candidate := managedPolicyCandidate{
		State: "HEALTHY", Samples: 4,
		SourceMultiplier: sql.NullFloat64{Float64: .2, Valid: true},
		TargetMultiplier: sql.NullFloat64{Float64: .5, Valid: true},
	}
	if !candidateCanRecoverWithProbe(candidate, config) {
		t.Fatal("insufficient samples should enter fast validation")
	}
	candidate.State = "MANUAL_HOLD"
	if candidateCanRecoverWithProbe(candidate, config) {
		t.Fatal("manual hold must not enter fast recovery")
	}
	candidate.State = "HEALTHY"
	candidate.SourceMultiplier.Float64 = .6
	if candidateCanRecoverWithProbe(candidate, config) {
		t.Fatal("multiplier violation must not enter fast recovery")
	}
}

func TestFastProbeIntervalBacksOffAndAcceleratesOnRecovery(t *testing.T) {
	if interval := fastProbeIntervalFor(managedPolicyCandidate{ConsecutiveFailures: 3}); interval != 15 {
		t.Fatalf("initial recovery interval=%d, want 15", interval)
	}
	if interval := fastProbeIntervalFor(managedPolicyCandidate{ConsecutiveFailures: 8}); interval != 60 {
		t.Fatalf("middle backoff interval=%d, want 60", interval)
	}
	if interval := fastProbeIntervalFor(managedPolicyCandidate{ConsecutiveFailures: 11}); interval != 300 {
		t.Fatalf("long backoff interval=%d, want 300", interval)
	}
	if interval := fastProbeIntervalFor(managedPolicyCandidate{ConsecutiveFailures: 11, RecentSuccesses: 1}); interval != 15 {
		t.Fatalf("recovering interval=%d, want 15", interval)
	}
}

func TestRankManagedAccountsByPriceFromPriority1000(t *testing.T) {
	items := []managedPolicyCandidate{
		eligiblePolicyCandidate("expensive", .8, 240),
		eligiblePolicyCandidate("cheap", .2, 900),
		eligiblePolicyCandidate("middle", .5, 120),
	}
	priorities := rankManagedAccounts(items, policyConfig{Mode: "PRICE", MinSuccessRate: 95, MinSamples: 5})
	if priorities["cheap"] != 1000 || priorities["middle"] != 2000 || priorities["expensive"] != 3000 {
		t.Fatalf("unexpected price ranking: %#v", priorities)
	}
}

func TestRankManagedAccountsBySpeedFromPriority1000(t *testing.T) {
	items := []managedPolicyCandidate{
		eligiblePolicyCandidate("slow", .1, 9_000),
		eligiblePolicyCandidate("fast", .8, 1_000),
		eligiblePolicyCandidate("middle", .5, 5_000),
	}
	priorities := rankManagedAccounts(items, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5})
	if priorities["fast"] != 1000 || priorities["middle"] != 2000 || priorities["slow"] != 3000 {
		t.Fatalf("unexpected speed ranking: %#v", priorities)
	}
}

func TestRankManagedAccountsDeprioritizesFirstTokenAboveStrategyLimit(t *testing.T) {
	items := []managedPolicyCandidate{
		eligiblePolicyCandidate("fast-1", .2, 1_000),
		eligiblePolicyCandidate("fast-2", .2, 2_000),
		eligiblePolicyCandidate("fast-3", .2, 3_000),
		eligiblePolicyCandidate("fast-4", .2, 4_000),
		eligiblePolicyCandidate("fast-5", .2, 5_000),
	}
	for index := range items {
		items[index].Schedulable = true
	}
	slow := eligiblePolicyCandidate("slow", .1, 12_000)
	items = append(items, slow)
	priorities := rankManagedAccounts(items, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: 10_000, MinAvailableChannels: 5})
	if priorities["fast-1"] != 1000 || priorities["fast-5"] != 5000 {
		t.Fatalf("unexpected normal priorities: %#v", priorities)
	}
	if priorities["slow"] != fallbackPriorityStart {
		t.Fatalf("slow candidate should receive a fallback priority: %#v", priorities)
	}
}

func TestPlanManagedAccountsAddsOnlyEnoughFastestSlowFallbacks(t *testing.T) {
	items := []managedPolicyCandidate{
		eligiblePolicyCandidate("normal-1", .2, 1_000),
		eligiblePolicyCandidate("normal-2", .2, 2_000),
		eligiblePolicyCandidate("normal-3", .2, 3_000),
		eligiblePolicyCandidate("slowest", .2, 30_000),
		eligiblePolicyCandidate("fallback-2", .2, 12_000),
		eligiblePolicyCandidate("fallback-1", .2, 11_000),
	}
	for index := 0; index < 3; index++ {
		items[index].Schedulable = true
	}
	plan := planManagedAccounts(items, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: 10_000, MinAvailableChannels: 5, PriorityStart: 1000, PriorityStep: 1000})
	if plan.NormalCount != 3 {
		t.Fatalf("normal count=%d, want 3", plan.NormalCount)
	}
	if plan.Priorities["fallback-1"] != fallbackPriorityStart || plan.Priorities["fallback-2"] != fallbackPriorityStart+1000 {
		t.Fatalf("unexpected fallback priorities: %#v", plan.Priorities)
	}
	if !plan.Fallback["fallback-1"] || !plan.Fallback["fallback-2"] {
		t.Fatalf("selected slow channels were not marked as fallback: %#v", plan.Fallback)
	}
	if plan.Priorities["slowest"] != fallbackPriorityStart+2000 || plan.Fallback["slowest"] {
		t.Fatalf("non-selected slow channels should remain as deprioritized capacity: %#v", plan)
	}
}

func TestManagedSchedulingEvidenceRequiresFreshPostBaselineEvidence(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	baseline := now.Add(-10 * time.Minute)
	candidate := managedPolicyCandidate{
		LatestProbeEvidenceAt: sql.NullTime{Time: baseline.Add(-time.Second), Valid: true},
	}
	if managedSchedulingEvidenceReady(candidate, baseline, now) {
		t.Fatal("pre-baseline probe evidence must not disable scheduling")
	}
	candidate.LatestProbeEvidenceAt = sql.NullTime{Time: baseline.Add(time.Second), Valid: true}
	if !managedSchedulingEvidenceReady(candidate, baseline, now) {
		t.Fatal("post-baseline probe evidence should allow scheduling decisions")
	}
	candidate.LatestProbeEvidenceAt = sql.NullTime{Time: now.Add(-managedEvidenceFreshness - time.Second), Valid: true}
	if managedSchedulingEvidenceReady(candidate, baseline, now) {
		t.Fatal("stale probe evidence must not disable scheduling")
	}
}

func TestPolicyRejectionReasonsDescribeBusinessFailureSeparately(t *testing.T) {
	candidate := eligiblePolicyCandidate("business-failure", .2, 120)
	candidate.BusinessConfirmedFailure = true
	candidate.BusinessRequests = 10
	candidate.BusinessErrors = 4
	candidate.StateReason = "最近流式抽样成功"
	reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 95, MinSamples: 5})
	if len(reasons) != 1 || reasons[0] != "近期真实业务已确认失败：错误率达到阈值：4/10（40.0%）" {
		t.Fatalf("unexpected business failure reason: %#v", reasons)
	}
}

func TestPlanManagedAccountsKeepsFallbackUntilFiveNormalChannelsAreActuallyScheduled(t *testing.T) {
	items := []managedPolicyCandidate{
		eligiblePolicyCandidate("normal-1", .2, 1_000),
		eligiblePolicyCandidate("normal-2", .2, 2_000),
		eligiblePolicyCandidate("normal-3", .2, 3_000),
		eligiblePolicyCandidate("normal-pending-1", .2, 4_000),
		eligiblePolicyCandidate("normal-pending-2", .2, 5_000),
		eligiblePolicyCandidate("fallback-1", .2, 11_000),
		eligiblePolicyCandidate("fallback-2", .2, 12_000),
	}
	for index := 0; index < 3; index++ {
		items[index].Schedulable = true
	}
	config := policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: 10_000, MinAvailableChannels: 5, PriorityStart: 1000, PriorityStep: 1000}
	plan := planManagedAccounts(items, config)
	if plan.NormalCount != 3 || !plan.Fallback["fallback-1"] || !plan.Fallback["fallback-2"] {
		t.Fatalf("fallback was removed before five normal channels were scheduled: %#v", plan)
	}
	items[3].Schedulable = true
	items[4].Schedulable = true
	plan = planManagedAccounts(items, config)
	if plan.NormalCount != 5 || len(plan.Fallback) != 0 {
		t.Fatalf("fallback remained after five normal channels were scheduled: %#v", plan)
	}
}

func TestRankManagedAccountsBySpeedPutsUnknownBusinessLatencyLast(t *testing.T) {
	known := eligiblePolicyCandidate("known", .5, 900)
	unknown := eligiblePolicyCandidate("unknown", .2, 100)
	unknown.FirstTokenP50 = sql.NullFloat64{}
	unknown.FirstTokenP90 = sql.NullFloat64{}
	priorities := rankManagedAccounts([]managedPolicyCandidate{unknown, known}, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5})
	if priorities["known"] != 1000 || priorities["unknown"] != 2000 {
		t.Fatalf("unknown real-business latency was not ranked last: %#v", priorities)
	}
}

func TestPlanManagedAccountsSeparatesObservingAndFallbackPriorityBands(t *testing.T) {
	normal := eligiblePolicyCandidate("normal", .2, 1_000)
	normal.Schedulable = true
	observing := eligiblePolicyCandidate("observing", .2, 9_000)
	observing.LatencyState = latencyStateObserving
	observing.Schedulable = true
	fallback := eligiblePolicyCandidate("fallback", .2, 11_000)
	plan := planManagedAccounts([]managedPolicyCandidate{fallback, observing, normal}, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: 10_000, MinAvailableChannels: 3, PriorityStart: 1000, PriorityStep: 1000})
	if plan.Priorities["normal"] != 1000 || plan.Priorities["observing"] != observingPriorityStart || plan.Priorities["fallback"] != fallbackPriorityStart {
		t.Fatalf("priority bands overlap: %#v", plan.Priorities)
	}
}

func TestQuickValidationUsesConsecutiveRecoverySamplesForSlowQuarantine(t *testing.T) {
	if got := quickValidationProbeLimit("QUARANTINED", slowFirstTokenReason(maxFirstTokenMs+1)); got != recoverySuccessSamples {
		t.Fatalf("slow quarantine probe limit=%d, want %d", got, recoverySuccessSamples)
	}
	if got := quickValidationProbeLimit("SUSPECT", "上游暂时失败"); got != 1 {
		t.Fatalf("ordinary validation probe limit=%d, want 1", got)
	}
}

func TestSlowFirstTokenQuarantineUsesSampledRecovery(t *testing.T) {
	candidate := eligiblePolicyCandidate("slow", .2, maxFirstTokenMs+1)
	candidate.State = "QUARANTINED"
	candidate.StateReason = slowFirstTokenReason(maxFirstTokenMs + 1)
	if !candidateCanRecoverWithProbe(candidate, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5}) {
		t.Fatal("slow first-token quarantine did not enter sampled recovery")
	}
	if !strings.Contains(candidate.StateReason, "60.00 秒超过 60 秒上限") {
		t.Fatalf("unexpected quarantine reason: %s", candidate.StateReason)
	}
}

func TestSlowRecoveryIntervalBacksOff(t *testing.T) {
	want := []int{60, 300, 1800, 7200, 21600, 86400, 86400}
	for failures, expected := range want {
		if got := slowRecoveryIntervalSeconds(failures, 0); got != expected {
			t.Fatalf("failures=%d interval=%d, want %d", failures, got, expected)
		}
	}
	if got := slowRecoveryIntervalSeconds(6, 1); got != 30 {
		t.Fatalf("successful recovery sample interval=%d, want 30", got)
	}
}

func TestSelectFirstTokenProbeModelSkipsNonTextModels(t *testing.T) {
	models := []string{"codex-auto-review", "text-embedding-3-small", "whisper-1", "gpt-4.1-mini"}
	if got := selectFirstTokenProbeModel(models); got != "gpt-4.1-mini" {
		t.Fatalf("selected model=%q", got)
	}
}

func TestTargetGroupProbeModelsKeepsOnlyPlatformTextModels(t *testing.T) {
	record := map[string]any{"models_list_config": map[string]any{"models": []any{"deepseek-v3", "codex-auto-review", "gpt-image-1", "gpt-5.5", "gpt-5.4"}}}
	models := targetGroupProbeModels(record, "openai")
	if !reflect.DeepEqual(models, []string{"gpt-5.5", "gpt-5.4"}) {
		t.Fatalf("probe models=%#v", models)
	}
	if got := preferredProbeModel("openai", models); got != "gpt-5.5" {
		t.Fatalf("preferred probe model=%q", got)
	}
}

func TestModelMappingForPlatformKeepsOnlyMatchingFamily(t *testing.T) {
	models := []string{"gpt-5.5", "codex-auto-review", "deepseek-v4-pro", "claude-sonnet-4-6", "gemini-3.5-flash", "grok-4.5"}
	tests := []struct {
		platform string
		expected string
	}{
		{"openai", "gpt-5.5"},
		{"anthropic", "claude-sonnet-4-6"},
		{"gemini", "gemini-3.5-flash"},
		{"grok", "grok-4.5"},
	}
	for _, test := range tests {
		mapping := modelMappingForPlatform(test.platform, models)
		if len(mapping) != 1 || mapping[test.expected] != test.expected {
			t.Fatalf("%s mapping=%#v", test.platform, mapping)
		}
	}
}

func TestModelMappingForPolicyExcludesDisabledModels(t *testing.T) {
	models := []string{"gpt-5.5", "gpt-5.4", "claude-sonnet-4-6"}
	mapping := modelMappingForPolicy("openai", models, []string{" gpt-5.4 ", "gpt-5.4"})
	if !reflect.DeepEqual(mapping, map[string]string{"gpt-5.5": "gpt-5.5"}) {
		t.Fatalf("policy mapping=%#v", mapping)
	}
}

func TestNormalizePolicyConfigNormalizesDisabledModels(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{ProbeModel: " custom-model-v2 ", DisabledModels: []string{" gpt-5.4 ", "", "gpt-5.5", "gpt-5.4"}})
	if config.ProbeModel != "custom-model-v2" {
		t.Fatalf("probe model=%q", config.ProbeModel)
	}
	if !reflect.DeepEqual(config.DisabledModels, []string{"gpt-5.4", "gpt-5.5"}) {
		t.Fatalf("disabled models=%#v", config.DisabledModels)
	}
}

func TestPolicyModelNamesAllowModelsOutsideDiscoveredList(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{ProbeModel: "future-text-model-2027", DisabledModels: []string{"legacy-special-model", "unlisted-preview-model"}})
	if err := validatePolicyModelNames(config); err != nil {
		t.Fatalf("manual model names were rejected: %v", err)
	}
	config.DisabledModels = append(config.DisabledModels, config.ProbeModel)
	if err := validatePolicyModelNames(config); err == nil {
		t.Fatal("probe model was allowed in disabled models")
	}
}

func TestDefaultProbeModelExistsForEveryManagedPlatform(t *testing.T) {
	if got := defaultProbeModelForPlatform("openai"); got != "gpt-5.6-sol" {
		t.Fatalf("OpenAI default probe model=%q, want gpt-5.6-sol", got)
	}
	for _, platform := range []string{"openai", "anthropic", "gemini", "grok", "custom"} {
		if model := defaultProbeModelForPlatform(platform); model == "" {
			t.Fatalf("platform %s has no default probe model", platform)
		}
	}
}

func TestPolicyRejectsAccountWithoutAllowedModels(t *testing.T) {
	candidate := eligiblePolicyCandidate("only-disabled", .2, 120)
	candidate.Platform = "openai"
	candidate.ModelsJSON = `["gpt-5.4"]`
	reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 95, MinSamples: 5, DisabledModels: []string{"gpt-5.4"}})
	if len(reasons) != 1 || !strings.Contains(reasons[0], "没有可用模型") {
		t.Fatalf("account without allowed models was not rejected: %#v", reasons)
	}
}

func TestUnconfirmedProbeFailureKeepsScheduledAccountEligible(t *testing.T) {
	candidate := eligiblePolicyCandidate("warming", .2, 120)
	candidate.Schedulable = true
	candidate.ConsecutiveFailures = 1
	candidate.ConfirmationFailures = 3
	candidate.SuccessRate = sql.NullFloat64{Float64: 0, Valid: true}
	if reasons := policyRejectionReasons(candidate, policyConfig{MinSuccessRate: 95, MinSamples: 5}); len(reasons) != 0 {
		t.Fatalf("unconfirmed failure stopped scheduling: %#v", reasons)
	}
}

func TestMeasureFirstTokenUsesStreamingGeneration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer probe-key" {
			t.Fatalf("unexpected authorization: %q", r.Header.Get("Authorization"))
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["model"] != "gpt-test" || payload["stream"] != true {
			t.Fatalf("unexpected payload: %#v", payload)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n"))
	}))
	defer server.Close()
	app := &App{httpClient: server.Client()}
	firstTokenMs, err := app.measureFirstToken(context.Background(), server.URL, "probe-key", "gpt-test")
	if err != nil {
		t.Fatal(err)
	}
	if firstTokenMs < 0 || firstTokenMs > 1000 {
		t.Fatalf("unexpected first token time: %dms", firstTokenMs)
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

func eligiblePolicyCandidate(id string, sourceMultiplier, firstTokenP50 float64) managedPolicyCandidate {
	latencyState := latencyStateNormal
	if firstTokenP50 > defaultPolicyMaxFirstTokenMs {
		latencyState = latencyStateSlow
	}
	return managedPolicyCandidate{
		ID: id, State: "HEALTHY", LatencyState: latencyState, Samples: 5, RecentSuccesses: recoverySuccessSamples,
		SourceMultiplier: sql.NullFloat64{Float64: sourceMultiplier, Valid: true},
		TargetMultiplier: sql.NullFloat64{Float64: 1, Valid: true},
		SuccessRate:      sql.NullFloat64{Float64: 100, Valid: true},
		FirstTokenP50:    sql.NullFloat64{Float64: firstTokenP50, Valid: true},
		FirstTokenP90:    sql.NullFloat64{Float64: firstTokenP50, Valid: true},
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

func TestMedianInt(t *testing.T) {
	values := []int{900, 100, 500, 300}
	if got := medianInt(values); got != 400 {
		t.Fatalf("median=%d, want 400", got)
	}
	if !reflect.DeepEqual(values, []int{900, 100, 500, 300}) {
		t.Fatalf("medianInt mutated its input: %#v", values)
	}
	if got := medianInt([]int{900, 100, 500}); got != 500 {
		t.Fatalf("odd median=%d, want 500", got)
	}
}

func TestManagedLatencyStateConfirmsSlowAndRecoversWithHysteresis(t *testing.T) {
	base := time.Now().UTC().Add(-10 * time.Minute)
	config := policyConfig{MaxFirstTokenMs: 10_000}
	candidate := eligiblePolicyCandidate("latency", .2, 11_000)
	candidate.LatencyState = latencyStateNormal
	candidate.SpeedMetricSamples = 20
	candidate.BusinessFirstToken = sql.NullFloat64{Float64: 11_000, Valid: true}
	candidate.BusinessFirstTokenP90 = sql.NullFloat64{Float64: 14_000, Valid: true}
	candidate.BusinessLatencyAt = sql.NullTime{Time: base, Valid: true}
	candidate.LatencyStateChangedAt = sql.NullTime{Time: base.Add(-time.Minute), Valid: true}

	updated, changed := nextManagedLatencyState(candidate, config, base.Add(time.Second))
	if !changed || updated.LatencyState != latencyStateObserving || updated.LatencyBadSnapshots != 1 {
		t.Fatalf("first slow snapshot=%#v, want observing 1/2", updated)
	}
	duplicate, changed := nextManagedLatencyState(updated, config, base.Add(30*time.Second))
	if changed || duplicate.LatencyBadSnapshots != 1 {
		t.Fatalf("same business snapshot was counted twice: %#v", duplicate)
	}

	updated.BusinessLatencyAt = sql.NullTime{Time: base.Add(time.Minute), Valid: true}
	updated, changed = nextManagedLatencyState(updated, config, base.Add(time.Minute+time.Second))
	if !changed || updated.LatencyState != latencyStateSlow || updated.LatencyBadSnapshots != 2 {
		t.Fatalf("second slow snapshot=%#v, want confirmed slow", updated)
	}

	for index := 2; index <= 4; index++ {
		updated.LatestProbeFirstToken = sql.NullFloat64{Float64: 6_000, Valid: true}
		updated.LatestProbeAt = sql.NullTime{Time: base.Add(time.Duration(index) * time.Minute), Valid: true}
		updated, changed = nextManagedLatencyState(updated, config, base.Add(time.Duration(index)*time.Minute+time.Second))
		if !changed || updated.LatencyState != latencyStateSlow {
			t.Fatalf("recovery sample %d changed state too early: %#v", index-1, updated)
		}
	}
	if updated.LatencyGoodSnapshots != latencyGoodSnapshots {
		t.Fatalf("good snapshots=%d, want %d", updated.LatencyGoodSnapshots, latencyGoodSnapshots)
	}
	updated, changed = nextManagedLatencyState(updated, config, base.Add(7*time.Minute))
	if !changed || updated.LatencyState != latencyStateNormal {
		t.Fatalf("confirmed recovery did not clear slow state: %#v", updated)
	}
}

func TestManagedLatencyStateNeedsEnoughBusinessSamples(t *testing.T) {
	now := time.Now().UTC()
	candidate := eligiblePolicyCandidate("sparse", .2, 12_000)
	candidate.LatencyState = latencyStateNormal
	candidate.SpeedMetricSamples = businessLatencyMinSamples - 1
	candidate.BusinessFirstToken = sql.NullFloat64{Float64: 12_000, Valid: true}
	candidate.BusinessFirstTokenP90 = sql.NullFloat64{Float64: 25_000, Valid: true}
	candidate.BusinessLatencyAt = sql.NullTime{Time: now, Valid: true}
	updated, changed := nextManagedLatencyState(candidate, policyConfig{MaxFirstTokenMs: 10_000}, now)
	if changed || updated.LatencyState != latencyStateNormal {
		t.Fatalf("sparse business window affected scheduling: %#v", updated)
	}
}

func TestManagedLatencyStateProtectsTailExperience(t *testing.T) {
	now := time.Now().UTC()
	candidate := eligiblePolicyCandidate("tail", .2, 5_000)
	candidate.SpeedMetricSamples = businessLatencyMinSamples
	candidate.BusinessFirstToken = sql.NullFloat64{Float64: 5_000, Valid: true}
	candidate.BusinessFirstTokenP90 = sql.NullFloat64{Float64: 21_000, Valid: true}
	candidate.BusinessLatencyAt = sql.NullTime{Time: now, Valid: true}
	updated, changed := nextManagedLatencyState(candidate, policyConfig{MaxFirstTokenMs: 10_000}, now)
	if !changed || updated.LatencyState != latencyStateSlow || updated.LatencyBadSnapshots != 1 {
		t.Fatalf("severely slow P90 tail was not stopped immediately: %#v", updated)
	}
}

func TestManagedLatencyStateUsesP90AsDirectSLA(t *testing.T) {
	now := time.Now().UTC()
	candidate := eligiblePolicyCandidate("tail-sla", .2, 5_000)
	candidate.SpeedMetricSamples = businessLatencyMinSamples
	candidate.BusinessFirstToken = sql.NullFloat64{Float64: 5_000, Valid: true}
	candidate.BusinessFirstTokenP90 = sql.NullFloat64{Float64: 11_000, Valid: true}
	candidate.BusinessLatencyAt = sql.NullTime{Time: now, Valid: true}
	updated, changed := nextManagedLatencyState(candidate, policyConfig{MaxFirstTokenMs: 10_000}, now)
	if !changed || updated.LatencyState != latencyStateObserving || updated.LatencyBadSnapshots != 1 {
		t.Fatalf("P90 above SLA did not enter observation: %#v", updated)
	}
}

func TestManagedLatencyStateStopsImmediatelyOnSevereSlowdown(t *testing.T) {
	now := time.Now().UTC()
	candidate := eligiblePolicyCandidate("severe", .2, 20_000)
	candidate.SpeedMetricSamples = businessLatencyMinSamples
	candidate.BusinessFirstToken = sql.NullFloat64{Float64: 20_000, Valid: true}
	candidate.BusinessFirstTokenP90 = sql.NullFloat64{Float64: 25_000, Valid: true}
	candidate.BusinessLatencyAt = sql.NullTime{Time: now, Valid: true}
	updated, changed := nextManagedLatencyState(candidate, policyConfig{MaxFirstTokenMs: 10_000}, now)
	if !changed || updated.LatencyState != latencyStateSlow || updated.LatencyBadSnapshots != 1 {
		t.Fatalf("severe slowdown was not stopped immediately: %#v", updated)
	}
}

func TestManagedLatencyStateRequiresExtraConfirmationForMixedModels(t *testing.T) {
	base := time.Now().UTC().Add(-time.Minute)
	candidate := eligiblePolicyCandidate("mixed", .2, 12_000)
	candidate.LatencyState = latencyStateNormal
	candidate.SpeedMetricModel = "ALL"
	candidate.SpeedMetricSamples = businessLatencyMinSamples
	candidate.BusinessFirstToken = sql.NullFloat64{Float64: 12_000, Valid: true}
	candidate.BusinessFirstTokenP90 = sql.NullFloat64{Float64: 18_000, Valid: true}
	config := policyConfig{MaxFirstTokenMs: 10_000, ProbeModel: "gpt-test"}
	for index := 0; index < 3; index++ {
		candidate.BusinessLatencyAt = sql.NullTime{Time: base.Add(time.Duration(index) * time.Second), Valid: true}
		candidate, _ = nextManagedLatencyState(candidate, config, base.Add(time.Duration(index+1)*time.Second))
		if index < 2 && candidate.LatencyState != latencyStateObserving {
			t.Fatalf("mixed-model snapshot %d confirmed too early: %#v", index+1, candidate)
		}
	}
	if candidate.LatencyState != latencyStateSlow || candidate.LatencyBadSnapshots != 3 {
		t.Fatalf("third mixed-model snapshot did not confirm slow state: %#v", candidate)
	}
}

func TestManagedLatencyStateDoesNotFlapAroundTenSecondBoundary(t *testing.T) {
	base := time.Now().UTC().Add(-10 * time.Minute)
	candidate := eligiblePolicyCandidate("boundary", .2, 12_027)
	candidate.LatencyState = latencyStateNormal
	candidate.LatencyStateChangedAt = sql.NullTime{Time: base.Add(-time.Minute), Valid: true}
	sequence := []struct {
		p50     float64
		p90     float64
		samples int
		state   string
		bad     int
	}{
		{12_027, 13_000, 10, latencyStateObserving, 1},
		{9_400, 9_800, 10, latencyStateObserving, 0},
		{11_029, 12_000, 10, latencyStateObserving, 1},
		{9_818, 9_900, 7, latencyStateObserving, 0},
	}
	for index, sample := range sequence {
		candidate.BusinessFirstToken = sql.NullFloat64{Float64: sample.p50, Valid: true}
		candidate.BusinessFirstTokenP90 = sql.NullFloat64{Float64: sample.p90, Valid: true}
		candidate.SpeedMetricSamples = sample.samples
		candidate.BusinessLatencyAt = sql.NullTime{Time: base.Add(time.Duration(index) * time.Minute), Valid: true}
		updated, _ := nextManagedLatencyState(candidate, policyConfig{MaxFirstTokenMs: 10_000}, base.Add(time.Duration(index)*time.Minute+time.Second))
		candidate = updated
		if candidate.LatencyState != sample.state || candidate.LatencyBadSnapshots != sample.bad {
			t.Fatalf("snapshot %d produced %#v, want state=%s bad=%d", index+1, candidate, sample.state, sample.bad)
		}
	}
}

func TestPercentileIntDoesNotMutateInput(t *testing.T) {
	values := []int{1000, 100, 900, 200, 800, 300, 700, 400, 600, 500}
	if got := percentileInt(values, .9); got != 900 {
		t.Fatalf("p90=%d, want 900", got)
	}
	if values[0] != 1000 || values[1] != 100 {
		t.Fatalf("percentileInt mutated input: %#v", values)
	}
}

func TestFetchRecentBusinessLatencyUsesRecentStreamingRecords(t *testing.T) {
	requested := 0
	latest := time.Now().UTC().Add(-time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested++
		if r.URL.Path != "/api/v1/admin/usage" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("account_id") != "42" || query.Get("page") != "1" || query.Get("page_size") != "50" {
			t.Fatalf("unexpected pagination query: %s", r.URL.RawQuery)
		}
		if query.Get("stream") != "true" || query.Get("sort_by") != "created_at" || query.Get("sort_order") != "desc" {
			t.Fatalf("unexpected usage filters: %s", r.URL.RawQuery)
		}
		items := make([]map[string]any, 0, 10)
		for index, firstToken := range []int{1000, 100, 900, 200, 800, 300, 700, 400, 600, 500} {
			items = append(items, map[string]any{
				"id":             index + 1,
				"account_id":     42,
				"first_token_ms": firstToken,
				"created_at":     latest.Add(-time.Duration(index) * time.Second).Format(time.RFC3339Nano),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"items": items, "pages": 1}})
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	snapshot, err := app.fetchRecentBusinessLatency(context.Background(), server.URL, "42", "", remoteSession{})
	if err != nil {
		t.Fatal(err)
	}
	if requested != 1 {
		t.Fatalf("usage requests=%d, want 1", requested)
	}
	if snapshot.Samples != 10 || snapshot.FirstTokenP50Ms != 550 || snapshot.FirstTokenP90Ms != 900 || !snapshot.LatestAt.Equal(latest) {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
}

func TestFetchRecentBusinessLatencyPrefersConfiguredModelWithEnoughSamples(t *testing.T) {
	latest := time.Now().UTC().Add(-time.Second)
	policySamples := 10
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		items := make([]map[string]any, 0, 20)
		for index := 0; index < 20; index++ {
			model := "slow-model"
			firstToken := 30_000
			if index < policySamples {
				model = "policy-model"
				firstToken = (index + 1) * 1_000
			}
			items = append(items, map[string]any{"account_id": 42, "model": model, "first_token_ms": firstToken, "created_at": latest.Add(-time.Duration(index) * time.Second).Format(time.RFC3339Nano)})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"items": items, "pages": 1}})
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	snapshot, err := app.fetchRecentBusinessLatency(context.Background(), server.URL, "42", "policy-model", remoteSession{})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Model != "policy-model" || snapshot.Samples != policySamples || snapshot.FirstTokenP50Ms != 5_500 || snapshot.FirstTokenP90Ms != 9_000 {
		t.Fatalf("configured model was not isolated: %#v", snapshot)
	}
}

func TestEffectiveSpeedMetricPrefersFreshBusinessAndFallsBackToProbe(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	business := sql.NullFloat64{Float64: 850, Valid: true}
	probe := sql.NullFloat64{Float64: 120, Valid: true}

	metric, source := effectiveSpeedMetric(business, sql.NullTime{Time: now.Add(-businessLatencyFreshness + time.Second), Valid: true}, probe, now)
	if !metric.Valid || metric.Float64 != 850 || source != "BUSINESS" {
		t.Fatalf("fresh business metric was not preferred: %#v %s", metric, source)
	}

	metric, source = effectiveSpeedMetric(business, sql.NullTime{Time: now.Add(-businessLatencyFreshness - time.Second), Valid: true}, probe, now)
	if !metric.Valid || metric.Float64 != 120 || source != "PROBE" {
		t.Fatalf("stale business metric did not fall back to probe: %#v %s", metric, source)
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

func TestSub2APIGroupMultiplierPrefersUserSpecificRate(t *testing.T) {
	record := map[string]any{"rate_multiplier": float64(.12)}
	rates := map[string]any{"43": float64(.5)}
	value := sub2APIGroupMultiplier(record, rates, "43")
	if value == nil || *value != .5 {
		t.Fatalf("unexpected user-specific multiplier: %v", value)
	}
	value = sub2APIGroupMultiplier(record, map[string]any{}, "43")
	if value == nil || *value != .12 {
		t.Fatalf("unexpected default group multiplier: %v", value)
	}
	value = sub2APIGroupMultiplier(record, map[string]any{"43": float64(0)}, "43")
	if value == nil || *value != 0 {
		t.Fatalf("unexpected zero user-specific multiplier: %v", value)
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

func TestRemoteInteractiveAuthRequiredClassification(t *testing.T) {
	for _, message := range []string{
		"Please complete the slider verification first",
		"AUTH_SESSION_LIMIT: Conflict",
		"远端登录会话上限",
	} {
		if !remoteInteractiveAuthRequired(&apiError{Status: 502, Code: "REMOTE_REJECTED", Message: message}) {
			t.Fatalf("interactive authentication error was not classified: %s", message)
		}
	}
	if remoteInteractiveAuthRequired(&apiError{Status: 502, Code: "REMOTE_REJECTED", Message: "INSUFFICIENT_BALANCE"}) {
		t.Fatal("ordinary remote rejection was classified as interactive authentication")
	}
}

func TestNormalizeDeploymentRequestUsesAsyncDefaults(t *testing.T) {
	request := sourceDeploymentRequest{TargetID: "target", SourceGroupIDs: []string{"source-group"}, TargetGroupIDs: []string{"target-group"}}
	if err := normalizeDeploymentRequest(&request); err != nil {
		t.Fatal(err)
	}
	if request.Priority != 1000 || request.Concurrency != 1000 {
		t.Fatalf("unexpected deployment defaults: %#v", request)
	}
	tooLarge := sourceDeploymentRequest{TargetID: "target", SourceGroupIDs: make([]string, 11), TargetGroupIDs: make([]string, 10)}
	if err := normalizeDeploymentRequest(&tooLarge); err == nil {
		t.Fatal("deployment larger than 100 mappings was accepted")
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

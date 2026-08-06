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
	accounts, err := app.createRemoteManagedAccounts(context.Background(), server.URL, remoteSession{}, "https://source.example", "源站", "分组 A", "sk-test", []string{"claude-test", "claude-allowed", "grok-test"}, targetGroups, 1000, 1000)
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
	accounts, err := app.createRemoteManagedAccounts(context.Background(), server.URL, remoteSession{}, "https://source.example", "源站", "分组 A", "sk-test", []string{"gpt-test"}, []deploymentTargetGroup{{ID: "local-1", Name: "成功", Platform: "openai", RemoteID: 11}, {ID: "local-2", Name: "失败", Platform: "openai", RemoteID: 22}}, 1000, 1000)
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

func TestBalanceForecastNeedsThreeConsumptionIntervals(t *testing.T) {
	start := time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC)
	forecast := calculateBalanceForecast([]balanceSample{
		{Balance: 100, CapturedAt: start},
		{Balance: 90, CapturedAt: start.Add(time.Hour)},
		{Balance: 80, CapturedAt: start.Add(2 * time.Hour)},
	})
	if forecast.Known {
		t.Fatalf("forecast should wait for three consumption intervals: %#v", forecast)
	}
}

func TestBalanceForecastRequiresConsecutiveThresholdBreaches(t *testing.T) {
	start := time.Date(2026, 7, 28, 8, 0, 0, 0, time.UTC)
	samples := []balanceSample{
		{Balance: 100, CapturedAt: start},
		{Balance: 99, CapturedAt: start.Add(time.Hour)},
		{Balance: 98, CapturedAt: start.Add(2 * time.Hour)},
		{Balance: 97, CapturedAt: start.Add(3 * time.Hour)},
		{Balance: 77, CapturedAt: start.Add(4 * time.Hour)},
	}
	if consecutiveBalanceForecasts(samples, 2, func(item balanceForecast) bool { return item.EtaHours < 10 }) {
		t.Fatal("a single short spike must not trigger a forecast alert")
	}
	samples = append(samples, balanceSample{Balance: 57, CapturedAt: start.Add(5 * time.Hour)})
	if consecutiveBalanceForecasts(samples, 2, func(item balanceForecast) bool { return item.EtaHours < 10 }) {
		t.Fatal("the first low-runway forecast must wait for confirmation")
	}
	samples = append(samples, balanceSample{Balance: 37, CapturedAt: start.Add(6 * time.Hour)})
	if consecutiveBalanceForecasts(samples, 2, func(item balanceForecast) bool { return item.EtaHours < 10 }) {
		t.Fatal("the previous forecast was still above the threshold")
	}
	samples = append(samples, balanceSample{Balance: 17, CapturedAt: start.Add(7 * time.Hour)})
	if !consecutiveBalanceForecasts(samples, 2, func(item balanceForecast) bool { return item.EtaHours < 10 }) {
		t.Fatal("two consecutive threshold breaches should trigger the alert")
	}
}

func TestRecommendedRechargeRoundsUpWithCoverageBuffer(t *testing.T) {
	if got := recommendedRecharge(12, 2, 14); got != 20 {
		t.Fatalf("recommended recharge = %.2f, want 20", got)
	}
}

func TestBalanceAlertLeadUsesNightAndWeekendWindows(t *testing.T) {
	if hours, period := balanceAlertLead(time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC), 4, 12, 36); hours != 4 || period != "工作时段" {
		t.Fatalf("unexpected work period: %d %s", hours, period)
	}
	if hours, period := balanceAlertLead(time.Date(2026, 7, 29, 22, 0, 0, 0, time.UTC), 4, 12, 36); hours != 12 || period != "夜间" {
		t.Fatalf("unexpected night period: %d %s", hours, period)
	}
	if hours, period := balanceAlertLead(time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC), 4, 12, 36); hours != 36 || period != "周末" {
		t.Fatalf("unexpected weekend period: %d %s", hours, period)
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
	if eventEmailSetting("GROUP_AVAILABILITY") != "email_alert_group_availability" {
		t.Fatal("group availability setting was not mapped")
	}
	if eventEmailSetting("ACCOUNT_MODEL_SYNC") != "email_alert_platform_sync" {
		t.Fatal("model mapping correction must use the account configuration setting")
	}
	if eventEmailSetting("TARGET_LOG") != "" {
		t.Fatal("unconfigured event category unexpectedly has an email setting")
	}
	if (&App{}).eventEmailEnabled(context.Background(), "TARGET_LOG", "P1") {
		t.Fatal("unconfigured event category was allowed to send email")
	}
	modelGuidance := eventEmailGuidanceFor("ACCOUNT_MODEL_SYNC", false)
	if modelGuidance.Scene != "账号模型映射校正失败" || !strings.Contains(modelGuidance.Action, "写入权限") {
		t.Fatalf("model correction guidance is incomplete: %#v", modelGuidance)
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
	if priorities["cheap"] != 1000 || priorities["middle"] != 1100 || priorities["expensive"] != 1200 {
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
	if priorities["fast"] != 1000 || priorities["middle"] != 1100 || priorities["slow"] != 1200 {
		t.Fatalf("unexpected speed ranking: %#v", priorities)
	}
}

func TestRankManagedAccountsBySpeedPutsUnknownBusinessLatencyLast(t *testing.T) {
	known := eligiblePolicyCandidate("known", .5, 900)
	unknown := eligiblePolicyCandidate("unknown", .2, 100)
	unknown.FirstTokenP95 = sql.NullFloat64{}
	priorities := rankManagedAccounts([]managedPolicyCandidate{unknown, known}, policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5})
	if priorities["known"] != 1000 || priorities["unknown"] != 1100 {
		t.Fatalf("unknown real-business latency was not ranked last: %#v", priorities)
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

func TestGroupAvailabilityAlertSuppressesOnlyColdStart(t *testing.T) {
	config := policyConfig{Mode: "PRICE", MinSuccessRate: 95, MinSamples: 5}
	warming := eligiblePolicyCandidate("warming", .2, 120)
	warming.Samples = 2
	warming.RecentSuccesses = 0
	warming.SuccessRate = sql.NullFloat64{}
	if groupNeedsAvailabilityAlert([]managedPolicyCandidate{warming}, config) {
		t.Fatal("sample-only cold start should not alert")
	}

	unhealthy := warming
	unhealthy.State = "OFFLINE"
	if !groupNeedsAvailabilityAlert([]managedPolicyCandidate{unhealthy}, config) {
		t.Fatal("offline group with no eligible account should alert")
	}

	overMultiplier := warming
	overMultiplier.SourceMultiplier.Float64 = 1.1
	if !groupNeedsAvailabilityAlert([]managedPolicyCandidate{overMultiplier}, config) {
		t.Fatal("multiplier violation with no eligible account should alert")
	}

	failedValidation := warming
	failedValidation.Samples = 5
	failedValidation.SuccessRate = sql.NullFloat64{Float64: 40, Valid: true}
	if !groupNeedsAvailabilityAlert([]managedPolicyCandidate{failedValidation}, config) {
		t.Fatal("qualified sample window with low success rate should alert")
	}
}

func eligiblePolicyCandidate(id string, sourceMultiplier, firstTokenP95 float64) managedPolicyCandidate {
	return managedPolicyCandidate{
		ID: id, State: "HEALTHY", Samples: 5, RecentSuccesses: recoverySuccessSamples,
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

func TestFetchRecentBusinessLatencyUsesTenLatestStreamingRecords(t *testing.T) {
	requested := 0
	latest := time.Date(2026, 7, 30, 12, 0, 0, 123000000, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested++
		if r.URL.Path != "/api/v1/admin/usage" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		query := r.URL.Query()
		if query.Get("account_id") != "42" || query.Get("page") != "1" || query.Get("page_size") != "10" {
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
	snapshot, err := app.fetchRecentBusinessLatency(context.Background(), server.URL, "42", remoteSession{})
	if err != nil {
		t.Fatal(err)
	}
	if requested != 1 {
		t.Fatalf("usage requests=%d, want 1", requested)
	}
	if snapshot.Samples != 10 || snapshot.FirstTokenMs != 550 || !snapshot.LatestAt.Equal(latest) {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
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

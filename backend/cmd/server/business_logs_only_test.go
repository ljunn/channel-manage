package main

import (
	"database/sql"
	"testing"
	"time"
)

// A probe failure must never block scheduling in logs-only mode, while a
// confirmed business-log failure still does.
func TestBusinessLogsOnlyIgnoresProbeFailuresForScheduling(t *testing.T) {
	item := eligiblePolicyCandidate("logs-only", .05, 120)
	item.BusinessLogsOnly = true
	item.State = "QUARANTINED"
	item.StateReason = "REMOTE_UNAUTHORIZED: 远端请求失败 (401)"
	item.ConsecutiveFailures = 12
	item.ConfirmationFailures = 3
	item.TransientConfirmationFailures = 6
	if managedProbeFailureBlocksScheduling(item) {
		t.Fatal("probe failure blocked scheduling in logs-only mode")
	}

	item.BusinessConfirmedFailure = true
	if !managedProbeFailureBlocksScheduling(item) {
		t.Fatal("confirmed business failure did not block scheduling in logs-only mode")
	}
}

// The same probe evidence keeps blocking scheduling when the mode is off, so
// the switch is the only thing that changes the verdict.
func TestProbeFailuresStillBlockSchedulingWhenModeOff(t *testing.T) {
	item := eligiblePolicyCandidate("normal-mode", .05, 120)
	item.State = "QUARANTINED"
	item.StateReason = "REMOTE_UNAUTHORIZED: 远端请求失败 (401)"
	item.ConsecutiveFailures = 12
	item.ConfirmationFailures = 3
	item.TransientConfirmationFailures = 6
	if !managedProbeFailureBlocksScheduling(item) {
		t.Fatal("probe failure stopped blocking scheduling with the mode off")
	}
}

// Probe-derived rejection reasons disappear in logs-only mode; business and
// manual criteria survive.
func TestBusinessLogsOnlySuppressesProbeRejectionReasons(t *testing.T) {
	config := policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: defaultPolicyMaxFirstTokenMs}
	item := eligiblePolicyCandidate("suppressed", .05, 120)
	item.BusinessLogsOnly = true
	item.State = "QUARANTINED"
	item.StateReason = "抽样请求失败 (500)"
	item.ConsecutiveFailures = 9
	item.ConfirmationFailures = 3
	item.Samples = 0
	item.SuccessRate = sql.NullFloat64{Float64: 0, Valid: true}
	item.RecentSuccesses = 0
	item.ModelCheckRequired = true
	item.ModelCheckStatus = modelCheckPending
	if reasons := policyRejectionReasons(item, config); len(reasons) != 0 {
		t.Fatalf("logs-only mode kept probe-derived rejection reasons: %v", reasons)
	}

	item.BusinessRequests = 100
	item.BusinessErrors = 90
	item.BusinessConfirmedFailure = true
	reasons := policyRejectionReasons(item, config)
	if len(reasons) != 1 {
		t.Fatalf("expected only the business failure reason, got %v", reasons)
	}
}

// A manual hold is an operator decision, not probe evidence, so it must still
// be reported in logs-only mode.
func TestBusinessLogsOnlyKeepsManualHoldRejection(t *testing.T) {
	config := policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: defaultPolicyMaxFirstTokenMs}
	item := eligiblePolicyCandidate("held", .05, 120)
	item.BusinessLogsOnly = true
	item.State = "MANUAL_HOLD"
	item.StateReason = "人工暂停"
	reasons := policyRejectionReasons(item, config)
	if len(reasons) == 0 {
		t.Fatal("manual hold was suppressed in logs-only mode")
	}
}

// The model-capability gate is not a negative criterion in logs-only mode.
func TestBusinessLogsOnlyDropsModelQualityGate(t *testing.T) {
	config := policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: defaultPolicyMaxFirstTokenMs}
	item := eligiblePolicyCandidate("quality-gated", .05, 120)
	item.BusinessLogsOnly = true
	item.ModelCheckRequired = true
	item.ModelCheckStatus = modelCheckFailed
	item.ModelCheckReason = "能力不足"
	item.SyncStatus = "SYNCED"
	if reasons := policyRejectionReasons(item, config); len(reasons) != 0 {
		t.Fatalf("model quality gate still rejected in logs-only mode: %v", reasons)
	}
	if !dynamicMultiplierCandidate(item, config) {
		t.Fatal("model quality gate excluded the candidate from dynamic pricing in logs-only mode")
	}

	item.BusinessLogsOnly = false
	if reasons := policyRejectionReasons(item, config); len(reasons) == 0 {
		t.Fatal("model quality gate stopped rejecting with the mode off")
	}
}

// A probe must remain available as the recovery mechanism even while the
// channel is held by probe-derived state or a failed capability check.
func TestBusinessLogsOnlyKeepsProbeRecoveryEligible(t *testing.T) {
	config := policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: defaultPolicyMaxFirstTokenMs}
	item := eligiblePolicyCandidate("recoverable", .05, 120)
	item.BusinessLogsOnly = true
	item.State = "QUARANTINED"
	item.StateReason = "REMOTE_UNAUTHORIZED: 远端请求失败 (401)"
	item.ModelCheckRequired = true
	item.ModelCheckStatus = modelCheckFailed
	if !candidateCanRecoverWithProbe(item, config) {
		t.Fatal("logs-only mode blocked the probe that is supposed to recover the channel")
	}

	item.BusinessConfirmedFailure = true
	if candidateCanRecoverWithProbe(item, config) {
		t.Fatal("a confirmed business failure still allowed probe recovery")
	}
}

// A slow probe sample may not deepen a business-derived latency hold, but a
// good one still lifts it.
func TestBusinessLogsOnlyProbeLatencyOnlyRecovers(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{Mode: "SPEED", MaxFirstTokenMs: 10_000})
	now := time.Now()
	base := eligiblePolicyCandidate("latency", .05, 120)
	base.BusinessLogsOnly = true
	base.LatencyState = latencyStateSlow
	base.LatencyBadSnapshots = 1
	base.LatestProbeAt = sql.NullTime{Time: now, Valid: true}
	base.BusinessFirstToken = sql.NullFloat64{}
	base.BusinessFirstTokenP90 = sql.NullFloat64{}

	slow := base
	slow.LatestProbeFirstToken = sql.NullFloat64{Float64: 30_000, Valid: true}
	updated, changed := nextManagedLatencyState(slow, config, now)
	if changed || updated.LatencyBadSnapshots != slow.LatencyBadSnapshots {
		t.Fatalf("a slow probe sample changed latency state in logs-only mode: %+v", updated)
	}

	good := base
	good.LatestProbeFirstToken = sql.NullFloat64{Float64: 1_000, Valid: true}
	updated, changed = nextManagedLatencyState(good, config, now)
	if !changed || updated.LatencyGoodSnapshots != 1 {
		t.Fatalf("a good probe sample did not count toward recovery: changed=%v state=%+v", changed, updated)
	}
}

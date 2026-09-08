package main

import (
	"database/sql"
	"fmt"
	"testing"
)

func speedRankCandidate(id string, p50, p90 float64, storedPriority int) managedPolicyCandidate {
	return managedPolicyCandidate{
		ID: id, State: "HEALTHY", LatencyState: latencyStateNormal, SyncStatus: "SYNCED",
		Samples: 10, RecentSuccesses: recoverySuccessSamples, Priority: storedPriority,
		SourceMultiplier: sql.NullFloat64{Float64: .05, Valid: true},
		TargetMultiplier: sql.NullFloat64{Float64: 1, Valid: true},
		SuccessRate:      sql.NullFloat64{Float64: 100, Valid: true},
		FirstTokenP50:    sql.NullFloat64{Float64: p50, Valid: true},
		FirstTokenP90:    sql.NullFloat64{Float64: p90, Valid: true},
	}
}

// Regression: SPEED mode used to sort by the coarse 5-band bucket and then by
// the previously stored priority. Because a 10s limit puts nearly every real
// channel in band 0, the stored priority decided the order and the ranking was
// self-referential, so a 2.8s channel could outrank a 150ms one.
func TestSpeedModeRanksFastestFirstRegardlessOfStoredPriority(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{Mode: "SPEED"})
	// Stored priority is deliberately the inverse of real speed.
	items := []managedPolicyCandidate{
		speedRankCandidate("slow-2800ms", 2800, 2900, 1000),
		speedRankCandidate("fast-300ms", 300, 400, 2000),
		speedRankCandidate("mid-1500ms", 1500, 1600, 3000),
		speedRankCandidate("fastest-150ms", 150, 200, 4000),
	}
	priorities := planManagedAccounts(items, config).Priorities

	order := []string{"fastest-150ms", "fast-300ms", "mid-1500ms", "slow-2800ms"}
	for index := 1; index < len(order); index++ {
		if priorities[order[index-1]] >= priorities[order[index]] {
			t.Fatalf("%s (priority %d) did not rank ahead of %s (priority %d): %#v",
				order[index-1], priorities[order[index-1]], order[index], priorities[order[index]], priorities)
		}
	}
	if priorities["fastest-150ms"] != config.PriorityStart {
		t.Fatalf("fastest channel did not take the first slot: %#v", priorities)
	}
}

// All channels well inside the first-token limit must still be separated by
// speed. This is the case the old band logic collapsed into a single bucket.
func TestSpeedModeSeparatesChannelsInsideTheSameOldBand(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{Mode: "SPEED", MaxFirstTokenMs: 10_000})
	items := []managedPolicyCandidate{
		speedRankCandidate("c-2500", 2500, 2600, 1000),
		speedRankCandidate("c-200", 200, 250, 1000),
		speedRankCandidate("c-1200", 1200, 1300, 1000),
	}
	priorities := planManagedAccounts(items, config).Priorities
	if priorities["c-200"] >= priorities["c-1200"] || priorities["c-1200"] >= priorities["c-2500"] {
		t.Fatalf("channels inside the old band 0 were not separated by speed: %#v", priorities)
	}
}

// Near-identical speeds must not reshuffle on every evaluation, otherwise the
// scheduler churns priorities and thrashes the target node.
func TestSpeedModeKeepsNearIdenticalSpeedsStable(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{Mode: "SPEED"})
	items := []managedPolicyCandidate{
		speedRankCandidate("settled-second", 1020, 1020, 2000),
		speedRankCandidate("settled-first", 1000, 1000, 1000),
	}
	priorities := planManagedAccounts(items, config).Priorities
	if priorities["settled-first"] >= priorities["settled-second"] {
		t.Fatalf("stable tiebreak did not preserve the settled order: %#v", priorities)
	}

	// A difference beyond the stability band must re-rank despite stored order.
	items[0] = speedRankCandidate("settled-second", 300, 300, 2000)
	priorities = planManagedAccounts(items, config).Priorities
	if priorities["settled-second"] >= priorities["settled-first"] {
		t.Fatalf("a clearly faster channel did not overtake a settled slower one: %#v", priorities)
	}
}

func TestPolicySpeedScoreWeightsP90AndHandlesMissingData(t *testing.T) {
	weighted := policySpeedScore(speedRankCandidate("weighted", 1000, 2000, 0))
	if !weighted.Valid || weighted.Float64 != .6*1000+.4*2000 {
		t.Fatalf("weighted speed score=%v, want 1400", weighted)
	}

	p50Only := speedRankCandidate("p50-only", 1000, 0, 0)
	p50Only.FirstTokenP90 = sql.NullFloat64{}
	if score := policySpeedScore(p50Only); !score.Valid || score.Float64 != 1000 {
		t.Fatalf("p50-only score=%v, want 1000", score)
	}

	unknown := speedRankCandidate("unknown", 0, 0, 0)
	unknown.FirstTokenP50 = sql.NullFloat64{}
	unknown.FirstTokenP90 = sql.NullFloat64{}
	if score := policySpeedScore(unknown); score.Valid {
		t.Fatalf("missing latency produced a valid score: %v", score)
	}
}

// Priority numbers should stay readable instead of climbing into the tens of
// thousands for an ordinary channel count.
func TestPriorityMagnitudeStaysReadableForRealisticChannelCounts(t *testing.T) {
	config := normalizePolicyConfig(policyConfig{Mode: "SPEED"})
	items := make([]managedPolicyCandidate, 0, 40)
	for index := 0; index < 40; index++ {
		latency := float64(200 + index*50)
		items = append(items, speedRankCandidate(fmt.Sprintf("ch-%02d", index), latency, latency, 1000))
	}
	priorities := planManagedAccounts(items, config).Priorities
	highest := 0
	for _, priority := range priorities {
		if priority > highest {
			highest = priority
		}
	}
	if highest >= 10_000 {
		t.Fatalf("40 channels produced priority %d, expected the normal tier to stay below 10000", highest)
	}
	if priorities["ch-00"] != config.PriorityStart {
		t.Fatalf("fastest channel did not take the priority start slot: %d", priorities["ch-00"])
	}
}

// A healthy channel carrying real business traffic must not be dropped from
// scheduling just because probe-derived sample volume or probe success rate is
// short; that difference belongs in the ordering, not in an exclusion.
func TestHealthyChannelWithBusinessTrafficSurvivesProbeSampleShortfall(t *testing.T) {
	config := policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: defaultPolicyMaxFirstTokenMs}
	item := speedRankCandidate("live-traffic", 400, 500, 1000)
	item.Samples = 0
	item.SuccessRate = sql.NullFloat64{Float64: 10, Valid: true}
	item.RecentSuccesses = 0
	item.BusinessRequests = 250
	item.BusinessErrors = 1
	if reasons := policyRejectionReasons(item, config); len(reasons) != 0 {
		t.Fatalf("healthy channel with real traffic was rejected on probe evidence: %v", reasons)
	}

	// Without business traffic the probe thresholds still apply.
	item.BusinessRequests = 0
	item.BusinessErrors = 0
	if reasons := policyRejectionReasons(item, config); len(reasons) == 0 {
		t.Fatal("probe thresholds stopped applying to a channel with no business traffic")
	}
}

// The relaxation must not rescue a channel that business logs have confirmed
// to be failing.
func TestBusinessConfirmedFailureStillRejectsDespiteRelaxation(t *testing.T) {
	config := policyConfig{Mode: "SPEED", MinSuccessRate: 95, MinSamples: 5, MaxFirstTokenMs: defaultPolicyMaxFirstTokenMs}
	item := speedRankCandidate("failing", 400, 500, 1000)
	item.BusinessRequests = 200
	item.BusinessErrors = 180
	item.BusinessConfirmedFailure = true
	if reasons := policyRejectionReasons(item, config); len(reasons) == 0 {
		t.Fatal("a business-confirmed failure was allowed to schedule")
	}
}

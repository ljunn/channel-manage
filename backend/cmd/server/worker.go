package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fastProbeIntervalSeconds = 15
	recoverySuccessSamples   = 3
	maxConcurrentProbes      = 6
	managedPriorityStart     = 1000
	managedPriorityStep      = 100
	maxFirstTokenMs          = 60_000
	businessLatencyFreshness = 15 * time.Minute
)

func (a *App) runScheduler(ctx context.Context) {
	recoveryTicker := time.NewTicker(15 * time.Second)
	maintenanceTicker := time.NewTicker(30 * time.Second)
	defer recoveryTicker.Stop()
	defer maintenanceTicker.Stop()
	a.runAutomation(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-recoveryTicker.C:
			a.runRecovery(ctx)
		case <-maintenanceTicker.C:
			a.runMaintenance(ctx)
		}
	}
}

func (a *App) runAutomation(ctx context.Context) {
	a.runRecovery(ctx)
	a.runMaintenance(ctx)
}

func (a *App) runRecovery(ctx context.Context) {
	if !a.recoveryMu.TryLock() {
		return
	}
	defer a.recoveryMu.Unlock()
	a.probeDueChannels(ctx)
	if err := a.evaluateManagedAccounts(ctx); err != nil {
		log.Printf("策略评估失败: %v", err)
	}
}

func (a *App) runMaintenance(ctx context.Context) {
	if !a.workerMu.TryLock() {
		return
	}
	defer a.workerMu.Unlock()
	a.scanDueSources(ctx)
	a.syncDueTargets(ctx)
	a.syncDueTargetMetrics(ctx)
}

func (a *App) runPolicyEvaluation(ctx context.Context) {
	a.recoveryMu.Lock()
	defer a.recoveryMu.Unlock()
	if err := a.evaluateManagedAccounts(ctx); err != nil {
		log.Printf("策略评估失败: %v", err)
	}
}

func (a *App) scanDueSources(ctx context.Context) {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM sources WHERE status='ACTIVE' AND scan_status NOT IN ('RUNNING','AUTH_REQUIRED') AND (last_scan_at IS NULL OR last_scan_at + (CASE WHEN manually_untrusted THEN GREATEST(scan_interval_seconds,86400) ELSE scan_interval_seconds END) * interval '1 second' <= now())`)
	if err != nil {
		log.Printf("读取待扫描数据源失败: %v", err)
		return
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		if err := a.scanSource(ctx, id); err != nil {
			log.Printf("数据源 %s 扫描失败: %v", id, err)
		}
	}
}

func (a *App) syncDueTargets(ctx context.Context) {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM targets t WHERE last_sync_at IS NULL OR last_sync_at<now()-interval '15 minutes' OR EXISTS(SELECT 1 FROM managed_accounts m WHERE m.target_id=t.id AND m.rate_multiplier IS NULL)`)
	if err != nil {
		return
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		if err := a.syncTarget(ctx, id); err != nil {
			log.Printf("目标 %s 同步失败: %v", id, err)
		}
	}
}

func (a *App) probeDueChannels(ctx context.Context) {
	interval := a.settingInt(ctx, "probe_interval_seconds", 900)
	fastIntervals := a.fastProbeIntervals(ctx)
	rows, err := a.db.QueryContext(ctx, `SELECT c.id,c.last_probe_at FROM channels c JOIN sources s ON s.id=c.source_id WHERE c.lifecycle_state<>'MANUAL_HOLD' AND s.manually_untrusted=false`)
	if err != nil {
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		var lastProbe sql.NullTime
		if rows.Scan(&id, &lastProbe) == nil {
			dueInterval := interval
			if fastInterval, fast := fastIntervals[id]; fast {
				dueInterval = fastInterval
			}
			if lastProbe.Valid && time.Since(lastProbe.Time) < time.Duration(dueInterval)*time.Second {
				continue
			}
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	a.probeChannels(ctx, ids)
}

func (a *App) fastProbeIntervals(ctx context.Context) map[string]int {
	result := map[string]int{}
	slowRows, slowErr := a.db.QueryContext(ctx, `SELECT c.id,c.consecutive_failures,
		COALESCE((SELECT count(*) FROM (
			SELECT bool_and(success) OVER (ORDER BY started_at DESC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS success_streak
			FROM (SELECT started_at,success FROM probe_runs p WHERE p.channel_id=c.id AND p.kind='RECOVERY' ORDER BY p.started_at DESC LIMIT $1) recent
		) streak WHERE success_streak),0)
		FROM channels c WHERE c.lifecycle_state='QUARANTINED' AND c.state_reason LIKE '%真实业务首 Token%'`, recoverySuccessSamples)
	if slowErr == nil {
		for slowRows.Next() {
			var channelID string
			var failures, successes int
			if slowRows.Scan(&channelID, &failures, &successes) == nil {
				result[channelID] = slowRecoveryIntervalSeconds(failures, successes)
			}
		}
		_ = slowRows.Close()
	}
	configs := map[string]policyConfig{}
	rows, err := a.db.QueryContext(ctx, `SELECT p.scope_id,v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE p.status='ACTIVE' AND p.scope_type='TARGET_GROUP'`)
	if err != nil {
		return result
	}
	for rows.Next() {
		var scopeID, configData string
		if rows.Scan(&scopeID, &configData) == nil {
			var config policyConfig
			_ = json.Unmarshal([]byte(configData), &config)
			configs[scopeID] = normalizePolicyConfig(config)
		}
	}
	_ = rows.Close()
	if len(configs) == 0 {
		return result
	}
	candidates, err := a.managedPolicyCandidates(ctx)
	if err != nil {
		return result
	}
	for _, candidate := range candidates {
		if _, slowRecovery := result[candidate.ChannelID]; slowRecovery {
			continue
		}
		config, configured := configs[candidate.TargetGroupID]
		if !configured || !candidateCanRecoverWithProbe(candidate, config) {
			continue
		}
		if len(policyRejectionReasons(candidate, config)) == 0 {
			continue
		}
		probeInterval := fastProbeIntervalFor(candidate)
		if current, exists := result[candidate.ChannelID]; !exists || probeInterval < current {
			result[candidate.ChannelID] = probeInterval
		}
	}
	return result
}

func fastProbeIntervalFor(item managedPolicyCandidate) int {
	if isSlowFirstTokenQuarantine(item.State, item.StateReason) {
		return slowRecoveryIntervalSeconds(item.ConsecutiveFailures, item.RecoverySuccesses)
	}
	if item.RecentSuccesses > 0 || item.ConsecutiveFailures <= 3 {
		return fastProbeIntervalSeconds
	}
	if item.ConsecutiveFailures <= 10 {
		return 60
	}
	return 300
}

func candidateCanRecoverWithProbe(item managedPolicyCandidate, config policyConfig) bool {
	if item.SourceUntrusted || item.SourcePaused || item.State == "MANUAL_HOLD" || !policyMultiplierQualified(item, config) || !policyHasAllowedModels(item, config) {
		return false
	}
	return item.Samples < config.MinSamples || item.State != "HEALTHY" || !policySuccessQualified(item, config)
}

func (a *App) probeChannels(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	requested := make(map[string]bool, len(ids))
	for _, id := range ids {
		requested[id] = true
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id,source_id FROM channels ORDER BY source_id,created_at`)
	if err != nil {
		log.Printf("读取渠道探测队列失败: %v", err)
		return
	}
	bySource := map[string][]string{}
	for rows.Next() {
		var id, sourceID string
		if rows.Scan(&id, &sourceID) == nil && requested[id] {
			bySource[sourceID] = append(bySource[sourceID], id)
		}
	}
	_ = rows.Close()
	queues := make([][]string, 0, len(bySource))
	for _, queue := range bySource {
		queues = append(queues, queue)
	}
	if len(queues) == 0 {
		return
	}
	jobs := make(chan []string)
	var workers sync.WaitGroup
	for worker := 0; worker < min(maxConcurrentProbes, len(queues)); worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for queue := range jobs {
				for _, id := range queue {
					if err := a.probeChannel(ctx, id); err != nil {
						log.Printf("渠道 %s 探测失败: %v", id, err)
					}
				}
			}
		}()
	}
	for _, queue := range queues {
		select {
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return
		case jobs <- queue:
		}
	}
	close(jobs)
	workers.Wait()
}

func (a *App) evaluateManagedAccounts(ctx context.Context) error {
	policyRows, err := a.db.QueryContext(ctx, `SELECT p.id,p.scope_id,v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE p.status='ACTIVE' AND p.scope_type='TARGET_GROUP' ORDER BY p.updated_at`)
	if err != nil {
		return err
	}
	type activePolicy struct {
		ID, ScopeID string
		Config      policyConfig
	}
	policies := []activePolicy{}
	for policyRows.Next() {
		var policy activePolicy
		var configData string
		if err := policyRows.Scan(&policy.ID, &policy.ScopeID, &configData); err != nil {
			policyRows.Close()
			return err
		}
		_ = json.Unmarshal([]byte(configData), &policy.Config)
		policy.Config = normalizePolicyConfig(policy.Config)
		policies = append(policies, policy)
	}
	if err := policyRows.Close(); err != nil {
		return err
	}
	if len(policies) == 0 {
		return nil
	}
	if err := a.ensureManagedTargetMultiplierCaches(ctx); err != nil {
		return err
	}
	items, err := a.managedPolicyCandidates(ctx)
	if err != nil {
		return err
	}
	shadow, _ := a.settingBool(ctx, "shadow_mode")
	frozen, _ := a.settingBool(ctx, "emergency_freeze")
	if shadow || frozen {
		return nil
	}
	for _, policy := range policies {
		groupItems := candidatesForTargetGroup(items, policy.ScopeID)
		desiredPriority := rankManagedAccounts(groupItems, policy.Config)
		if len(groupItems) > 0 && len(desiredPriority) == 0 && groupNeedsAvailabilityAlert(groupItems, policy.Config) {
			detail := fmt.Sprintf("%s / %s 当前没有任何符合策略的托管账号。系统仍在快速复检可恢复渠道，请检查源站余额、渠道状态和倍率。", groupItems[0].TargetName, groupItems[0].TargetGroup)
			a.openEvent(ctx, "P1", "GROUP_AVAILABILITY", "目标分组无可用账号", detail, "group-availability:"+policy.ScopeID)
		} else if len(desiredPriority) > 0 {
			a.resolveEvent(ctx, "group-availability:"+policy.ScopeID)
		}
		for _, item := range groupItems {
			reasons := policyRejectionReasons(item, policy.Config)
			desired := len(reasons) == 0
			if desired != item.Schedulable {
				reason := "渠道与目标分组倍率均符合策略，自动恢复参与调度"
				if !desired {
					reason = strings.Join(reasons, "；")
				}
				a.enqueueManagedAction(ctx, item.ID, "SET_SCHEDULABLE", map[string]bool{"schedulable": item.Schedulable}, map[string]bool{"schedulable": desired}, reason)
			}
			priority, ranked := desiredPriority[item.ID]
			if ranked && priority != item.Priority {
				reason := fmt.Sprintf("%s策略自动排序：%s 调整为优先级 %d", policyModeText(policy.Config.Mode), item.SourceGroup, priority)
				a.enqueueManagedAction(ctx, item.ID, "SET_PRIORITY", map[string]int{"priority": item.Priority}, map[string]int{"priority": priority}, reason)
			}
		}
	}
	return nil
}

func groupNeedsAvailabilityAlert(items []managedPolicyCandidate, config policyConfig) bool {
	config = normalizePolicyConfig(config)
	for _, item := range items {
		if item.Schedulable || item.State != "HEALTHY" {
			return true
		}
		if !policyMultiplierQualified(item, config) {
			return true
		}
		if item.Samples >= config.MinSamples && !policySuccessQualified(item, config) {
			return true
		}
	}
	return false
}

func (a *App) enqueueManagedAction(ctx context.Context, managedID, action string, before, after any, reason string) {
	key := stableKey(managedID, action, jsonValue(before), jsonValue(after))
	var id string
	err := a.db.QueryRowContext(ctx, `INSERT INTO action_intents(managed_account_id,action_type,before_state,after_state,reason,status,idempotency_key,approved_at) VALUES($1,$2,$3,$4,$5,'APPROVED',$6,now()) ON CONFLICT DO NOTHING RETURNING id`, managedID, action, jsonValue(before), jsonValue(after), reason, key).Scan(&id)
	if err == nil {
		go a.executeAction(context.Background(), id)
	}
}

type managedPolicyCandidate struct {
	ID, ChannelID, TargetGroupID, RemoteName, SourceName, TargetName string
	State, StateReason, SourceGroup, TargetGroup, SyncStatus         string
	Platform, ModelsJSON                                             string
	SpeedMetricSource                                                string
	Schedulable                                                      bool
	SourceUntrusted                                                  bool
	SourcePaused                                                     bool
	Priority                                                         int
	SourceMultiplier, TargetMultiplier, SuccessRate, FirstTokenP95   sql.NullFloat64
	BusinessFirstToken, ProbeFirstTokenP95                           sql.NullFloat64
	BusinessLatencyAt                                                sql.NullTime
	Samples, RecentSuccesses, RecoverySuccesses, ConsecutiveFailures int
	SpeedMetricSamples                                               int
	ConfirmationFailures                                             int
}

const policyMetricWindowDays = 7

func (a *App) managedPolicyCandidates(ctx context.Context) ([]managedPolicyCandidate, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,c.id,COALESCE(min(tg.id::text),''),m.remote_name,min(s.name),min(t.name),m.schedulable,m.priority,m.sync_status,c.lifecycle_state,c.state_reason,c.consecutive_failures,COALESCE(sg.name,''),COALESCE(string_agg(tg.name,'、' ORDER BY tg.name),''),sg.multiplier,min(tg.multiplier),m.platform,min(k.models::text),bool_or(s.manually_untrusted),bool_or(s.scheduling_paused),
		(SELECT count(*) FROM probe_runs p WHERE p.channel_id=c.id AND p.started_at>now()-$1 * interval '1 day'),
		(SELECT avg(CASE WHEN p.success THEN 100.0 ELSE 0 END) FROM probe_runs p WHERE p.channel_id=c.id AND p.started_at>now()-$1 * interval '1 day'),
		m.business_first_token_ms,m.business_latency_samples,m.business_latency_at,
		(SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY p.first_token_ms) FROM probe_runs p WHERE p.channel_id=c.id AND p.success AND p.first_token_ms IS NOT NULL AND p.started_at>now()-interval '1 hour'),
		(SELECT count(*) FROM (
			SELECT bool_and(success) OVER (ORDER BY started_at DESC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS success_streak
			FROM (SELECT started_at,success FROM probe_runs p WHERE p.channel_id=c.id ORDER BY p.started_at DESC LIMIT $2) recent
		) streak WHERE success_streak),
		(SELECT count(*) FROM (
			SELECT bool_and(success) OVER (ORDER BY started_at DESC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS success_streak
			FROM (SELECT started_at,success FROM probe_runs p WHERE p.channel_id=c.id AND p.kind='RECOVERY' ORDER BY p.started_at DESC LIMIT $2) recent
		) streak WHERE success_streak)
		FROM managed_accounts m JOIN channels c ON c.id=m.channel_id JOIN source_keys k ON k.id=c.source_key_id JOIN sources s ON s.id=c.source_id JOIN targets t ON t.id=m.target_id LEFT JOIN source_groups sg ON sg.id=c.source_group_id LEFT JOIN managed_account_groups mg ON mg.managed_account_id=m.id LEFT JOIN target_groups tg ON tg.id=mg.target_group_id
		GROUP BY m.id,c.id,sg.id ORDER BY m.created_at`, policyMetricWindowDays, recoverySuccessSamples)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []managedPolicyCandidate{}
	confirmationFailures := a.settingInt(ctx, "confirmation_failures", 3)
	for rows.Next() {
		var item managedPolicyCandidate
		if err := rows.Scan(&item.ID, &item.ChannelID, &item.TargetGroupID, &item.RemoteName, &item.SourceName, &item.TargetName, &item.Schedulable, &item.Priority, &item.SyncStatus, &item.State, &item.StateReason, &item.ConsecutiveFailures, &item.SourceGroup, &item.TargetGroup, &item.SourceMultiplier, &item.TargetMultiplier, &item.Platform, &item.ModelsJSON, &item.SourceUntrusted, &item.SourcePaused, &item.Samples, &item.SuccessRate, &item.BusinessFirstToken, &item.SpeedMetricSamples, &item.BusinessLatencyAt, &item.ProbeFirstTokenP95, &item.RecentSuccesses, &item.RecoverySuccesses); err != nil {
			return nil, err
		}
		item.FirstTokenP95, item.SpeedMetricSource = effectiveSpeedMetric(item.BusinessFirstToken, item.BusinessLatencyAt, item.ProbeFirstTokenP95, time.Now())
		if item.SpeedMetricSource != "BUSINESS" {
			item.SpeedMetricSamples = 0
		}
		item.ConfirmationFailures = confirmationFailures
		items = append(items, item)
	}
	return items, rows.Err()
}

func effectiveSpeedMetric(business sql.NullFloat64, businessAt sql.NullTime, probe sql.NullFloat64, now time.Time) (sql.NullFloat64, string) {
	if business.Valid && businessAt.Valid && now.Sub(businessAt.Time) <= businessLatencyFreshness {
		return business, "BUSINESS"
	}
	if probe.Valid {
		return probe, "PROBE"
	}
	return sql.NullFloat64{}, ""
}

func candidatesForTargetGroup(items []managedPolicyCandidate, targetGroupID string) []managedPolicyCandidate {
	result := []managedPolicyCandidate{}
	for _, item := range items {
		if item.TargetGroupID == targetGroupID {
			result = append(result, item)
		}
	}
	return result
}

func rankManagedAccounts(items []managedPolicyCandidate, config policyConfig) map[string]int {
	eligible := []managedPolicyCandidate{}
	config = normalizePolicyConfig(config)
	for _, item := range items {
		if len(policyRejectionReasons(item, config)) == 0 {
			eligible = append(eligible, item)
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		if config.Mode == "SPEED" {
			if eligible[i].FirstTokenP95.Valid != eligible[j].FirstTokenP95.Valid {
				return eligible[i].FirstTokenP95.Valid
			}
			if eligible[i].FirstTokenP95.Valid && eligible[i].FirstTokenP95.Float64 != eligible[j].FirstTokenP95.Float64 {
				return eligible[i].FirstTokenP95.Float64 < eligible[j].FirstTokenP95.Float64
			}
		} else if eligible[i].SourceMultiplier.Valid && eligible[j].SourceMultiplier.Valid && eligible[i].SourceMultiplier.Float64 != eligible[j].SourceMultiplier.Float64 {
			return eligible[i].SourceMultiplier.Float64 < eligible[j].SourceMultiplier.Float64
		}
		return eligible[i].ID < eligible[j].ID
	})
	result := map[string]int{}
	for index, item := range eligible {
		result[item.ID] = managedPriorityStart + index*managedPriorityStep
	}
	return result
}

func policyModeText(mode string) string {
	if mode == "SPEED" {
		return "速度优先"
	}
	return "价格优先"
}

func policyRejectionReasons(item managedPolicyCandidate, config policyConfig) []string {
	config = normalizePolicyConfig(config)
	reasons := []string{}
	if item.SourceUntrusted {
		reasons = append(reasons, "数据源已被人工标记为不可信")
	}
	if item.SourcePaused {
		reasons = append(reasons, "数据源已人工暂停调度")
	}
	unconfirmed := unconfirmedProbeFailure(item)
	if item.State != "HEALTHY" && !unconfirmed {
		reasons = append(reasons, "渠道状态为 "+item.State+"："+item.StateReason)
	}
	if !policyHasAllowedModels(item, config) {
		reasons = append(reasons, "源渠道在应用分组禁用清单后没有可用模型")
	}
	if !item.SourceMultiplier.Valid || !item.TargetMultiplier.Valid {
		reasons = append(reasons, "源分组或目标分组倍率缺失")
	} else if item.SourceMultiplier.Float64 > item.TargetMultiplier.Float64+multiplierComparisonTolerance {
		reasons = append(reasons, fmt.Sprintf("源分组倍率 %.4fx 超过目标分组上限 %.4fx", item.SourceMultiplier.Float64, item.TargetMultiplier.Float64))
	} else if !config.AllowEqualMultiplier && item.SourceMultiplier.Float64 >= item.TargetMultiplier.Float64-multiplierComparisonTolerance {
		reasons = append(reasons, fmt.Sprintf("源分组倍率 %.4fx 与目标分组倍率 %.4fx 相同，策略未允许等倍率账号参与", item.SourceMultiplier.Float64, item.TargetMultiplier.Float64))
	}
	if item.Samples < config.MinSamples && !(item.Schedulable && unconfirmed) {
		reasons = append(reasons, fmt.Sprintf("有效样本 %d 少于 %d", item.Samples, config.MinSamples))
	}
	if !policySuccessQualified(item, config) {
		actual := "暂无"
		if item.SuccessRate.Valid {
			actual = fmt.Sprintf("%.1f%%", item.SuccessRate.Float64)
		}
		reasons = append(reasons, fmt.Sprintf("7 天成功率 %s 低于 %.1f%%，或最近探测成功 %d/%d", actual, config.MinSuccessRate, item.RecentSuccesses, recoverySuccessSamples))
	}
	return reasons
}

func policyHasAllowedModels(item managedPolicyCandidate, config policyConfig) bool {
	config = normalizePolicyConfig(config)
	if len(config.DisabledModels) == 0 {
		return true
	}
	return len(modelMappingForPolicy(item.Platform, decodeModels(item.ModelsJSON), config.DisabledModels)) > 0
}

const multiplierComparisonTolerance = 1e-9

func policyMultiplierQualified(item managedPolicyCandidate, config policyConfig) bool {
	if !item.SourceMultiplier.Valid || !item.TargetMultiplier.Valid {
		return false
	}
	if item.SourceMultiplier.Float64 > item.TargetMultiplier.Float64+multiplierComparisonTolerance {
		return false
	}
	return config.AllowEqualMultiplier || item.SourceMultiplier.Float64 < item.TargetMultiplier.Float64-multiplierComparisonTolerance
}

func policySuccessQualified(item managedPolicyCandidate, config policyConfig) bool {
	if item.Schedulable && unconfirmedProbeFailure(item) {
		return true
	}
	if !item.Schedulable {
		return item.Samples >= config.MinSamples && item.RecentSuccesses >= recoverySuccessSamples
	}
	return (item.SuccessRate.Valid && item.SuccessRate.Float64 >= config.MinSuccessRate) || (item.Samples >= config.MinSamples && item.RecentSuccesses >= recoverySuccessSamples)
}

func unconfirmedProbeFailure(item managedPolicyCandidate) bool {
	limit := item.ConfirmationFailures
	if limit < 1 {
		limit = 3
	}
	return item.ConsecutiveFailures > 0 && item.ConsecutiveFailures < limit
}

func stableKey(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

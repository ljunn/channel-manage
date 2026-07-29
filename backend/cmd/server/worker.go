package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

func (a *App) runScheduler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	a.runAutomation(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runAutomation(ctx)
		}
	}
}

func (a *App) runAutomation(ctx context.Context) {
	if !a.workerMu.TryLock() {
		return
	}
	defer a.workerMu.Unlock()
	a.scanDueSources(ctx)
	a.syncDueTargets(ctx)
	a.syncDueTargetMetrics(ctx)
	a.probeDueChannels(ctx)
	if err := a.evaluateManagedAccounts(ctx); err != nil {
		log.Printf("策略评估失败: %v", err)
	}
}

func (a *App) scanDueSources(ctx context.Context) {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM sources WHERE status='ACTIVE' AND scan_status<>'RUNNING' AND (last_scan_at IS NULL OR last_scan_at + scan_interval_seconds * interval '1 second' <= now())`)
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
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM targets WHERE last_sync_at IS NULL OR last_sync_at<now()-interval '15 minutes'`)
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
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM channels WHERE lifecycle_state<>'MANUAL_HOLD' AND (last_probe_at IS NULL OR last_probe_at + $1 * interval '1 second' <= now())`, interval)
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
		if err := a.probeChannel(ctx, id); err != nil {
			log.Printf("渠道 %s 探测失败: %v", id, err)
		}
	}
}

func (a *App) evaluateManagedAccounts(ctx context.Context) error {
	var configData string
	if err := a.db.QueryRowContext(ctx, `SELECT v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE p.status='ACTIVE' ORDER BY p.updated_at DESC LIMIT 1`).Scan(&configData); err == sql.ErrNoRows {
		return nil
	} else if err != nil {
		return err
	}
	var config policyConfig
	_ = json.Unmarshal([]byte(configData), &config)
	config = normalizePolicyConfig(config)
	if err := a.ensureManagedTargetMultiplierCaches(ctx); err != nil {
		return err
	}
	items, err := a.managedPolicyCandidates(ctx)
	if err != nil {
		return err
	}
	autoApprove, _ := a.settingBool(ctx, "auto_approve")
	shadow, _ := a.settingBool(ctx, "shadow_mode")
	for _, item := range items {
		reasons := policyRejectionReasons(item, config)
		desired := len(reasons) == 0
		if desired == item.Schedulable {
			continue
		}
		action := "SET_SCHEDULABLE"
		reason := "渠道与目标分组倍率均符合策略，建议恢复调度"
		if !desired {
			reason = strings.Join(reasons, "；")
		}
		key := stableKey(item.ID, action, fmt.Sprint(desired), time.Now().UTC().Format("2006-01-02"))
		status := "PENDING"
		if autoApprove && !shadow {
			status = "APPROVED"
		}
		var id string
		err := a.db.QueryRowContext(ctx, `INSERT INTO action_intents(managed_account_id,action_type,before_state,after_state,reason,status,idempotency_key,approved_at) VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $6='APPROVED' THEN now() END) ON CONFLICT(idempotency_key) DO NOTHING RETURNING id`, item.ID, action, jsonValue(map[string]bool{"schedulable": item.Schedulable}), jsonValue(map[string]bool{"schedulable": desired}), reason, status, key).Scan(&id)
		if err == nil && status == "APPROVED" {
			go a.executeAction(context.Background(), id)
		}
	}
	return nil
}

type managedPolicyCandidate struct {
	ID, State, StateReason, SourceGroup, TargetGroup string
	Schedulable                                      bool
	SourceMultiplier, TargetMultiplier, SuccessRate  sql.NullFloat64
	Samples                                          int
}

func (a *App) managedPolicyCandidates(ctx context.Context) ([]managedPolicyCandidate, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.schedulable,c.lifecycle_state,c.state_reason,COALESCE(sg.name,''),COALESCE(string_agg(tg.name,'、' ORDER BY tg.name),''),sg.multiplier,min(tg.multiplier),
		(SELECT count(*) FROM probe_runs p WHERE p.channel_id=c.id AND p.started_at>now()-interval '1 hour'),
		(SELECT avg(CASE WHEN p.success THEN 100.0 ELSE 0 END) FROM probe_runs p WHERE p.channel_id=c.id AND p.started_at>now()-interval '1 hour')
		FROM managed_accounts m JOIN channels c ON c.id=m.channel_id LEFT JOIN source_groups sg ON sg.id=c.source_group_id LEFT JOIN managed_account_groups mg ON mg.managed_account_id=m.id LEFT JOIN target_groups tg ON tg.id=mg.target_group_id
		GROUP BY m.id,c.id,sg.id ORDER BY m.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []managedPolicyCandidate{}
	for rows.Next() {
		var item managedPolicyCandidate
		if err := rows.Scan(&item.ID, &item.Schedulable, &item.State, &item.StateReason, &item.SourceGroup, &item.TargetGroup, &item.SourceMultiplier, &item.TargetMultiplier, &item.Samples, &item.SuccessRate); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func policyRejectionReasons(item managedPolicyCandidate, config policyConfig) []string {
	reasons := []string{}
	if item.State != "HEALTHY" {
		reasons = append(reasons, "渠道状态为 "+item.State+"："+item.StateReason)
	}
	if !item.SourceMultiplier.Valid || !item.TargetMultiplier.Valid {
		reasons = append(reasons, "源分组或目标分组倍率缺失")
	} else if item.SourceMultiplier.Float64 > item.TargetMultiplier.Float64 {
		reasons = append(reasons, fmt.Sprintf("源分组倍率 %.4fx 超过目标分组上限 %.4fx", item.SourceMultiplier.Float64, item.TargetMultiplier.Float64))
	}
	if item.Samples < config.MinSamples {
		reasons = append(reasons, fmt.Sprintf("有效样本 %d 少于 %d", item.Samples, config.MinSamples))
	}
	if !item.SuccessRate.Valid || item.SuccessRate.Float64 < config.MinSuccessRate {
		reasons = append(reasons, fmt.Sprintf("成功率低于 %.1f%%", config.MinSuccessRate))
	}
	return reasons
}

func stableKey(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

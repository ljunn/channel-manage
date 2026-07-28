package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
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
	var activePolicies int
	if err := a.db.QueryRowContext(ctx, `SELECT count(*) FROM policies WHERE status='ACTIVE' AND active_version IS NOT NULL`).Scan(&activePolicies); err != nil {
		return err
	}
	if activePolicies == 0 {
		return nil
	}
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.schedulable,c.lifecycle_state,c.state_reason FROM managed_accounts m JOIN channels c ON c.id=m.channel_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type candidate struct {
		id, state, reason string
		schedulable       bool
	}
	items := []candidate{}
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.schedulable, &item.state, &item.reason); err != nil {
			return err
		}
		items = append(items, item)
	}
	autoApprove, _ := a.settingBool(ctx, "auto_approve")
	shadow, _ := a.settingBool(ctx, "shadow_mode")
	for _, item := range items {
		desired := item.state == "HEALTHY"
		if desired == item.schedulable {
			continue
		}
		action := "SET_SCHEDULABLE"
		reason := "渠道恢复健康，建议恢复调度"
		if !desired {
			reason = "渠道状态为 " + item.state + "，建议停止调度：" + item.reason
		}
		key := stableKey(item.id, action, fmt.Sprint(desired), time.Now().UTC().Format("2006-01-02"))
		status := "PENDING"
		if autoApprove && !shadow {
			status = "APPROVED"
		}
		var id string
		err := a.db.QueryRowContext(ctx, `INSERT INTO action_intents(managed_account_id,action_type,before_state,after_state,reason,status,idempotency_key,approved_at) VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $6='APPROVED' THEN now() END) ON CONFLICT(idempotency_key) DO NOTHING RETURNING id`, item.id, action, jsonValue(map[string]bool{"schedulable": item.schedulable}), jsonValue(map[string]bool{"schedulable": desired}), reason, status, key).Scan(&id)
		if err == nil && status == "APPROVED" {
			go a.executeAction(context.Background(), id)
		}
	}
	return nil
}

func stableKey(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

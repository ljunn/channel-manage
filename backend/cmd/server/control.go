package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (a *App) openEvent(ctx context.Context, severity, category, title, detail, dedupeKey string) {
	var existing string
	err := a.db.QueryRowContext(ctx, `SELECT id FROM events WHERE dedupe_key=$1 AND status<>'RESOLVED' AND created_at>now()-interval '1 hour' LIMIT 1`, dedupeKey).Scan(&existing)
	if err == nil {
		return
	}
	var eventID string
	err = a.db.QueryRowContext(ctx, `INSERT INTO events(severity,category,title,detail,dedupe_key) VALUES($1,$2,$3,$4,$5) RETURNING id`, severity, category, title, truncate(detail, 1000), dedupeKey).Scan(&eventID)
	logDatabaseError("写入事件", err)
	if err == nil && (severity == "P0" || severity == "P1") {
		go a.notifyEvent(context.Background(), eventID, severity, title, detail)
	}
}

func (a *App) listEvents(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,severity,category,title,detail,status,acknowledged_at,resolved_at,created_at FROM events ORDER BY CASE severity WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END,created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, severity, category, title, detail, status string
		var acknowledged, resolved sql.NullTime
		var created time.Time
		if err := rows.Scan(&id, &severity, &category, &title, &detail, &status, &acknowledged, &resolved, &created); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "severity": severity, "category": category, "title": title, "detail": detail, "status": status, "acknowledgedAt": nullableTime(acknowledged), "resolvedAt": nullableTime(resolved), "createdAt": created})
	}
	return items, rows.Err()
}

func (a *App) updateEvent(w http.ResponseWriter, r *http.Request, id, action string) error {
	status := "ACKNOWLEDGED"
	column := "acknowledged_at"
	if action == "resolve" {
		status = "RESOLVED"
		column = "resolved_at"
	}
	result, err := a.db.ExecContext(r.Context(), `UPDATE events SET status=$2,`+column+`=now() WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "EVENT_NOT_FOUND", "事件不存在"}
	}
	a.audit(r.Context(), strings.ToUpper(action), "event", id, nil)
	writeData(w, map[string]string{"id": id, "status": status})
	return nil
}

func (a *App) listAudit(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,action,object_type,object_id,detail,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var action, objectType, objectID, detail string
		var created time.Time
		if err := rows.Scan(&id, &action, &objectType, &objectID, &detail, &created); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "action": action, "objectType": objectType, "objectId": objectID, "detail": json.RawMessage(detail), "createdAt": created})
	}
	return items, rows.Err()
}

func (a *App) listActions(ctx context.Context, latest bool) ([]map[string]any, error) {
	where := ""
	if latest {
		where = " WHERE created_at>now()-interval '24 hours'"
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id,managed_account_id,action_type,before_state,after_state,reason,status,approved_at,executed_at,error,created_at FROM action_intents`+where+` ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id string
		var managedID sql.NullString
		var action, before, after, reason, status, errorMessage string
		var approved, executed sql.NullTime
		var created time.Time
		if err := rows.Scan(&id, &managedID, &action, &before, &after, &reason, &status, &approved, &executed, &errorMessage, &created); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "managedAccountId": nullableString(managedID), "actionType": action, "beforeState": json.RawMessage(before), "afterState": json.RawMessage(after), "reason": reason, "status": status, "approvedAt": nullableTime(approved), "executedAt": nullableTime(executed), "error": errorMessage, "createdAt": created})
	}
	return items, rows.Err()
}

func nullableString(value sql.NullString) any {
	if value.Valid {
		return value.String
	}
	return nil
}

func (a *App) decideAction(w http.ResponseWriter, r *http.Request, id, decision string) error {
	status := "REJECTED"
	if decision == "approve" {
		status = "APPROVED"
	}
	result, err := a.db.ExecContext(r.Context(), `UPDATE action_intents SET status=$2,approved_at=CASE WHEN $2='APPROVED' THEN now() ELSE approved_at END WHERE id=$1 AND status='PENDING'`, id, status)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "ACTION_NOT_FOUND", "待处理动作不存在"}
	}
	a.audit(r.Context(), "ACTION_"+status, "action_intent", id, nil)
	if status == "APPROVED" {
		go a.executeAction(context.Background(), id)
	}
	writeData(w, map[string]string{"id": id, "status": status})
	return nil
}

func (a *App) executeAction(ctx context.Context, id string) error {
	frozen, _ := a.settingBool(ctx, "emergency_freeze")
	shadow, _ := a.settingBool(ctx, "shadow_mode")
	if frozen || shadow {
		return a.failAction(ctx, id, "安全冻结或影子模式禁止执行写动作")
	}
	var managedID, action, after, targetID, targetBase, remoteID, marker string
	var writeEnabled bool
	err := a.db.QueryRowContext(ctx, `SELECT m.id,i.action_type,i.after_state,t.id,t.base_url,t.write_enabled,m.remote_id,m.ownership_marker FROM action_intents i JOIN managed_accounts m ON m.id=i.managed_account_id JOIN targets t ON t.id=m.target_id WHERE i.id=$1 AND i.status='APPROVED'`, id).Scan(&managedID, &action, &after, &targetID, &targetBase, &writeEnabled, &remoteID, &marker)
	if err != nil {
		return a.failAction(ctx, id, err.Error())
	}
	if !writeEnabled || !strings.HasPrefix(marker, "channel-manage:") {
		return a.failAction(ctx, id, "目标写入未授权或托管所有权无效")
	}
	requestCtx, cancel := timeoutContext(ctx)
	defer cancel()
	session, err := a.authenticateTarget(requestCtx, Target{ID: targetID, BaseURL: targetBase}, true)
	if err != nil {
		return a.failAction(ctx, id, err.Error())
	}
	var state map[string]any
	if json.Unmarshal([]byte(after), &state) != nil {
		return a.failAction(ctx, id, "动作状态不可读")
	}
	path := "/api/v1/admin/accounts/" + remoteID
	method := http.MethodPut
	payload := state
	if action == "SET_SCHEDULABLE" {
		path += "/schedulable"
		method = http.MethodPost
	}
	value, _, err := a.remoteJSON(requestCtx, targetBase, method, path, session, payload)
	if err == nil {
		_, err = unwrapEnvelope(value, "SUB2API")
	}
	if err != nil {
		return a.failAction(ctx, id, err.Error())
	}
	_, err = a.db.ExecContext(ctx, `UPDATE action_intents SET status='EXECUTED',executed_at=now(),error='' WHERE id=$1`, id)
	if err == nil {
		if schedulable, ok := state["schedulable"].(bool); ok {
			_, _ = a.db.ExecContext(ctx, `UPDATE managed_accounts SET schedulable=$2,updated_at=now() WHERE id=$1`, managedID, schedulable)
		}
		if priority, ok := number(state["priority"]); ok {
			_, _ = a.db.ExecContext(ctx, `UPDATE managed_accounts SET priority=$2,updated_at=now() WHERE id=$1`, managedID, int(priority))
		}
	}
	return err
}

func (a *App) failAction(ctx context.Context, id, message string) error {
	_, _ = a.db.ExecContext(ctx, `UPDATE action_intents SET status='FAILED',error=$2,executed_at=now() WHERE id=$1`, id, truncate(message, 500))
	a.openEvent(ctx, "P0", "ACTION_EXECUTION", "远程动作执行失败", message, "action:"+id)
	return fmt.Errorf("action failed: %s", message)
}

type policyConfig struct {
	MaxMultiplier        float64 `json:"maxMultiplier"`
	MinSuccessRate       float64 `json:"minSuccessRate"`
	MinSamples           int     `json:"minSamples"`
	ConfirmationFailures int     `json:"confirmationFailures"`
	CooldownMinutes      int     `json:"cooldownMinutes"`
}

func defaultPolicyConfig() policyConfig { return policyConfig{1, 95, 5, 3, 15} }

func (a *App) listPolicies(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT p.id,p.name,p.scope_type,p.scope_id,p.status,p.active_version,p.created_at,COALESCE(v.config,'{}'::jsonb) FROM policies p LEFT JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version ORDER BY p.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, scope, status, config string
		var scopeID sql.NullString
		var active sql.NullInt64
		var created time.Time
		if err := rows.Scan(&id, &name, &scope, &scopeID, &status, &active, &created, &config); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "name": name, "scopeType": scope, "scopeId": nullableString(scopeID), "status": status, "activeVersion": nullableInt(active), "config": json.RawMessage(config), "createdAt": created})
	}
	return items, rows.Err()
}

func (a *App) createPolicy(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Name, ScopeType, ScopeID string
		Config                   policyConfig
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Name == "" {
		return &apiError{400, "INVALID_INPUT", "请填写策略名称"}
	}
	if input.ScopeType == "" {
		input.ScopeType = "GLOBAL"
	}
	if input.Config.MaxMultiplier <= 0 {
		input.Config = defaultPolicyConfig()
	}
	id := uuid.NewString()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO policies(id,name,scope_type,scope_id,status,active_version) VALUES($1,$2,$3,NULLIF($4,'')::uuid,'DRAFT',1)`, id, input.Name, input.ScopeType, input.ScopeID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO policy_versions(policy_id,version,config) VALUES($1,1,$2)`, id, jsonValue(input.Config))
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "CREATE", "policy", id, input.Config)
	writeData(w, map[string]any{"id": id, "version": 1})
	return nil
}

func (a *App) createPolicyVersion(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct{ Config policyConfig }
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Config.MaxMultiplier <= 0 {
		return &apiError{400, "INVALID_POLICY", "倍率上限必须大于 0"}
	}
	var version int
	err := a.db.QueryRowContext(r.Context(), `INSERT INTO policy_versions(policy_id,version,config) SELECT $1,COALESCE(max(version),0)+1,$2 FROM policy_versions WHERE policy_id=$1 RETURNING version`, id, jsonValue(input.Config)).Scan(&version)
	if err != nil {
		return err
	}
	a.audit(r.Context(), "VERSION_CREATE", "policy", id, map[string]int{"version": version})
	writeData(w, map[string]int{"version": version})
	return nil
}

func (a *App) activatePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct{ Version int }
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	result, err := a.db.ExecContext(r.Context(), `UPDATE policies SET active_version=$2,status='ACTIVE',updated_at=now() WHERE id=$1 AND EXISTS(SELECT 1 FROM policy_versions WHERE policy_id=$1 AND version=$2)`, id, input.Version)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "POLICY_VERSION_NOT_FOUND", "策略版本不存在"}
	}
	a.audit(r.Context(), "ACTIVATE", "policy", id, map[string]int{"version": input.Version})
	writeData(w, map[string]any{"id": id, "version": input.Version, "status": "ACTIVE"})
	return nil
}

func (a *App) simulatePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	var configData string
	err := a.db.QueryRowContext(r.Context(), `SELECT v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE p.id=$1`, id).Scan(&configData)
	if err != nil {
		return &apiError{404, "POLICY_VERSION_NOT_FOUND", "策略尚未激活"}
	}
	var config policyConfig
	_ = json.Unmarshal([]byte(configData), &config)
	channels, err := a.listChannels(r.Context())
	if err != nil {
		return err
	}
	preview := []map[string]any{}
	for _, channel := range channels {
		reasons := []string{}
		multiplier, _ := channel["multiplier"].(float64)
		rate, _ := channel["successRate"].(float64)
		samples, _ := channel["probeSamples1h"].(int)
		if multiplier == 0 || multiplier > config.MaxMultiplier {
			reasons = append(reasons, "倍率超过上限或缺失")
		}
		if samples < config.MinSamples {
			reasons = append(reasons, "有效样本不足")
		}
		if rate < config.MinSuccessRate {
			reasons = append(reasons, "成功率低于阈值")
		}
		preview = append(preview, map[string]any{"channel": channel, "decision": map[bool]string{true: "REJECTED", false: "ELIGIBLE"}[len(reasons) > 0], "reasons": reasons})
	}
	writeData(w, map[string]any{"policyId": id, "generatedAt": time.Now(), "preview": preview})
	return nil
}

func (a *App) getSettings(ctx context.Context) (map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT key,value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]any{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		var decoded any
		if json.Unmarshal([]byte(value), &decoded) == nil {
			result[key] = decoded
		}
	}
	result["version"] = Version
	result["buildType"] = BuildType
	result["githubRepo"] = GitHubRepo
	return result, rows.Err()
}

func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) error {
	var input map[string]any
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	allowed := map[string]bool{"shadow_mode": true, "emergency_freeze": true, "auto_approve": true, "probe_interval_seconds": true, "scan_interval_seconds": true, "max_daily_probe_cost_usd": true, "min_healthy_channels": true, "confirmation_failures": true, "metric_window_minutes": true, "min_error_samples": true, "error_rate_threshold": true}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range input {
		if !allowed[key] {
			return &apiError{400, "INVALID_SETTING", "包含不支持的系统设置"}
		}
		if _, err = tx.ExecContext(r.Context(), `INSERT INTO settings(key,value,updated_at) VALUES($1,$2,now()) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()`, key, jsonValue(value)); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "UPDATE", "settings", "global", input)
	settings, err := a.getSettings(r.Context())
	if err != nil {
		return err
	}
	writeData(w, settings)
	return nil
}

func (a *App) settingBool(ctx context.Context, key string) (bool, error) {
	var raw string
	if err := a.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&raw); err != nil {
		return false, err
	}
	value, err := strconv.ParseBool(strings.Trim(raw, `"`))
	return value, err
}

func (a *App) settingInt(ctx context.Context, key string, fallback int) int {
	var raw string
	if a.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&raw) != nil {
		return fallback
	}
	value, err := strconv.Atoi(strings.Trim(raw, `"`))
	if err != nil {
		return fallback
	}
	return value
}

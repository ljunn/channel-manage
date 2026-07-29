package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (a *App) openEvent(ctx context.Context, severity, category, title, detail, dedupeKey string) {
	var existingID, existingSeverity string
	err := a.db.QueryRowContext(ctx, `SELECT id,severity FROM events WHERE dedupe_key=$1 AND status<>'RESOLVED' ORDER BY created_at DESC LIMIT 1`, dedupeKey).Scan(&existingID, &existingSeverity)
	if err == nil {
		_, updateErr := a.db.ExecContext(ctx, `UPDATE events SET severity=$2,category=$3,title=$4,detail=$5,status='OPEN',acknowledged_at=NULL WHERE id=$1`, existingID, severity, category, title, truncate(detail, 1000))
		logDatabaseError("更新事件", updateErr)
		if updateErr == nil && severityRank(severity) < severityRank(existingSeverity) && (severity == "P0" || severity == "P1") {
			go a.notifyEvent(context.Background(), existingID, severity, "告警升级："+title, detail)
		}
		return
	}
	var eventID string
	err = a.db.QueryRowContext(ctx, `INSERT INTO events(severity,category,title,detail,dedupe_key) VALUES($1,$2,$3,$4,$5) RETURNING id`, severity, category, title, truncate(detail, 1000), dedupeKey).Scan(&eventID)
	logDatabaseError("写入事件", err)
	if err == nil && (severity == "P0" || severity == "P1") {
		go a.notifyEvent(context.Background(), eventID, severity, title, detail)
	}
}

func (a *App) resolveEvent(ctx context.Context, dedupeKey string) {
	var eventID, severity, title, detail string
	err := a.db.QueryRowContext(ctx, `UPDATE events SET status='RESOLVED',resolved_at=now() WHERE id=(SELECT id FROM events WHERE dedupe_key=$1 AND status<>'RESOLVED' ORDER BY created_at DESC LIMIT 1) RETURNING id,severity,title,detail`, dedupeKey).Scan(&eventID, &severity, &title, &detail)
	if err == sql.ErrNoRows {
		return
	}
	logDatabaseError("恢复事件", err)
	if err == nil && (severity == "P0" || severity == "P1") {
		go a.notifyEvent(context.Background(), eventID, "恢复", title+"已恢复", detail+"\n\n系统已确认恢复，相关告警自动关闭。")
	}
}

func severityRank(value string) int {
	if value == "P0" {
		return 0
	}
	if value == "P1" {
		return 1
	}
	if value == "P2" {
		return 2
	}
	return 3
}

func (a *App) listEvents(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,severity,category,title,detail,status,acknowledged_at,resolved_at,created_at FROM events
		WHERE status<>'RESOLVED' OR id IN (
			SELECT id FROM events WHERE status='RESOLVED' AND resolved_at>now()-interval '24 hours' ORDER BY resolved_at DESC LIMIT 10
		)
		ORDER BY CASE WHEN status='RESOLVED' THEN 1 ELSE 0 END,CASE severity WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END,COALESCE(resolved_at,created_at) DESC LIMIT 200`)
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
		where = " WHERE i.created_at>now()-interval '24 hours'"
	}
	rows, err := a.db.QueryContext(ctx, `SELECT i.id,i.managed_account_id,i.action_type,i.before_state,i.after_state,i.reason,i.status,i.approved_at,i.executed_at,i.error,i.created_at,
		COALESCE(m.remote_name,''),COALESCE(s.name,''),COALESCE(sg.name,''),COALESCE(t.name,''),COALESCE(string_agg(tg.name,'、' ORDER BY tg.name),'')
		FROM action_intents i
		LEFT JOIN managed_accounts m ON m.id=i.managed_account_id
		LEFT JOIN channels c ON c.id=m.channel_id LEFT JOIN sources s ON s.id=c.source_id LEFT JOIN source_groups sg ON sg.id=c.source_group_id
		LEFT JOIN targets t ON t.id=m.target_id LEFT JOIN managed_account_groups mag ON mag.managed_account_id=m.id LEFT JOIN target_groups tg ON tg.id=mag.target_group_id`+where+`
		GROUP BY i.id,m.id,s.name,sg.name,t.name ORDER BY i.created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id string
		var managedID sql.NullString
		var action, before, after, reason, status, errorMessage string
		var remoteName, sourceName, sourceGroup, targetName, targetGroup string
		var approved, executed sql.NullTime
		var created time.Time
		if err := rows.Scan(&id, &managedID, &action, &before, &after, &reason, &status, &approved, &executed, &errorMessage, &created, &remoteName, &sourceName, &sourceGroup, &targetName, &targetGroup); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "managedAccountId": nullableString(managedID), "remoteName": remoteName, "sourceName": sourceName, "sourceGroup": sourceGroup, "targetName": targetName, "targetGroup": targetGroup, "actionType": action, "beforeState": json.RawMessage(before), "afterState": json.RawMessage(after), "reason": reason, "status": status, "approvedAt": nullableTime(approved), "executedAt": nullableTime(executed), "error": errorMessage, "createdAt": created})
	}
	return items, rows.Err()
}

func (a *App) listSchedulingStatus(ctx context.Context) ([]map[string]any, error) {
	if err := a.ensureManagedTargetMultiplierCaches(ctx); err != nil {
		return nil, err
	}
	candidates, err := a.managedPolicyCandidates(ctx)
	if err != nil {
		return nil, err
	}
	type activePolicy struct {
		ID, Name string
		Config   policyConfig
	}
	policies := map[string]activePolicy{}
	probeInterval := a.settingInt(ctx, "probe_interval_seconds", 900)
	rows, err := a.db.QueryContext(ctx, `SELECT p.id,p.name,p.scope_id,v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE p.status='ACTIVE' AND p.scope_type='TARGET_GROUP'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name, scopeID, configData string
		if err := rows.Scan(&id, &name, &scopeID, &configData); err != nil {
			rows.Close()
			return nil, err
		}
		var config policyConfig
		_ = json.Unmarshal([]byte(configData), &config)
		policies[scopeID] = activePolicy{ID: id, Name: name, Config: normalizePolicyConfig(config)}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		policy, configured := policies[candidate.TargetGroupID]
		reasons := []string{"目标分组未配置启用策略"}
		eligible := false
		if configured {
			reasons = policyRejectionReasons(candidate, policy.Config)
			eligible = len(reasons) == 0
		}
		fastValidation := configured && !eligible && candidateCanRecoverWithProbe(candidate, policy.Config)
		fastInterval := fastProbeIntervalFor(candidate)
		estimatedValidationSeconds := 0
		if fastValidation {
			remainingProbes := max(0, policy.Config.MinSamples-candidate.Samples)
			recentSuccesses := candidate.RecentSuccesses
			if isSlowFirstTokenQuarantine(candidate.State, candidate.StateReason) {
				recentSuccesses = candidate.RecoverySuccesses
			}
			if !candidate.Schedulable || candidate.State != "HEALTHY" || !policySuccessQualified(candidate, policy.Config) {
				remainingProbes = max(remainingProbes, max(0, recoverySuccessSamples-recentSuccesses))
			}
			estimatedValidationSeconds = remainingProbes * fastInterval
		}
		displayedSuccesses := candidate.RecentSuccesses
		if isSlowFirstTokenQuarantine(candidate.State, candidate.StateReason) {
			displayedSuccesses = candidate.RecoverySuccesses
		}
		items = append(items, map[string]any{
			"managedAccountId": candidate.ID, "remoteName": candidate.RemoteName,
			"sourceName": candidate.SourceName, "sourceGroup": candidate.SourceGroup,
			"targetName": candidate.TargetName, "targetGroupId": candidate.TargetGroupID, "targetGroup": candidate.TargetGroup,
			"schedulable": candidate.Schedulable, "eligible": eligible, "priority": candidate.Priority, "syncStatus": candidate.SyncStatus,
			"channelState": candidate.State, "sourceMultiplier": nullableFloat(candidate.SourceMultiplier), "targetMultiplier": nullableFloat(candidate.TargetMultiplier),
			"samples": candidate.Samples, "successRate": nullableFloat(candidate.SuccessRate), "firstTokenP95Ms": nullableFloat(candidate.FirstTokenP95), "recentSuccesses": displayedSuccesses,
			"policyId": map[bool]any{true: policy.ID, false: nil}[configured], "policyName": policy.Name,
			"minSamples": policy.Config.MinSamples, "minSuccessRate": policy.Config.MinSuccessRate,
			"probeIntervalSeconds": probeInterval, "fastProbeIntervalSeconds": fastInterval, "fastValidation": fastValidation, "estimatedValidationSeconds": estimatedValidationSeconds,
			"reasons": reasons,
		})
	}
	return items, nil
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
	Mode                 string  `json:"mode"`
	MinSuccessRate       float64 `json:"minSuccessRate"`
	MinSamples           int     `json:"minSamples"`
	AllowEqualMultiplier bool    `json:"allowEqualMultiplier"`
	ProbeModel           string  `json:"probeModel"`
}

func normalizePolicyConfig(config policyConfig) policyConfig {
	if config.Mode != "SPEED" {
		config.Mode = "PRICE"
	}
	if config.MinSuccessRate <= 0 {
		config.MinSuccessRate = 95
	}
	if config.MinSamples < 1 {
		config.MinSamples = 5
	}
	return config
}

func (a *App) validatePolicyProbeModel(ctx context.Context, scopeID string, config policyConfig) (policyConfig, error) {
	var platform, modelsJSON, defaultModel string
	if err := a.db.QueryRowContext(ctx, `SELECT platform,models,probe_model FROM target_groups WHERE id=$1`, scopeID).Scan(&platform, &modelsJSON, &defaultModel); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return config, &apiError{400, "INVALID_POLICY_SCOPE", "目标分组不存在"}
		}
		return config, err
	}
	config.ProbeModel = strings.TrimSpace(config.ProbeModel)
	if config.ProbeModel == "" {
		config.ProbeModel = defaultModel
	}
	allowed := false
	for _, model := range decodeModels(modelsJSON) {
		if model == config.ProbeModel && probeModelMatchesPlatform(platform, model) {
			allowed = true
			break
		}
	}
	if !allowed {
		return config, &apiError{400, "INVALID_PROBE_MODEL", "测试模型必须来自目标分组的同平台文本模型"}
	}
	return config, nil
}

func (a *App) listPolicies(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT p.id,p.name,p.scope_type,p.scope_id,p.status,p.active_version,p.created_at,COALESCE(v.config,'{}'::jsonb),COALESCE(tg.name,''),COALESCE(t.name,''),tg.target_id,COALESCE(tg.models,'[]'::jsonb),
		(SELECT count(*) FROM managed_account_groups mg WHERE mg.target_group_id=p.scope_id),
		(SELECT count(*) FROM managed_account_groups mg JOIN managed_accounts m ON m.id=mg.managed_account_id WHERE mg.target_group_id=p.scope_id AND m.schedulable=true)
		FROM policies p LEFT JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version LEFT JOIN target_groups tg ON tg.id=p.scope_id LEFT JOIN targets t ON t.id=tg.target_id ORDER BY p.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, scope, status, config, targetGroupName, targetName, probeModels string
		var scopeID, targetID sql.NullString
		var active sql.NullInt64
		var managedCount, schedulableCount int
		var created time.Time
		if err := rows.Scan(&id, &name, &scope, &scopeID, &status, &active, &created, &config, &targetGroupName, &targetName, &targetID, &probeModels, &managedCount, &schedulableCount); err != nil {
			return nil, err
		}
		var policy policyConfig
		_ = json.Unmarshal([]byte(config), &policy)
		items = append(items, map[string]any{"id": id, "name": name, "scopeType": scope, "scopeId": nullableString(scopeID), "targetId": nullableString(targetID), "targetGroupName": targetGroupName, "targetName": targetName, "status": status, "activeVersion": nullableInt(active), "config": normalizePolicyConfig(policy), "probeModels": json.RawMessage(probeModels), "managedCount": managedCount, "schedulableCount": schedulableCount, "evaluationIntervalSeconds": fastProbeIntervalSeconds, "metricWindowDays": policyMetricWindowDays, "multiplierLimitSource": "TARGET_GROUP", "multiplierCacheSeconds": int(targetMultiplierCacheTTL.Seconds()), "createdAt": created})
	}
	return items, rows.Err()
}

func (a *App) updatePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		Name   string       `json:"name"`
		Config policyConfig `json:"config"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return &apiError{400, "INVALID_INPUT", "请填写策略名称"}
	}
	input.Config = normalizePolicyConfig(input.Config)
	var scopeID string
	if err := a.db.QueryRowContext(r.Context(), `SELECT scope_id FROM policies WHERE id=$1`, id).Scan(&scopeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &apiError{404, "POLICY_NOT_FOUND", "策略不存在"}
		}
		return err
	}
	validatedConfig, err := a.validatePolicyProbeModel(r.Context(), scopeID, input.Config)
	if err != nil {
		return err
	}
	input.Config = validatedConfig
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err = tx.QueryRowContext(r.Context(), `SELECT status FROM policies WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &apiError{404, "POLICY_NOT_FOUND", "策略不存在"}
		}
		return err
	}
	var version int
	if err = tx.QueryRowContext(r.Context(), `INSERT INTO policy_versions(policy_id,version,config) SELECT $1,COALESCE(max(version),0)+1,$2 FROM policy_versions WHERE policy_id=$1 RETURNING version`, id, jsonValue(input.Config)).Scan(&version); err != nil {
		return err
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE policies SET name=$2,active_version=$3,updated_at=now() WHERE id=$1`, id, input.Name, version); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "UPDATE", "policy", id, map[string]any{"name": input.Name, "version": version, "config": input.Config})
	go a.runPolicyEvaluation(context.Background())
	writeData(w, map[string]any{"id": id, "name": input.Name, "version": version})
	return nil
}

func (a *App) deletePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	result, err := a.db.ExecContext(r.Context(), `DELETE FROM policies WHERE id=$1`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "POLICY_NOT_FOUND", "策略不存在"}
	}
	a.audit(r.Context(), "DELETE", "policy", id, nil)
	writeData(w, map[string]bool{"deleted": true})
	return nil
}

func (a *App) deactivatePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	result, err := a.db.ExecContext(r.Context(), `UPDATE policies SET status='DRAFT',updated_at=now() WHERE id=$1 AND status='ACTIVE'`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{409, "POLICY_NOT_ACTIVE", "策略未处于启用状态"}
	}
	a.audit(r.Context(), "DEACTIVATE", "policy", id, nil)
	writeData(w, map[string]any{"id": id, "status": "DRAFT"})
	return nil
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
	if input.ScopeType != "TARGET_GROUP" || input.ScopeID == "" {
		return &apiError{400, "INVALID_POLICY_SCOPE", "请选择策略对应的目标分组"}
	}
	input.Config = normalizePolicyConfig(input.Config)
	validatedConfig, err := a.validatePolicyProbeModel(r.Context(), input.ScopeID, input.Config)
	if err != nil {
		return err
	}
	input.Config = validatedConfig
	id := uuid.NewString()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, input.ScopeID); err != nil {
		return err
	}
	var groupExists int
	if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM target_groups WHERE id=$1`, input.ScopeID).Scan(&groupExists); err != nil {
		return err
	}
	if groupExists == 0 {
		return &apiError{400, "INVALID_POLICY_SCOPE", "目标分组不存在"}
	}
	var existingName string
	err = tx.QueryRowContext(r.Context(), `SELECT name FROM policies WHERE scope_type='TARGET_GROUP' AND scope_id=$1 ORDER BY created_at DESC LIMIT 1`, input.ScopeID).Scan(&existingName)
	if err == nil {
		return &apiError{409, "POLICY_SCOPE_EXISTS", fmt.Sprintf("目标分组已有策略“%s”，请直接编辑现有策略", existingName)}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
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
	input.Config = normalizePolicyConfig(input.Config)
	var scopeID string
	if err := a.db.QueryRowContext(r.Context(), `SELECT scope_id FROM policies WHERE id=$1`, id).Scan(&scopeID); err != nil {
		return &apiError{404, "POLICY_NOT_FOUND", "策略不存在"}
	}
	var err error
	input.Config, err = a.validatePolicyProbeModel(r.Context(), scopeID, input.Config)
	if err != nil {
		return err
	}
	var version int
	err = a.db.QueryRowContext(r.Context(), `INSERT INTO policy_versions(policy_id,version,config) SELECT $1,COALESCE(max(version),0)+1,$2 FROM policy_versions WHERE policy_id=$1 RETURNING version`, id, jsonValue(input.Config)).Scan(&version)
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
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `UPDATE policies SET status='DRAFT',updated_at=now() WHERE id<>$1 AND scope_type=(SELECT scope_type FROM policies WHERE id=$1) AND scope_id=(SELECT scope_id FROM policies WHERE id=$1) AND status='ACTIVE'`, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(r.Context(), `UPDATE policies SET active_version=$2,status='ACTIVE',updated_at=now() WHERE id=$1 AND EXISTS(SELECT 1 FROM policy_versions WHERE policy_id=$1 AND version=$2)`, id, input.Version)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "POLICY_VERSION_NOT_FOUND", "策略版本不存在"}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "ACTIVATE", "policy", id, map[string]int{"version": input.Version})
	go a.runPolicyEvaluation(context.Background())
	writeData(w, map[string]any{"id": id, "version": input.Version, "status": "ACTIVE"})
	return nil
}

func (a *App) simulatePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	var configData, scopeID string
	err := a.db.QueryRowContext(r.Context(), `SELECT v.config,p.scope_id FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE p.id=$1`, id).Scan(&configData, &scopeID)
	if err != nil {
		return &apiError{404, "POLICY_VERSION_NOT_FOUND", "策略尚未激活"}
	}
	var config policyConfig
	_ = json.Unmarshal([]byte(configData), &config)
	config = normalizePolicyConfig(config)
	if err := a.ensureManagedTargetMultiplierCaches(r.Context()); err != nil {
		return err
	}
	candidates, err := a.managedPolicyCandidates(r.Context())
	if err != nil {
		return err
	}
	preview := []map[string]any{}
	for _, candidate := range candidatesForTargetGroup(candidates, scopeID) {
		reasons := policyRejectionReasons(candidate, config)
		preview = append(preview, map[string]any{"managedAccountId": candidate.ID, "remoteName": candidate.RemoteName, "sourceName": candidate.SourceName, "sourceGroup": candidate.SourceGroup, "sourceMultiplier": nullableFloat(candidate.SourceMultiplier), "targetName": candidate.TargetName, "targetGroup": candidate.TargetGroup, "targetMultiplier": nullableFloat(candidate.TargetMultiplier), "samples": candidate.Samples, "successRate": nullableFloat(candidate.SuccessRate), "minSamples": config.MinSamples, "minSuccessRate": config.MinSuccessRate, "firstTokenP95Ms": nullableFloat(candidate.FirstTokenP95), "decision": map[bool]string{true: "REJECTED", false: "ELIGIBLE"}[len(reasons) > 0], "reasons": reasons})
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
	allowed := map[string]bool{
		"shadow_mode": true, "emergency_freeze": true, "auto_approve": true,
		"probe_interval_seconds": true, "scan_interval_seconds": true, "max_daily_probe_cost_usd": true,
		"min_healthy_channels": true, "confirmation_failures": true, "metric_window_minutes": true,
		"min_error_samples": true, "error_rate_threshold": true,
		"balance_alert_work_hours": true, "balance_alert_night_hours": true, "balance_alert_weekend_hours": true,
		"email_alert_source_balance": true, "email_alert_source_scan": true, "email_alert_target_sync": true,
		"email_alert_group_availability": true, "email_alert_action_execution": true, "email_alert_platform_sync": true,
		"email_alert_recovery": true,
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range input {
		if !allowed[key] {
			return &apiError{400, "INVALID_SETTING", "包含不支持的系统设置"}
		}
		if strings.HasPrefix(key, "email_alert_") {
			if _, ok := value.(bool); !ok {
				return &apiError{400, "INVALID_EMAIL_ALERT_SETTING", "邮件场景开关必须是布尔值"}
			}
		}
		if strings.HasPrefix(key, "balance_alert_") {
			hours, ok := number(value)
			if !ok || hours < 1 || hours > 168 || hours != float64(int(hours)) {
				return &apiError{400, "INVALID_BALANCE_ALERT_WINDOW", "余额预警提前量必须是 1 到 168 之间的整数小时"}
			}
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

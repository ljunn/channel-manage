package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (a *App) openEvent(ctx context.Context, severity, category, title, detail, dedupeKey string) {
	if sourceID := sourceIDFromEvent(category, dedupeKey); sourceID != "" && a.sourceIsManuallyUntrusted(ctx, sourceID) {
		return
	}
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
	plans := map[string]managedPolicyPlan{}
	for scopeID, policy := range policies {
		plans[scopeID] = planManagedAccounts(candidatesForTargetGroup(candidates, scopeID), policy.Config)
	}
	items := make([]map[string]any, 0, len(candidates))
	for _, candidate := range candidates {
		policy, configured := policies[candidate.TargetGroupID]
		reasons := []string{"目标分组未配置启用策略"}
		eligible := false
		fallback := false
		plannedPriority := 0
		if configured {
			reasons = policyRejectionReasons(candidate, policy.Config)
			if observation := policyLatencyObservationReason(candidate, policy.Config); observation != "" {
				reasons = append(reasons, observation)
			}
			if cacheReason := policyCacheReason(candidate, policy.Config); cacheReason != "" {
				reasons = append(reasons, cacheReason)
			}
			plan := plans[candidate.TargetGroupID]
			plannedPriority, eligible = plan.Priorities[candidate.ID]
			fallback = plan.Fallback[candidate.ID]
			if fallback {
				reasons = append(reasons, fmt.Sprintf("常规可用渠道仅 %d/%d，当前作为低优先级兜底", plan.NormalCount, policy.Config.MinAvailableChannels))
			}
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
			if candidate.LatencyState == latencyStateSlow {
				remainingProbes = max(remainingProbes, max(0, latencyGoodSnapshots-candidate.LatencyGoodSnapshots))
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
			"schedulable": candidate.Schedulable, "eligible": eligible, "fallback": fallback, "fallbackActive": candidate.FallbackActive, "priority": candidate.Priority, "plannedPriority": plannedPriority, "syncStatus": candidate.SyncStatus,
			"channelState": candidate.State, "modelCheckRequired": candidate.ModelCheckRequired, "modelCheckStatus": candidate.ModelCheckStatus, "modelCheckModel": candidate.ModelCheckModel, "modelCheckScore": nullableFloat(candidate.ModelCheckScore), "modelCheckReason": candidate.ModelCheckReason, "modelCheckOverride": candidate.ModelCheckOverride, "sourceMultiplier": nullableFloat(candidate.SourceMultiplier), "targetMultiplier": nullableFloat(candidate.TargetMultiplier),
			"samples": candidate.Samples, "successRate": nullableFloat(candidate.SuccessRate), "firstTokenP50Ms": nullableFloat(candidate.FirstTokenP50), "firstTokenP90Ms": nullableFloat(candidate.FirstTokenP90), "firstTokenP95Ms": nullableFloat(candidate.FirstTokenP50), "speedFirstTokenMs": nullableFloat(candidate.FirstTokenP50), "speedMetricSource": candidate.SpeedMetricSource, "speedMetricModel": candidate.SpeedMetricModel, "speedMetricSamples": candidate.SpeedMetricSamples, "maxFirstTokenMs": policy.Config.MaxFirstTokenMs, "recentSuccesses": displayedSuccesses,
			"cacheState": candidate.CacheState, "cacheScore": nullableFloat(candidate.CacheScore), "cacheSamples": candidate.CacheSamples, "cacheInputTokens": candidate.CacheInputTokens, "cacheReadTokens": candidate.CacheReadTokens, "cacheMetricSource": candidate.CacheMetricSource, "cacheMetricModel": candidate.CacheMetricModel, "cacheMetricRequestType": candidate.CacheMetricRequestType, "cachePenaltyActive": candidate.CachePenaltyActive, "cacheExploration": plans[candidate.TargetGroupID].Exploration[candidate.ID], "cacheReason": policyCacheReason(candidate, policy.Config), "cacheMode": policy.Config.CacheMode,
			"latencyState": candidate.LatencyState, "latencyBadSnapshots": candidate.LatencyBadSnapshots, "latencyBadRequired": latencyBadSnapshotLimit(candidate, policy.Config), "latencyGoodSnapshots": candidate.LatencyGoodSnapshots, "latencyMinSamples": businessLatencyMinSamples,
			"policyId": map[bool]any{true: policy.ID, false: nil}[configured], "policyName": policy.Name,
			"minSamples": policy.Config.MinSamples, "minSuccessRate": policy.Config.MinSuccessRate, "minAvailableChannels": policy.Config.MinAvailableChannels, "cacheAbsoluteGap": policy.Config.CacheAbsoluteGap, "cacheRelativeGap": policy.Config.CacheRelativeGap,
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
	var actionManagedID string
	if err := a.db.QueryRowContext(ctx, `SELECT managed_account_id::text FROM action_intents WHERE id=$1 AND status='APPROVED'`, id).Scan(&actionManagedID); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return a.failAction(ctx, id, err.Error())
	}
	lock := a.managedActionLock(actionManagedID)
	lock.Lock()
	defer lock.Unlock()

	var managedID, action, before, after, idempotencyKey, targetID, targetBase, remoteID, remoteName, marker string
	var writeEnabled bool
	err := a.db.QueryRowContext(ctx, `SELECT m.id,i.action_type,i.before_state,i.after_state,i.idempotency_key,t.id,t.base_url,t.write_enabled,m.remote_id,m.remote_name,m.ownership_marker
		FROM action_intents i
		JOIN managed_accounts m ON m.id=i.managed_account_id
		JOIN targets t ON t.id=m.target_id
		WHERE i.id=$1 AND i.status='APPROVED'
		AND NOT EXISTS (
			SELECT 1 FROM action_intents newer
			WHERE newer.managed_account_id=i.managed_account_id
				AND newer.action_type=i.action_type
				AND newer.status='APPROVED'
				AND newer.created_at>i.created_at
		)`, id).Scan(&managedID, &action, &before, &after, &idempotencyKey, &targetID, &targetBase, &writeEnabled, &remoteID, &remoteName, &marker)
	if err != nil {
		if err == sql.ErrNoRows {
			a.rejectSupersededAction(ctx, id)
			return nil
		}
		return a.failAction(ctx, id, err.Error())
	}
	if !writeEnabled || !strings.HasPrefix(marker, "channel-manage:") {
		return a.failAction(ctx, id, "目标写入未授权或托管所有权无效")
	}
	authCtx, authCancel := timeoutContext(ctx)
	session, err := a.authenticateTarget(authCtx, Target{ID: targetID, BaseURL: targetBase}, true)
	authCancel()
	if err != nil {
		return a.failAction(ctx, id, err.Error())
	}
	var state map[string]any
	if json.Unmarshal([]byte(after), &state) != nil {
		return a.failAction(ctx, id, "动作状态不可读")
	}
	var previous map[string]any
	_ = json.Unmarshal([]byte(before), &previous)
	if action == "ROTATE_FALLBACK" || action == "RECREATE_FALLBACK" {
		err = a.executeFallbackRecreation(ctx, id, managedID, targetID, targetBase, remoteID, remoteName, idempotencyKey, session, previous, state)
		if err != nil {
			if errors.Is(err, errManagedActionSuperseded) {
				return nil
			}
			return a.failAction(ctx, id, err.Error())
		}
		a.resolveEvent(ctx, actionFailureEventKey(managedID, action))
		return nil
	}
	requestCtx, cancel := timeoutContext(ctx)
	defer cancel()
	if action == "APPLY_SCHEDULING_PLAN" {
		priority, ok := number(state["priority"])
		if !ok {
			return a.failAction(ctx, id, "调度计划缺少有效优先级")
		}
		err = a.syncTargetAccountPriority(requestCtx, targetBase, remoteID, session, int(priority))
		if err == nil {
			err = a.syncTargetAccountSchedulable(requestCtx, targetBase, remoteID, session, true)
		}
	} else {
		path := "/api/v1/admin/accounts/" + remoteID
		method := http.MethodPut
		payload := state
		if action == "SET_SCHEDULABLE" {
			path += "/schedulable"
			method = http.MethodPost
		}
		var value any
		value, _, err = a.remoteJSON(requestCtx, targetBase, method, path, session, payload)
		if err == nil {
			_, err = unwrapEnvelope(value, "SUB2API")
		}
	}
	if err != nil {
		return a.failAction(ctx, id, err.Error())
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE action_intents current
		SET status='EXECUTED',executed_at=now(),error=''
		WHERE current.id=$1 AND current.status='APPROVED'
		AND NOT EXISTS (
			SELECT 1 FROM action_intents newer
			WHERE newer.managed_account_id=current.managed_account_id
				AND newer.action_type=current.action_type
				AND newer.status='APPROVED'
				AND newer.created_at>current.created_at
		)`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return nil
	}
	if schedulable, ok := state["schedulable"].(bool); ok {
		if _, err = tx.ExecContext(ctx, `UPDATE managed_accounts SET schedulable=$2,fallback_active=CASE WHEN $2 THEN fallback_active ELSE false END,updated_at=now() WHERE id=$1`, managedID, schedulable); err != nil {
			return err
		}
	}
	if priority, ok := number(state["priority"]); ok {
		if _, err = tx.ExecContext(ctx, `UPDATE managed_accounts SET priority=$2,priority_synced_at=now(),updated_at=now() WHERE id=$1`, managedID, int(priority)); err != nil {
			return err
		}
	}
	if fallbackActive, ok := state["fallbackActive"].(bool); ok {
		if _, err = tx.ExecContext(ctx, `UPDATE managed_accounts SET fallback_active=$2,updated_at=now() WHERE id=$1`, managedID, fallbackActive); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err == nil {
		a.resolveEvent(ctx, actionFailureEventKey(managedID, action))
	}
	return err
}

var errManagedActionSuperseded = errors.New("托管动作已被更新动作替代")

func (a *App) rejectSupersededAction(ctx context.Context, id string) {
	_, _ = a.db.ExecContext(ctx, `UPDATE action_intents current
		SET status='REJECTED',error='已由更新的托管动作替代',executed_at=now()
		WHERE current.id=$1 AND current.status='APPROVED'
		AND EXISTS (
			SELECT 1 FROM action_intents newer
			WHERE newer.managed_account_id=current.managed_account_id
				AND newer.action_type=current.action_type
				AND newer.status='APPROVED'
				AND newer.created_at>current.created_at
		)`, id)
}

type fallbackRebuildSpec struct {
	Source          Source
	EncryptedKey    []byte
	SourceGroupName string
	TargetGroupName string
	TargetGroupID   int
	TargetPlatform  string
	RateMultiplier  float64
	Concurrency     int
}

func (a *App) loadFallbackRebuildSpec(ctx context.Context, managedID, targetID, oldRemoteID string) (fallbackRebuildSpec, error) {
	var spec fallbackRebuildSpec
	var targetGroupRemoteID string
	var multiplier sql.NullFloat64
	err := a.db.QueryRowContext(ctx, `SELECT s.id,s.name,s.platform,s.base_url,k.key_cipher,sg.name,
		tg.name,tg.remote_id,tg.platform,COALESCE(m.rate_multiplier,sg.multiplier),m.concurrency
		FROM managed_accounts m
		JOIN channels c ON c.id=m.channel_id
		JOIN sources s ON s.id=c.source_id
		JOIN source_keys k ON k.id=c.source_key_id
		JOIN source_groups sg ON sg.id=c.source_group_id
		JOIN managed_account_groups mg ON mg.managed_account_id=m.id
		JOIN target_groups tg ON tg.id=mg.target_group_id AND tg.target_id=m.target_id
		WHERE m.id=$1 AND m.target_id=$2 AND m.remote_id=$3
		LIMIT 1`, managedID, targetID, oldRemoteID).Scan(
		&spec.Source.ID, &spec.Source.Name, &spec.Source.Platform, &spec.Source.BaseURL,
		&spec.EncryptedKey, &spec.SourceGroupName, &spec.TargetGroupName,
		&targetGroupRemoteID, &spec.TargetPlatform, &multiplier, &spec.Concurrency,
	)
	if err != nil {
		return spec, fmt.Errorf("读取重建账号配置失败: %w", err)
	}
	if !multiplier.Valid || multiplier.Float64 < 0 {
		return spec, fmt.Errorf("重建账号缺少有效倍率")
	}
	spec.RateMultiplier = multiplier.Float64
	if spec.Concurrency < 1 {
		spec.Concurrency = 1000
	}
	spec.TargetGroupID, err = strconv.Atoi(targetGroupRemoteID)
	if err != nil {
		return spec, fmt.Errorf("目标分组 ID 不兼容: %w", err)
	}
	return spec, nil
}

func (a *App) fetchRemoteAccountModelMapping(ctx context.Context, targetBase, remoteID string, session remoteSession) (map[string]string, error) {
	value, _, err := a.remoteJSON(ctx, targetBase, http.MethodGet, "/api/v1/admin/accounts/"+remoteID, session, nil)
	if err != nil {
		return nil, err
	}
	data, err := unwrapEnvelope(value, "SUB2API")
	if err != nil {
		return nil, err
	}
	account, _ := data.(map[string]any)
	credentials, _ := account["credentials"].(map[string]any)
	rawMapping, _ := credentials["model_mapping"].(map[string]any)
	mapping := make(map[string]string, len(rawMapping))
	for sourceModel, rawTargetModel := range rawMapping {
		targetModel, ok := rawTargetModel.(string)
		if ok && strings.TrimSpace(sourceModel) != "" && strings.TrimSpace(targetModel) != "" {
			mapping[sourceModel] = targetModel
		}
	}
	if len(mapping) == 0 {
		return nil, fmt.Errorf("旧账号没有可复用的模型映射")
	}
	return mapping, nil
}

func (a *App) lowerExistingFallbackPriority(ctx context.Context, managedID, targetBase, remoteID string, session remoteSession, priority int) error {
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := a.syncTargetAccountPriority(requestCtx, targetBase, remoteID, session, priority); err != nil {
		return err
	}
	_, err := a.db.ExecContext(ctx, `UPDATE managed_accounts SET priority=$2,priority_synced_at=now(),updated_at=now() WHERE id=$1 AND remote_id=$3`, managedID, priority, remoteID)
	return err
}

func (a *App) fallbackRecreationError(ctx context.Context, managedID, targetBase, remoteID string, session remoteSession, priority int, cause error) error {
	if lowerErr := a.lowerExistingFallbackPriority(ctx, managedID, targetBase, remoteID, session, priority); lowerErr == nil {
		return fmt.Errorf("重建末档兜底账号失败，旧账号已降至优先级 %d: %w", priority, cause)
	}
	return fmt.Errorf("重建末档兜底账号失败: %w", cause)
}

func (a *App) executeFallbackRecreation(ctx context.Context, actionID, managedID, targetID, targetBase, oldRemoteID, oldRemoteName, idempotencyKey string, session remoteSession, previous, state map[string]any) (resultErr error) {
	priority, ok := number(state["priority"])
	if !ok {
		return fmt.Errorf("慢速兜底动作缺少有效优先级")
	}
	wasSchedulable, _ := previous["schedulable"].(bool)
	rotationCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	spec, err := a.loadFallbackRebuildSpec(rotationCtx, managedID, targetID, oldRemoteID)
	if err != nil {
		return a.fallbackRecreationError(ctx, managedID, targetBase, oldRemoteID, session, int(priority), err)
	}
	key, err := a.decryptSecret(spec.EncryptedKey)
	if err != nil {
		return a.fallbackRecreationError(ctx, managedID, targetBase, oldRemoteID, session, int(priority), fmt.Errorf("读取重建账号密钥失败: %w", err))
	}
	modelMapping, err := a.fetchRemoteAccountModelMapping(rotationCtx, targetBase, oldRemoteID, session)
	if err != nil {
		return a.fallbackRecreationError(ctx, managedID, targetBase, oldRemoteID, session, int(priority), fmt.Errorf("读取旧账号模型映射失败: %w", err))
	}
	sourceAPIBase, err := a.discoverSourceAPIBaseURL(rotationCtx, spec.Source)
	if err != nil {
		return a.fallbackRecreationError(ctx, managedID, targetBase, oldRemoteID, session, int(priority), fmt.Errorf("读取源站 API 地址失败: %w", err))
	}
	newRemoteName := managedAccountName(spec.Source.Name, spec.SourceGroupName, spec.TargetGroupName, spec.TargetGroupID)
	newRemoteID, err := a.createRemoteManagedAccountWithMappingIdempotent(rotationCtx, targetBase, session, sourceAPIBase, spec.TargetPlatform, string(key), modelMapping, []int{spec.TargetGroupID}, newRemoteName, spec.RateMultiplier, int(priority), spec.Concurrency, idempotencyKey)
	if err != nil {
		return a.fallbackRecreationError(ctx, managedID, targetBase, oldRemoteID, session, int(priority), err)
	}
	oldDisabled := false
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = a.syncTargetAccountSchedulable(cleanupCtx, targetBase, newRemoteID, session, false)
		if oldDisabled && wasSchedulable {
			_ = a.syncTargetAccountSchedulable(cleanupCtx, targetBase, oldRemoteID, session, true)
		}
		_ = a.lowerExistingFallbackPriority(cleanupCtx, managedID, targetBase, oldRemoteID, session, int(priority))
		_ = a.deleteRemoteManagedAccountChecked(cleanupCtx, targetBase, session, newRemoteID)
	}()
	if err = a.syncTargetAccountPriority(rotationCtx, targetBase, newRemoteID, session, int(priority)); err != nil {
		return err
	}
	if err = a.syncTargetAccountSchedulable(rotationCtx, targetBase, newRemoteID, session, false); err != nil {
		return err
	}
	if err = a.syncTargetAccountSchedulable(rotationCtx, targetBase, oldRemoteID, session, false); err != nil {
		return err
	}
	oldDisabled = true
	if err = a.syncTargetAccountSchedulable(rotationCtx, targetBase, newRemoteID, session, true); err != nil {
		return err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO managed_account_remote_history(managed_account_id,target_id,remote_id,remote_name,reason) VALUES($1,$2,$3,$4,'慢速兜底重建并删除')
		ON CONFLICT(target_id,remote_id) DO UPDATE SET reason=EXCLUDED.reason,deleted_at=NULL,cleanup_attempted_at=NULL,cleanup_error=''`, managedID, targetID, oldRemoteID, oldRemoteName); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE action_intents current
		SET status='EXECUTED',executed_at=now(),error=''
		WHERE current.id=$1 AND current.status='APPROVED'
		AND NOT EXISTS (
			SELECT 1 FROM action_intents newer
			WHERE newer.managed_account_id=current.managed_account_id
				AND newer.action_type=current.action_type
				AND newer.status='APPROVED'
				AND newer.created_at>current.created_at
		)`, actionID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return errManagedActionSuperseded
	}
	result, err = tx.ExecContext(ctx, `UPDATE managed_accounts SET remote_id=$2,remote_name=$3,priority=$4,schedulable=true,fallback_active=true,priority_synced_at=now(),sync_status='SYNCED',last_error='',updated_at=now() WHERE id=$1 AND remote_id=$5`, managedID, newRemoteID, newRemoteName, int(priority), oldRemoteID)
	if err != nil {
		return err
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return fmt.Errorf("托管账号在替换过程中已发生变化")
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	committed = true
	cleanupKey := "retired-account-cleanup:" + targetID + ":" + oldRemoteID
	if err = a.deleteRemoteManagedAccountChecked(rotationCtx, targetBase, session, oldRemoteID); err != nil {
		_, _ = a.db.ExecContext(ctx, `UPDATE managed_account_remote_history SET cleanup_attempted_at=now(),cleanup_error=$3 WHERE target_id=$1 AND remote_id=$2`, targetID, oldRemoteID, truncate(err.Error(), 500))
		a.openEvent(ctx, "P1", "RETIRED_ACCOUNT_CLEANUP", "旧兜底账号删除失败", err.Error(), cleanupKey)
	} else {
		_, _ = a.db.ExecContext(ctx, `UPDATE managed_account_remote_history SET deleted_at=now(),cleanup_attempted_at=now(),cleanup_error='' WHERE target_id=$1 AND remote_id=$2`, targetID, oldRemoteID)
		a.resolveEvent(ctx, cleanupKey)
	}
	a.audit(ctx, "RECREATE_FALLBACK", "managed_account", managedID, map[string]any{"old_remote_id": oldRemoteID, "new_remote_id": newRemoteID, "priority": int(priority), "old_deleted": err == nil})
	return nil
}

func actionFailureEventKey(managedID, action string) string {
	return "action-failure:" + managedID + ":" + action
}

func (a *App) failAction(ctx context.Context, id, message string) error {
	var managedID, action string
	if err := a.db.QueryRowContext(ctx, `SELECT COALESCE(managed_account_id::text,''),action_type FROM action_intents WHERE id=$1`, id).Scan(&managedID, &action); err != nil {
		managedID = id
		action = "UNKNOWN"
	}
	result, err := a.db.ExecContext(ctx, `UPDATE action_intents current
		SET status='FAILED',error=$2,executed_at=now()
		WHERE current.id=$1 AND current.status='APPROVED'
		AND NOT EXISTS (
			SELECT 1 FROM action_intents newer
			WHERE newer.managed_account_id=current.managed_account_id
				AND newer.action_type=current.action_type
				AND newer.status='APPROVED'
				AND newer.created_at>current.created_at
		)`, id, truncate(message, 500))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("action superseded: %s", message)
	}
	if managedAccountGoneError(message) && managedID != "" {
		_, _ = a.db.ExecContext(ctx, `UPDATE managed_accounts SET schedulable=false,sync_status='FAILED',last_error=$2,updated_at=now() WHERE id=$1`, managedID, truncate("远端托管账号已不存在，已停止调度："+message, 500))
	}
	a.openEvent(ctx, "P0", "ACTION_EXECUTION", "远程动作执行失败", message, actionFailureEventKey(managedID, action))
	return fmt.Errorf("action failed: %s", message)
}

func managedAccountGoneError(message string) bool {
	message = strings.ToLower(message)
	for _, marker := range []string{"account_not_found", "managed_account_not_found", "account not found", "账户不存在", "账号不存在", "group_deleted", "分组已删除"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

type policyConfig struct {
	Mode                     string   `json:"mode"`
	MinSuccessRate           float64  `json:"minSuccessRate"`
	MinSamples               int      `json:"minSamples"`
	MaxFirstTokenMs          int      `json:"maxFirstTokenMs"`
	MinAvailableChannels     int      `json:"minAvailableChannels"`
	PriorityStart            int      `json:"priorityStart"`
	PriorityStep             int      `json:"priorityStep"`
	AllowEqualMultiplier     bool     `json:"allowEqualMultiplier"`
	DynamicMultiplierEnabled bool     `json:"dynamicMultiplierEnabled"`
	DynamicMultiplierType    string   `json:"dynamicMultiplierType"`
	DynamicMultiplierValue   float64  `json:"dynamicMultiplierValue"`
	DynamicMultiplierMax     float64  `json:"dynamicMultiplierMax"`
	ProbeModel               string   `json:"probeModel"`
	DisabledModels           []string `json:"disabledModels"`
	CacheMode                string   `json:"cacheMode"`
	CacheMinRequests         int      `json:"cacheMinRequests"`
	CacheMinInputTokens      int64    `json:"cacheMinInputTokens"`
	CacheAbsoluteGap         float64  `json:"cacheAbsoluteGap"`
	CacheRelativeGap         float64  `json:"cacheRelativeGap"`
	CacheBadSnapshots        int      `json:"cacheBadSnapshots"`
	CacheGoodSnapshots       int      `json:"cacheGoodSnapshots"`
}

const defaultPolicyMaxFirstTokenMs = 10_000

const (
	dynamicMultiplierFixed      = "FIXED"
	dynamicMultiplierPercent    = "PERCENT"
	dynamicMultiplierStep       = 0.01
	defaultDynamicMultiplierMax = 1.0

	cacheModeOff            = "OFF"
	cacheModeObserve        = "OBSERVE"
	cacheModeDeprioritize   = "DEPRIORITIZE"
	defaultCacheMinRequest  = 50
	defaultCacheMinTokens   = 50_000
	defaultCacheAbsoluteGap = 0.10
	defaultCacheRelativeGap = 0.25
)

func normalizePolicyConfig(config policyConfig) policyConfig {
	if config.Mode != "SPEED" {
		config.Mode = "PRICE"
	}
	if config.DynamicMultiplierType != dynamicMultiplierPercent {
		config.DynamicMultiplierType = dynamicMultiplierFixed
	}
	if config.DynamicMultiplierValue == 0 && !config.DynamicMultiplierEnabled {
		config.DynamicMultiplierValue = dynamicMultiplierStep
	}
	if config.DynamicMultiplierMax == 0 && config.DynamicMultiplierEnabled {
		config.DynamicMultiplierMax = defaultDynamicMultiplierMax
	}
	if config.MinSuccessRate <= 0 {
		config.MinSuccessRate = 95
	}
	if config.MinSamples < 1 {
		config.MinSamples = 5
	}
	if config.MaxFirstTokenMs <= 0 {
		config.MaxFirstTokenMs = defaultPolicyMaxFirstTokenMs
	}
	if config.MinAvailableChannels < 1 {
		config.MinAvailableChannels = 5
	}
	if config.PriorityStart < 1 {
		config.PriorityStart = 1000
	}
	if config.PriorityStep < 1000 {
		config.PriorityStep = 1000
	}
	if config.CacheMode != cacheModeObserve && config.CacheMode != cacheModeDeprioritize {
		config.CacheMode = cacheModeOff
	}
	if config.CacheMinRequests < 1 {
		config.CacheMinRequests = defaultCacheMinRequest
	}
	if config.CacheMinInputTokens < 1 {
		config.CacheMinInputTokens = defaultCacheMinTokens
	}
	if config.CacheAbsoluteGap <= 0 || config.CacheAbsoluteGap >= 1 {
		config.CacheAbsoluteGap = defaultCacheAbsoluteGap
	}
	if config.CacheRelativeGap <= 0 || config.CacheRelativeGap >= 1 {
		config.CacheRelativeGap = defaultCacheRelativeGap
	}
	if config.CacheBadSnapshots < 1 {
		config.CacheBadSnapshots = 3
	}
	if config.CacheGoodSnapshots < 1 {
		config.CacheGoodSnapshots = 3
	}
	config.ProbeModel = strings.TrimSpace(config.ProbeModel)
	config.DisabledModels = normalizeModelNames(config.DisabledModels)
	return config
}

func (a *App) validatePolicyProbeModel(ctx context.Context, scopeID string, config policyConfig) (policyConfig, error) {
	if err := validateDynamicMultiplierConfig(config); err != nil {
		return config, err
	}
	if config.MaxFirstTokenMs < 1_000 || config.MaxFirstTokenMs > maxFirstTokenMs {
		return config, &apiError{400, "INVALID_FIRST_TOKEN_LIMIT", "首 Token 上限需要设置为 1 至 60 秒"}
	}
	if config.MinAvailableChannels < 1 || config.MinAvailableChannels > 100 {
		return config, &apiError{400, "INVALID_MIN_AVAILABLE_CHANNELS", "最低可用渠道数需要设置为 1 至 100"}
	}
	if config.PriorityStart < 1 || config.PriorityStart > 1_000_000 {
		return config, &apiError{400, "INVALID_PRIORITY_START", "优先级起点需要设置为 1 至 1000000"}
	}
	if config.PriorityStep < 1000 || config.PriorityStep > 1_000_000 {
		return config, &apiError{400, "INVALID_PRIORITY_STEP", "优先级间隔需要设置为 1000 至 1000000"}
	}
	if config.CacheMinRequests < 1 || config.CacheMinRequests > 10000 {
		return config, &apiError{400, "INVALID_CACHE_REQUESTS", "缓存最少请求数需要设置为 1 至 10000"}
	}
	if config.CacheMinInputTokens < 1 || config.CacheMinInputTokens > 1000000000 {
		return config, &apiError{400, "INVALID_CACHE_TOKENS", "缓存最少输入 Token 需要设置为 1 至 1000000000"}
	}
	if config.CacheAbsoluteGap < 0.01 || config.CacheAbsoluteGap > 0.9 {
		return config, &apiError{400, "INVALID_CACHE_ABSOLUTE_GAP", "缓存绝对差距需要设置为 1 至 90 个百分点"}
	}
	if config.CacheRelativeGap < 0.01 || config.CacheRelativeGap > 0.9 {
		return config, &apiError{400, "INVALID_CACHE_GAP", "缓存相对差距需要设置为 1% 至 90%"}
	}
	if config.CacheBadSnapshots < 1 || config.CacheBadSnapshots > 20 || config.CacheGoodSnapshots < 1 || config.CacheGoodSnapshots > 20 {
		return config, &apiError{400, "INVALID_CACHE_SNAPSHOTS", "缓存确认窗口需要设置为 1 至 20 次"}
	}
	var platform string
	if err := a.db.QueryRowContext(ctx, `SELECT platform FROM target_groups WHERE id=$1`, scopeID).Scan(&platform); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return config, &apiError{400, "INVALID_POLICY_SCOPE", "目标分组不存在"}
		}
		return config, err
	}
	if config.ProbeModel == "" {
		config.ProbeModel = defaultProbeModelForPlatform(platform)
	}
	if err := validatePolicyModelNames(config); err != nil {
		return config, err
	}
	return config, nil
}

func validateDynamicMultiplierConfig(config policyConfig) error {
	if !config.DynamicMultiplierEnabled {
		return nil
	}
	if config.Mode != "PRICE" {
		return &apiError{400, "DYNAMIC_MULTIPLIER_PRICE_ONLY", "动态倍率只能在价格优先策略中启用"}
	}
	value := config.DynamicMultiplierValue
	if math.IsNaN(value) || math.IsInf(value, 0) || value < dynamicMultiplierStep {
		return &apiError{400, "INVALID_DYNAMIC_MULTIPLIER_VALUE", "动态倍率上浮值不能小于 0.01"}
	}
	maxMultiplier := config.DynamicMultiplierMax
	if maxMultiplier == 0 {
		maxMultiplier = defaultDynamicMultiplierMax
	}
	if math.IsNaN(maxMultiplier) || math.IsInf(maxMultiplier, 0) || maxMultiplier < dynamicMultiplierStep || maxMultiplier > 10_000_000 {
		return &apiError{400, "INVALID_DYNAMIC_MULTIPLIER_MAX", "动态倍率上限需要设置为 0.01 至 10000000"}
	}
	if config.DynamicMultiplierType == dynamicMultiplierPercent {
		if value > 10_000 {
			return &apiError{400, "INVALID_DYNAMIC_MULTIPLIER_VALUE", "动态倍率上浮百分比不能超过 10000%"}
		}
		return nil
	}
	if config.DynamicMultiplierType != dynamicMultiplierFixed || value > 1_000 {
		return &apiError{400, "INVALID_DYNAMIC_MULTIPLIER_VALUE", "动态倍率固定增加值需要设置为 0.01 至 1000"}
	}
	return nil
}

func validatePolicyModelNames(config policyConfig) error {
	if !validPolicyModelName(config.ProbeModel) {
		return &apiError{400, "INVALID_PROBE_MODEL", "业务测速模型需要是 1 至 200 个字符的单行模型名称"}
	}
	if len(config.DisabledModels) > 200 {
		return &apiError{400, "TOO_MANY_DISABLED_MODELS", "禁用模型最多填写 200 个"}
	}
	for _, model := range config.DisabledModels {
		if !validPolicyModelName(model) {
			return &apiError{400, "INVALID_DISABLED_MODEL", "禁用模型需要是 1 至 200 个字符的单行模型名称"}
		}
		if model == config.ProbeModel {
			return &apiError{400, "PROBE_MODEL_DISABLED", "业务测速模型不能同时加入禁用模型清单"}
		}
	}
	return nil
}

func validPolicyModelName(model string) bool {
	model = strings.TrimSpace(model)
	if model == "" || len([]rune(model)) > 200 {
		return false
	}
	return !strings.ContainsAny(model, "\r\n\x00")
}

func (a *App) listPolicies(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT p.id,p.name,p.scope_type,p.scope_id,p.status,p.active_version,p.created_at,COALESCE(v.config,'{}'::jsonb),COALESCE(tg.name,''),COALESCE(t.name,''),tg.target_id,COALESCE(tg.models,'[]'::jsonb),tg.multiplier,
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
		var targetMultiplier sql.NullFloat64
		var managedCount, schedulableCount int
		var created time.Time
		if err := rows.Scan(&id, &name, &scope, &scopeID, &status, &active, &created, &config, &targetGroupName, &targetName, &targetID, &probeModels, &targetMultiplier, &managedCount, &schedulableCount); err != nil {
			return nil, err
		}
		var policy policyConfig
		_ = json.Unmarshal([]byte(config), &policy)
		items = append(items, map[string]any{"id": id, "name": name, "scopeType": scope, "scopeId": nullableString(scopeID), "targetId": nullableString(targetID), "targetGroupName": targetGroupName, "targetName": targetName, "targetMultiplier": nullableFloat(targetMultiplier), "status": status, "activeVersion": nullableInt(active), "config": normalizePolicyConfig(policy), "probeModels": json.RawMessage(probeModels), "managedCount": managedCount, "schedulableCount": schedulableCount, "evaluationIntervalSeconds": fastProbeIntervalSeconds, "metricWindowDays": policyMetricWindowDays, "multiplierLimitSource": "TARGET_GROUP", "multiplierCacheSeconds": int(targetMultiplierCacheTTL.Seconds()), "createdAt": created})
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
	a.requestPolicyEvaluation()
	go a.syncPolicyModelMappings(context.Background(), scopeID)
	writeData(w, map[string]any{"id": id, "name": input.Name, "version": version})
	return nil
}

func (a *App) deletePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	var scopeID string
	if err := a.db.QueryRowContext(r.Context(), `SELECT scope_id FROM policies WHERE id=$1`, id).Scan(&scopeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &apiError{404, "POLICY_NOT_FOUND", "策略不存在"}
		}
		return err
	}
	result, err := a.db.ExecContext(r.Context(), `DELETE FROM policies WHERE id=$1`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "POLICY_NOT_FOUND", "策略不存在"}
	}
	a.audit(r.Context(), "DELETE", "policy", id, nil)
	a.resolveEvent(r.Context(), dynamicMultiplierEventKey(scopeID))
	go a.syncPolicyModelMappings(context.Background(), scopeID)
	writeData(w, map[string]bool{"deleted": true})
	return nil
}

func (a *App) deactivatePolicy(w http.ResponseWriter, r *http.Request, id string) error {
	var scopeID string
	err := a.db.QueryRowContext(r.Context(), `UPDATE policies SET status='DRAFT',updated_at=now() WHERE id=$1 AND status='ACTIVE' RETURNING scope_id`, id).Scan(&scopeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &apiError{409, "POLICY_NOT_ACTIVE", "策略未处于启用状态"}
		}
		return err
	}
	a.audit(r.Context(), "DEACTIVATE", "policy", id, nil)
	a.resolveEvent(r.Context(), dynamicMultiplierEventKey(scopeID))
	go a.syncPolicyModelMappings(context.Background(), scopeID)
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
	a.requestPolicyEvaluation()
	var scopeID string
	if err = a.db.QueryRowContext(r.Context(), `SELECT scope_id FROM policies WHERE id=$1`, id).Scan(&scopeID); err == nil {
		go a.syncPolicyModelMappings(context.Background(), scopeID)
	}
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
	groupCandidates := candidatesForTargetGroup(candidates, scopeID)
	dynamicPreview := map[string]any{"enabled": config.DynamicMultiplierEnabled}
	if config.DynamicMultiplierEnabled {
		if quote, available := calculateDynamicMultiplier(groupCandidates, config); available {
			dynamicPreview["available"] = true
			dynamicPreview["sourceGroup"] = quote.SourceGroup
			dynamicPreview["lowest"] = quote.Lowest
			dynamicPreview["desired"] = quote.Desired
			groupCandidates = candidatesWithTargetMultiplier(groupCandidates, quote.Desired)
		} else {
			dynamicPreview["available"] = false
		}
	}
	plan := planManagedAccounts(groupCandidates, config)
	for _, candidate := range groupCandidates {
		reasons := policyRejectionReasons(candidate, config)
		if observation := policyLatencyObservationReason(candidate, config); observation != "" {
			reasons = append(reasons, observation)
		}
		if cacheReason := policyCacheReason(candidate, config); cacheReason != "" {
			reasons = append(reasons, cacheReason)
		}
		priority, selected := plan.Priorities[candidate.ID]
		fallback := plan.Fallback[candidate.ID]
		decision := "REJECTED"
		if fallback {
			decision = "FALLBACK"
			reasons = append(reasons, fmt.Sprintf("常规可用渠道仅 %d/%d，按优先级 %d 兜底", plan.NormalCount, config.MinAvailableChannels, priority))
		} else if selected {
			decision = "ELIGIBLE"
		}
		preview = append(preview, map[string]any{"managedAccountId": candidate.ID, "remoteName": candidate.RemoteName, "sourceName": candidate.SourceName, "sourceGroup": candidate.SourceGroup, "sourceMultiplier": nullableFloat(candidate.SourceMultiplier), "targetName": candidate.TargetName, "targetGroup": candidate.TargetGroup, "targetMultiplier": nullableFloat(candidate.TargetMultiplier), "samples": candidate.Samples, "successRate": nullableFloat(candidate.SuccessRate), "minSamples": config.MinSamples, "minSuccessRate": config.MinSuccessRate, "maxFirstTokenMs": config.MaxFirstTokenMs, "firstTokenP50Ms": nullableFloat(candidate.FirstTokenP50), "firstTokenP90Ms": nullableFloat(candidate.FirstTokenP90), "speedFirstTokenMs": nullableFloat(candidate.FirstTokenP50), "speedMetricSource": candidate.SpeedMetricSource, "speedMetricModel": candidate.SpeedMetricModel, "speedMetricSamples": candidate.SpeedMetricSamples, "latencyState": candidate.LatencyState, "latencyBadSnapshots": candidate.LatencyBadSnapshots, "latencyBadRequired": latencyBadSnapshotLimit(candidate, config), "latencyGoodSnapshots": candidate.LatencyGoodSnapshots, "latencyMinSamples": businessLatencyMinSamples, "cacheState": candidate.CacheState, "cacheScore": nullableFloat(candidate.CacheScore), "cacheSamples": candidate.CacheSamples, "cacheInputTokens": candidate.CacheInputTokens, "cacheReadTokens": candidate.CacheReadTokens, "cacheMetricSource": candidate.CacheMetricSource, "cacheMetricModel": candidate.CacheMetricModel, "cacheMetricRequestType": candidate.CacheMetricRequestType, "cachePenaltyActive": candidate.CachePenaltyActive, "cacheExploration": plan.Exploration[candidate.ID], "cacheReason": policyCacheReason(candidate, config), "cacheMode": config.CacheMode, "cacheAbsoluteGap": config.CacheAbsoluteGap, "cacheRelativeGap": config.CacheRelativeGap, "plannedPriority": priority, "decision": decision, "reasons": reasons})
	}
	writeData(w, map[string]any{"policyId": id, "generatedAt": time.Now(), "dynamicMultiplier": dynamicPreview, "preview": preview})
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
		"min_healthy_channels": true, "confirmation_failures": true, "transient_confirmation_failures": true, "metric_window_minutes": true,
		"min_error_samples": true, "error_rate_threshold": true,
		"balance_alert_threshold":     true,
		modelQualityProbeModelSetting: true,
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
		if key == "balance_alert_threshold" {
			threshold, ok := number(value)
			if !ok || math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold <= 0 || threshold > 1000000 {
				return &apiError{400, "INVALID_BALANCE_ALERT_THRESHOLD", "余额提醒阈值必须大于 0 且不超过 1000000"}
			}
		}
		if key == "transient_confirmation_failures" {
			threshold, ok := number(value)
			if !ok || math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 3 || threshold > 20 || math.Trunc(threshold) != threshold {
				return &apiError{400, "INVALID_TRANSIENT_CONFIRMATION_FAILURES", "瞬时错误确认次数必须是 3 至 20 的整数"}
			}
		}
		if key == modelQualityProbeModelSetting {
			configured, ok := value.(string)
			if !ok {
				return &apiError{400, "INVALID_MODEL", "模型能力检测模型必须是文本"}
			}
			normalized, validationErr := resolveModelQualityProbeModel(configured)
			if validationErr != nil {
				return validationErr
			}
			value = normalized
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

func (a *App) settingFloat(ctx context.Context, key string, fallback float64) float64 {
	var raw string
	if a.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&raw) != nil {
		return fallback
	}
	value, err := strconv.ParseFloat(strings.Trim(raw, `"`), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return fallback
	}
	return value
}

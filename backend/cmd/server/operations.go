package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (a *App) listChannels(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT c.id,s.name,k.name,g.name,g.multiplier,c.lifecycle_state,c.state_reason,c.score,c.priority_tier,c.consecutive_failures,c.last_probe_at,c.state_changed_at,
		(SELECT count(*) FROM probe_runs p WHERE p.channel_id=c.id AND p.started_at>now()-interval '1 hour'),
		(SELECT avg(CASE WHEN p.success THEN 100.0 ELSE 0 END) FROM probe_runs p WHERE p.channel_id=c.id AND p.started_at>now()-interval '1 hour'),
		(SELECT avg(CASE WHEN p.success THEN 100.0 ELSE 0 END) FROM probe_runs p WHERE p.channel_id=c.id AND p.started_at>now()-interval '7 days'),
		(SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY p.first_token_ms) FROM probe_runs p WHERE p.channel_id=c.id AND p.success AND p.started_at>now()-interval '7 days'),
		(SELECT COALESCE(sum(m.requests),0) FROM metric_buckets m WHERE m.channel_id=c.id AND m.window_start>now()-interval '1 hour'),
		(SELECT CASE WHEN COALESCE(sum(m.requests),0)=0 THEN NULL ELSE 100.0*(sum(m.requests)-sum(m.errors))/sum(m.requests) END FROM metric_buckets m WHERE m.channel_id=c.id AND m.window_start>now()-interval '1 hour')
		FROM channels c JOIN sources s ON s.id=c.source_id JOIN source_keys k ON k.id=c.source_key_id LEFT JOIN source_groups g ON g.id=c.source_group_id ORDER BY s.name,k.name,g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, sourceName, keyName, groupName, state, reason, tier string
		var multiplier, score, rate1h, rate7d, p95, businessRate sql.NullFloat64
		var failures, samples, businessRequests int
		var lastProbe sql.NullTime
		var changed time.Time
		if err := rows.Scan(&id, &sourceName, &keyName, &groupName, &multiplier, &state, &reason, &score, &tier, &failures, &lastProbe, &changed, &samples, &rate1h, &rate7d, &p95, &businessRequests, &businessRate); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "sourceName": sourceName, "keyName": keyName, "groupName": groupName, "multiplier": nullableFloat(multiplier), "lifecycleState": state, "stateReason": reason, "score": nullableFloat(score), "priorityTier": tier, "consecutiveFailures": failures, "lastProbeAt": nullableTime(lastProbe), "stateChangedAt": changed, "probeSamples1h": samples, "probeExpected1h": 4, "probeSamples7d": samples, "probeExpected7d": 672, "successRate": nullableFloat(rate1h), "successRate7d": nullableFloat(rate7d), "firstTokenP95Ms": nullableFloat(p95), "requests": samples, "businessRequests1h": businessRequests, "businessSuccessRate1h": nullableFloat(businessRate), "metricWindowMinutes": 60})
	}
	return items, rows.Err()
}

func nullableTime(value sql.NullTime) any {
	if value.Valid {
		return value.Time
	}
	return nil
}

func (a *App) probeChannel(ctx context.Context, id string) error {
	var sourceBase, encryptedKey, state string
	err := a.db.QueryRowContext(ctx, `SELECT s.base_url,k.key_cipher,c.lifecycle_state FROM channels c JOIN sources s ON s.id=c.source_id JOIN source_keys k ON k.id=c.source_key_id WHERE c.id=$1`, id).Scan(&sourceBase, &encryptedKey, &state)
	if err == sql.ErrNoRows {
		return &apiError{404, "CHANNEL_NOT_FOUND", "渠道不存在"}
	}
	if err != nil {
		return err
	}
	if state == "MANUAL_HOLD" {
		return &apiError{409, "CHANNEL_ON_HOLD", "人工暂停的渠道不会自动探测"}
	}
	keyBytes, err := a.decryptSecret([]byte(encryptedKey))
	if err != nil {
		return err
	}
	started := time.Now()
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	value, _, requestErr := a.remoteJSON(requestCtx, sourceBase, http.MethodGet, "/v1/models", remoteSession{Authorization: "Bearer " + string(keyBytes)}, nil)
	latency := int(time.Since(started).Milliseconds())
	success := requestErr == nil
	errorType := ""
	summary := ""
	models := []string{}
	if success {
		record, _ := value.(map[string]any)
		if raw, ok := record["data"].([]any); ok {
			for _, entry := range raw {
				if model, ok := entry.(map[string]any); ok {
					if modelID := text(model["id"], ""); modelID != "" {
						models = append(models, modelID)
					}
				}
			}
		}
		sort.Strings(models)
		summary = fmt.Sprintf("读取到 %d 个模型", len(models))
	} else {
		errorType = requestErr.Error()
		summary = "探测失败"
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO probe_runs(channel_id,kind,success,latency_ms,first_token_ms,error_type,response_summary,finished_at) VALUES($1,'LIGHT',$2,$3,$3,$4,$5,now())`, id, success, latency, truncate(errorType, 100), summary)
	if err != nil {
		return err
	}
	if success {
		_, err = tx.ExecContext(ctx, `UPDATE channels SET lifecycle_state='HEALTHY',state_reason='最近探测成功',score=100,consecutive_failures=0,last_probe_at=now(),state_changed_at=CASE WHEN lifecycle_state='HEALTHY' THEN state_changed_at ELSE now() END WHERE id=$1`, id)
		if len(models) > 0 {
			_, _ = tx.ExecContext(ctx, `UPDATE source_keys SET models=$2::jsonb,updated_at=now() WHERE id=(SELECT source_key_id FROM channels WHERE id=$1)`, id, jsonValue(models))
		}
	} else {
		windowMinutes := a.settingInt(ctx, "metric_window_minutes", 5)
		minSamples := a.settingInt(ctx, "min_error_samples", 5)
		errorThreshold := a.settingInt(ctx, "error_rate_threshold", 20)
		confirmationFailures := a.settingInt(ctx, "confirmation_failures", 3)
		var businessRequests, businessErrors int
		_ = tx.QueryRowContext(ctx, `SELECT COALESCE(sum(requests),0),COALESCE(sum(errors),0) FROM metric_buckets WHERE channel_id=$1 AND window_start>now()-$2*interval '1 minute'`, id, windowMinutes).Scan(&businessRequests, &businessErrors)
		businessConfirmed := businessRequests >= minSamples && businessErrors*100 >= businessRequests*errorThreshold
		_, err = tx.ExecContext(ctx, `UPDATE channels SET consecutive_failures=consecutive_failures+1,lifecycle_state=CASE WHEN $3 OR consecutive_failures+1 >= $4 THEN 'QUARANTINED' ELSE 'SUSPECT' END,state_reason=$2,last_probe_at=now(),state_changed_at=now(),score=0 WHERE id=$1`, id, truncate(errorType, 200), businessConfirmed, confirmationFailures)
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if !success {
		a.openEvent(ctx, "P1", "CHANNEL_PROBE", "渠道探测异常", errorType, "channel-probe:"+id)
	} else {
		a.resolveEvent(ctx, "channel-probe:"+id)
	}
	return requestErr
}

func (a *App) listManagedAccounts(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.target_id,t.name,m.channel_id,s.name,k.name,m.remote_id,m.remote_name,m.priority,m.concurrency,m.schedulable,m.sync_status,m.last_error,m.created_at,COALESCE(json_agg(json_build_object('id',tg.remote_id,'name',tg.name)) FILTER (WHERE tg.id IS NOT NULL),'[]') FROM managed_accounts m JOIN targets t ON t.id=m.target_id JOIN channels c ON c.id=m.channel_id JOIN sources s ON s.id=c.source_id JOIN source_keys k ON k.id=c.source_key_id LEFT JOIN managed_account_groups mg ON mg.managed_account_id=m.id LEFT JOIN target_groups tg ON tg.id=mg.target_group_id GROUP BY m.id,t.name,s.name,k.name ORDER BY m.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, targetID, targetName, channelID, sourceName, keyName, remoteID, remoteName, status, lastError, groups string
		var priority, concurrency int
		var schedulable bool
		var created time.Time
		if err := rows.Scan(&id, &targetID, &targetName, &channelID, &sourceName, &keyName, &remoteID, &remoteName, &priority, &concurrency, &schedulable, &status, &lastError, &created, &groups); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "targetId": targetID, "targetName": targetName, "channelId": channelID, "sourceName": sourceName, "keyName": keyName, "remoteId": remoteID, "remoteName": remoteName, "priority": priority, "concurrency": concurrency, "schedulable": schedulable, "syncStatus": status, "lastError": lastError, "targetGroups": json.RawMessage(groups), "createdAt": created})
	}
	return items, rows.Err()
}

func (a *App) listManagedAccountsForTarget(w http.ResponseWriter, r *http.Request, targetID string) error {
	items, err := a.listManagedAccounts(r.Context())
	if err != nil {
		return err
	}
	filtered := []map[string]any{}
	for _, item := range items {
		if item["targetId"] == targetID {
			filtered = append(filtered, item)
		}
	}
	writeData(w, filtered)
	return nil
}

func (a *App) updateManagedAccountPriority(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		Priority int `json:"priority"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Priority < 1 || input.Priority > 1000000 {
		return &apiError{400, "INVALID_PRIORITY", "优先级必须在 1 到 1000000 之间"}
	}
	frozen, _ := a.settingBool(r.Context(), "emergency_freeze")
	if frozen {
		return &apiError{409, "REMOTE_WRITE_BLOCKED", "紧急冻结禁止同步优先级"}
	}
	var targetID, targetBase, remoteID, marker string
	var writeEnabled bool
	err := a.db.QueryRowContext(r.Context(), `SELECT t.id,t.base_url,t.write_enabled,m.remote_id,m.ownership_marker FROM managed_accounts m JOIN targets t ON t.id=m.target_id WHERE m.id=$1`, id).Scan(&targetID, &targetBase, &writeEnabled, &remoteID, &marker)
	if err == sql.ErrNoRows {
		return &apiError{404, "MANAGED_ACCOUNT_NOT_FOUND", "托管账号不存在"}
	}
	if err != nil {
		return err
	}
	if !writeEnabled || !strings.HasPrefix(marker, "channel-manage:") {
		return &apiError{409, "TARGET_WRITE_DISABLED", "目标写入未授权或托管所有权无效"}
	}
	requestCtx, cancel := timeoutContext(r.Context())
	defer cancel()
	target, _, err := a.targetCredentials(requestCtx, targetID)
	if err != nil {
		return err
	}
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return err
	}
	if err = a.syncTargetAccountPriority(requestCtx, targetBase, remoteID, session, input.Priority); err != nil {
		return err
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE managed_accounts SET priority=$2,updated_at=now() WHERE id=$1`, id, input.Priority); err != nil {
		return err
	}
	a.audit(r.Context(), "SET_PRIORITY", "managed_account", id, map[string]any{"priority": input.Priority, "remote_id": remoteID})
	writeData(w, map[string]any{"id": id, "priority": input.Priority, "syncStatus": "SYNCED"})
	return nil
}

func (a *App) syncTargetAccountPriority(ctx context.Context, targetBase, remoteID string, session remoteSession, priority int) error {
	return a.syncTargetAccountNumbers(ctx, targetBase, remoteID, session, map[string]int{"priority": priority})
}

func (a *App) updateManagedAccountConcurrency(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		Concurrency int `json:"concurrency"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Concurrency < 1 || input.Concurrency > 1000000 {
		return &apiError{400, "INVALID_CONCURRENCY", "并发必须在 1 到 1000000 之间"}
	}
	frozen, _ := a.settingBool(r.Context(), "emergency_freeze")
	if frozen {
		return &apiError{409, "REMOTE_WRITE_BLOCKED", "紧急冻结禁止同步并发"}
	}
	var targetID, targetBase, remoteID, marker string
	var writeEnabled bool
	err := a.db.QueryRowContext(r.Context(), `SELECT t.id,t.base_url,t.write_enabled,m.remote_id,m.ownership_marker FROM managed_accounts m JOIN targets t ON t.id=m.target_id WHERE m.id=$1`, id).Scan(&targetID, &targetBase, &writeEnabled, &remoteID, &marker)
	if err == sql.ErrNoRows {
		return &apiError{404, "MANAGED_ACCOUNT_NOT_FOUND", "托管账号不存在"}
	}
	if err != nil {
		return err
	}
	if !writeEnabled || !strings.HasPrefix(marker, "channel-manage:") {
		return &apiError{409, "TARGET_WRITE_DISABLED", "目标写入未授权或托管所有权无效"}
	}
	requestCtx, cancel := timeoutContext(r.Context())
	defer cancel()
	target, _, err := a.targetCredentials(requestCtx, targetID)
	if err != nil {
		return err
	}
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return err
	}
	if err = a.syncTargetAccountNumbers(requestCtx, targetBase, remoteID, session, map[string]int{"concurrency": input.Concurrency}); err != nil {
		return err
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE managed_accounts SET concurrency=$2,updated_at=now() WHERE id=$1`, id, input.Concurrency); err != nil {
		return err
	}
	a.audit(r.Context(), "SET_CONCURRENCY", "managed_account", id, map[string]any{"concurrency": input.Concurrency, "remote_id": remoteID})
	writeData(w, map[string]any{"id": id, "concurrency": input.Concurrency, "syncStatus": "SYNCED"})
	return nil
}

func (a *App) syncTargetAccountNumbers(ctx context.Context, targetBase, remoteID string, session remoteSession, payload map[string]int) error {
	value, _, err := a.remoteJSON(ctx, targetBase, http.MethodPut, "/api/v1/admin/accounts/"+remoteID, session, payload)
	if err != nil {
		return err
	}
	_, err = unwrapEnvelope(value, "SUB2API")
	return err
}

func (a *App) createManagedAccount(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		TargetID, ChannelID, Name string
		TargetGroupIDs            []string
		Priority, Concurrency     int
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.TargetID == "" || input.ChannelID == "" || len(input.TargetGroupIDs) == 0 {
		return &apiError{400, "INVALID_INPUT", "请选择目标节点、渠道和目标分组"}
	}
	if len(input.TargetGroupIDs) != 1 {
		return &apiError{400, "ONE_TARGET_GROUP_PER_ACCOUNT", "每个托管账号必须且只能绑定一个目标分组"}
	}
	if input.Priority < 1 {
		input.Priority = 1000
	}
	if input.Concurrency < 1 {
		input.Concurrency = 1000
	}
	if input.Name == "" {
		input.Name = "渠道"
	}
	remoteName := "[托管] " + input.Name
	var sourceBase, encryptedKey, platform, keyModels, targetBase string
	var targetWrite bool
	err := a.db.QueryRowContext(r.Context(), `SELECT s.base_url,k.key_cipher,s.platform,k.models,t.base_url,t.write_enabled FROM channels c JOIN sources s ON s.id=c.source_id JOIN source_keys k ON k.id=c.source_key_id JOIN targets t ON t.id=$2 WHERE c.id=$1 AND k.production_authorized=true`, input.ChannelID, input.TargetID).Scan(&sourceBase, &encryptedKey, &platform, &keyModels, &targetBase, &targetWrite)
	if err == sql.ErrNoRows {
		return &apiError{404, "CHANNEL_NOT_FOUND", "渠道不存在或尚未授权生产使用"}
	}
	if err != nil {
		return err
	}
	if !targetWrite {
		return &apiError{409, "TARGET_WRITE_DISABLED", "目标节点未开启托管写入"}
	}
	frozen, _ := a.settingBool(r.Context(), "emergency_freeze")
	if frozen {
		return &apiError{409, "EMERGENCY_FREEZE", "紧急冻结已开启，禁止远程写入"}
	}
	shadow, _ := a.settingBool(r.Context(), "shadow_mode")
	if shadow {
		return &apiError{409, "SHADOW_MODE", "影子模式下禁止创建生产托管账号"}
	}
	key, err := a.decryptSecret([]byte(encryptedKey))
	if err != nil {
		return err
	}
	models := []string{}
	_ = json.Unmarshal([]byte(keyModels), &models)
	if len(models) == 0 {
		return &apiError{409, "SOURCE_MODELS_UNAVAILABLE", "请先成功探测该渠道以读取模型"}
	}
	groupRemoteIDs := []int{}
	for _, groupID := range input.TargetGroupIDs {
		var remoteID string
		if err := a.db.QueryRowContext(r.Context(), `SELECT remote_id FROM target_groups WHERE id=$1 AND target_id=$2`, groupID, input.TargetID).Scan(&remoteID); err != nil {
			return &apiError{400, "INVALID_TARGET_GROUP_IDS", "目标分组无效"}
		}
		numeric, err := strconv.Atoi(remoteID)
		if err != nil {
			return &apiError{400, "INVALID_TARGET_GROUP_IDS", "目标分组 ID 不兼容"}
		}
		groupRemoteIDs = append(groupRemoteIDs, numeric)
	}
	requestCtx, cancel := timeoutContext(r.Context())
	defer cancel()
	target, _, err := a.targetCredentials(requestCtx, input.TargetID)
	if err != nil {
		return err
	}
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return err
	}
	modelMap := map[string]string{}
	for _, model := range models {
		modelMap[model] = model
	}
	payload := map[string]any{"name": remoteName, "platform": managedPlatform(platform), "type": "apikey", "credentials": map[string]any{"api_key": string(key), "base_url": strings.TrimSuffix(sourceBase, "/") + "/v1", "model_mapping": modelMap, "pool_mode": true, "pool_mode_retry_count": 3, "pool_mode_retry_status_codes": []int{401, 408, 429, 500, 502, 503, 504}}, "group_ids": groupRemoteIDs, "priority": input.Priority, "concurrency": input.Concurrency, "schedulable": false}
	value, _, err := a.remoteJSON(requestCtx, targetBase, http.MethodPost, "/api/v1/admin/accounts", session, payload)
	if err != nil {
		return err
	}
	data, err := unwrapEnvelope(value, "SUB2API")
	if err != nil {
		return err
	}
	record, _ := data.(map[string]any)
	remoteNumber, ok := number(record["id"])
	if !ok {
		return &apiError{502, "SCHEMA_CHANGED", "目标节点未返回账号 ID"}
	}
	remoteID := strconv.Itoa(int(remoteNumber))
	id := uuid.NewString()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO managed_accounts(id,target_id,channel_id,remote_id,remote_name,priority,concurrency,schedulable,ownership_marker,sync_status) VALUES($1,$2,$3,$4,$5,$6,$7,false,$8,'SYNCED')`, id, input.TargetID, input.ChannelID, remoteID, remoteName, input.Priority, input.Concurrency, "channel-manage:"+id)
	if err != nil {
		return err
	}
	for _, groupID := range input.TargetGroupIDs {
		if _, err = tx.ExecContext(r.Context(), `INSERT INTO managed_account_groups(managed_account_id,target_group_id) VALUES($1,$2)`, id, groupID); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "CREATE_REMOTE", "managed_account", id, map[string]any{"remote_id": remoteID, "schedulable": false})
	writeData(w, map[string]any{"id": id, "remoteId": remoteID, "schedulable": false})
	return nil
}

func managedPlatform(sourcePlatform string) string {
	if sourcePlatform == "NEW_API" {
		return "openai"
	}
	return "openai"
}

func (a *App) updateChannelState(w http.ResponseWriter, r *http.Request, id, action string) error {
	switch action {
	case "probe":
		go a.probeChannel(context.Background(), id)
		writeData(w, map[string]any{"id": id, "status": "ACCEPTED"})
		return nil
	case "manual-hold":
		_, err := a.db.ExecContext(r.Context(), `UPDATE channels SET lifecycle_state='MANUAL_HOLD',state_reason='人工暂停',state_changed_at=now() WHERE id=$1`, id)
		if err != nil {
			return err
		}
		a.audit(r.Context(), "MANUAL_HOLD", "channel", id, nil)
		writeData(w, map[string]string{"id": id, "state": "MANUAL_HOLD"})
		return nil
	case "resume-validation":
		_, err := a.db.ExecContext(r.Context(), `UPDATE channels SET lifecycle_state='VALIDATING',state_reason='等待重新验证',consecutive_failures=0,state_changed_at=now() WHERE id=$1`, id)
		if err != nil {
			return err
		}
		go a.probeChannel(context.Background(), id)
		writeData(w, map[string]string{"id": id, "state": "VALIDATING"})
		return nil
	}
	return &apiError{404, "NOT_FOUND", "操作不存在"}
}

func (a *App) dashboard(ctx context.Context) (map[string]any, error) {
	var sources, channels, healthy, managed, events, actions int
	var minMultiplier sql.NullFloat64
	queries := []struct {
		query  string
		target *int
	}{{`SELECT count(*) FROM sources WHERE status='ACTIVE'`, &sources}, {`SELECT count(*) FROM channels`, &channels}, {`SELECT count(*) FROM channels WHERE lifecycle_state='HEALTHY'`, &healthy}, {`SELECT count(*) FROM managed_accounts`, &managed}, {`SELECT count(*) FROM events WHERE status<>'RESOLVED'`, &events}, {`SELECT count(*) FROM action_intents WHERE status='PENDING'`, &actions}}
	for _, item := range queries {
		if err := a.db.QueryRowContext(ctx, item.query).Scan(item.target); err != nil {
			return nil, err
		}
	}
	_ = a.db.QueryRowContext(ctx, `SELECT min(multiplier) FROM source_groups WHERE captured_at>now()-interval '1 day'`).Scan(&minMultiplier)
	shadow, _ := a.settingBool(ctx, "shadow_mode")
	freeze, _ := a.settingBool(ctx, "emergency_freeze")
	return map[string]any{"sources": sources, "channels": channels, "healthyChannels": healthy, "managedAccounts": managed, "openEvents": events, "pendingActions": actions, "minimumMultiplier": nullableFloat(minMultiplier), "shadowMode": shadow, "emergencyFreeze": freeze, "version": Version}, nil
}

func (a *App) marketGroups(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT g.id,s.name,g.name,g.group_type,g.multiplier,g.captured_at FROM source_groups g JOIN sources s ON s.id=g.source_id ORDER BY g.multiplier NULLS LAST,s.name,g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, source, name, groupType string
		var multiplier sql.NullFloat64
		var captured time.Time
		if err := rows.Scan(&id, &source, &name, &groupType, &multiplier, &captured); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "sourceName": source, "name": name, "groupType": groupType, "multiplier": nullableFloat(multiplier), "capturedAt": captured})
	}
	return items, rows.Err()
}

func (a *App) marketHistory(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT gs.group_id,s.name,g.name,gs.multiplier,gs.captured_at FROM group_samples gs JOIN source_groups g ON g.id=gs.group_id JOIN sources s ON s.id=gs.source_id WHERE gs.captured_at>now()-interval '30 days' ORDER BY gs.captured_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, source, name string
		var multiplier sql.NullFloat64
		var captured time.Time
		if err := rows.Scan(&id, &source, &name, &multiplier, &captured); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"groupId": id, "sourceName": source, "name": name, "multiplier": nullableFloat(multiplier), "capturedAt": captured})
	}
	return items, rows.Err()
}

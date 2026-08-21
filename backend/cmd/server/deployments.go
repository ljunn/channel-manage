package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

type sourceDeploymentRequest struct {
	TargetID       string   `json:"targetID"`
	SourceGroupIDs []string `json:"sourceGroupIDs"`
	TargetGroupIDs []string `json:"targetGroupIDs"`
	Priority       int      `json:"priority"`
	Concurrency    int      `json:"concurrency"`
}

type deploymentSourceGroup struct {
	ID, RemoteID, Name string
	Multiplier         float64
}

type deploymentTargetGroup struct {
	ID, Name, Platform string
	RemoteID           int
	DisabledModels     []string
}

type generatedRemoteKey struct {
	ID, Name, Key string
}

type createdDeployment struct {
	SourceGroup deploymentSourceGroup
	Key         generatedRemoteKey
	Models      []string
	Accounts    []createdRemoteAccount
}

type createdRemoteAccount struct {
	RemoteID    string
	RemoteName  string
	TargetGroup deploymentTargetGroup
}

func normalizeDeploymentRequest(input *sourceDeploymentRequest) error {
	if input.TargetID == "" || len(input.SourceGroupIDs) == 0 || len(input.TargetGroupIDs) == 0 {
		return &apiError{400, "INVALID_INPUT", "请选择源分组、目标节点和目标分组"}
	}
	if len(input.SourceGroupIDs) > 50 {
		return &apiError{400, "TOO_MANY_GROUPS", "每次最多映射 50 个源分组"}
	}
	if len(input.SourceGroupIDs)*len(input.TargetGroupIDs) > 100 {
		return &apiError{400, "TOO_MANY_MAPPINGS", "每次最多创建 100 个独立托管账号"}
	}
	if input.Priority < 1 {
		input.Priority = 1000
	}
	if input.Concurrency < 1 {
		input.Concurrency = 1000
	}
	return nil
}

func (a *App) deploySourceGroups(w http.ResponseWriter, r *http.Request, sourceID string) error {
	a.mappingMu.RLock()
	defer a.mappingMu.RUnlock()
	var input sourceDeploymentRequest
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if err := normalizeDeploymentRequest(&input); err != nil {
		return err
	}
	if len(input.SourceGroupIDs) == 1 {
		unlockGroup := a.lockSourceGroupMapping(sourceID, input.SourceGroupIDs[0])
		defer unlockGroup()
	}
	frozen, _ := a.settingBool(r.Context(), "emergency_freeze")
	if frozen {
		return &apiError{409, "EMERGENCY_FREEZE", "紧急冻结已开启，禁止远程写入"}
	}
	shadow, _ := a.settingBool(r.Context(), "shadow_mode")
	if shadow {
		return &apiError{409, "SHADOW_MODE", "请先在系统设置中关闭影子模式，再创建托管账号"}
	}
	if _, _, err := a.sourceCredentials(r.Context(), sourceID); err != nil {
		return err
	}
	var sourceStatus, scanStatus, sourceError string
	var manuallyUntrusted bool
	if err := a.db.QueryRowContext(r.Context(), `SELECT status,scan_status,last_error,manually_untrusted FROM sources WHERE id=$1`, sourceID).Scan(&sourceStatus, &scanStatus, &sourceError, &manuallyUntrusted); err != nil {
		return err
	}
	if sourceStatus != "ACTIVE" {
		return &apiError{409, "SOURCE_DELETING", "该数据源正在删除，不能创建新的托管账号"}
	}
	if manuallyUntrusted {
		return &apiError{409, "SOURCE_UNTRUSTED", "该数据源已被人工标记为不可信，不能创建新的托管账号"}
	}
	if scanStatus == "AUTH_REQUIRED" {
		return &apiError{409, "SOURCE_AUTH_ACTION_REQUIRED", sourceError}
	}
	target, _, err := a.targetCredentials(r.Context(), input.TargetID)
	if err != nil {
		return err
	}
	if !target.WriteEnabled {
		return &apiError{409, "TARGET_WRITE_DISABLED", "目标节点未开启托管写入"}
	}
	if _, err = a.validateDeploymentSourceGroups(r.Context(), sourceID, input.TargetID, input.SourceGroupIDs); err != nil {
		return err
	}
	if _, err = a.validateDeploymentTargetGroups(r.Context(), input.TargetID, input.TargetGroupIDs); err != nil {
		return err
	}

	jobID := uuid.NewString()
	var sourceGroupID any
	if len(input.SourceGroupIDs) == 1 {
		sourceGroupID = input.SourceGroupIDs[0]
	}
	result, err := a.db.ExecContext(r.Context(), `INSERT INTO deployment_jobs(id,source_id,target_id,source_group_id,request,progress_total)
		SELECT $1,$2,$3,$4,$5,$6 FROM sources WHERE id=$2 AND status='ACTIVE'`, jobID, sourceID, input.TargetID, sourceGroupID, jsonValue(input), len(input.SourceGroupIDs))
	if err != nil {
		if strings.Contains(err.Error(), "idx_deployment_jobs_active_group") || strings.Contains(err.Error(), "duplicate key") {
			return &apiError{409, "DEPLOYMENT_ALREADY_RUNNING", "该源分组已有后台创建任务，请等待完成后再提交"}
		}
		return err
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
		return affectedErr
	} else if affected == 0 {
		return &apiError{409, "SOURCE_DELETING", "该数据源正在删除，不能创建新的托管账号"}
	}
	operator, _ := r.Context().Value(userContextKey).(Operator)
	go a.runDeploymentJob(jobID, sourceID, input, operator)
	writeData(w, map[string]any{"jobId": jobID, "status": "QUEUED", "progressDone": 0, "progressTotal": len(input.SourceGroupIDs)})
	return nil
}

func (a *App) runDeploymentJob(jobID, sourceID string, input sourceDeploymentRequest, operator Operator) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if operator.ID != "" {
		ctx = context.WithValue(ctx, userContextKey, operator)
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE deployment_jobs SET status='RUNNING',started_at=now() WHERE id=$1 AND status='QUEUED'`, jobID)
	result, err := a.executeSourceDeployment(ctx, sourceID, input, func(done, total int) {
		_, _ = a.db.ExecContext(context.Background(), `UPDATE deployment_jobs SET progress_done=$2,progress_total=$3 WHERE id=$1`, jobID, done, total)
	})
	if err != nil {
		message := truncate(userErrorMessage(err), 500)
		_, _ = a.db.ExecContext(context.Background(), `UPDATE deployment_jobs SET status='FAILED',error=$2,finished_at=now() WHERE id=$1`, jobID, message)
		a.audit(ctx, "AUTO_DEPLOY_FAILED", "deployment_job", jobID, map[string]any{"source_id": sourceID, "error": message})
		return
	}
	_, _ = a.db.ExecContext(context.Background(), `UPDATE deployment_jobs SET status='COMPLETED',progress_done=progress_total,result=$2,finished_at=now() WHERE id=$1`, jobID, jsonValue(result))
	a.audit(ctx, "AUTO_DEPLOY_COMPLETED", "deployment_job", jobID, map[string]any{"source_id": sourceID, "created": result["created"]})
}

func (a *App) listDeploymentJobs(w http.ResponseWriter, r *http.Request, sourceID string) error {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,target_id,COALESCE(source_group_id::text,''),status,progress_done,progress_total,result,error,created_at,started_at,finished_at FROM deployment_jobs WHERE source_id=$1 ORDER BY created_at DESC LIMIT 20`, sourceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, targetID, sourceGroupID, status, result, jobError string
		var done, total int
		var created time.Time
		var started, finished sql.NullTime
		if err = rows.Scan(&id, &targetID, &sourceGroupID, &status, &done, &total, &result, &jobError, &created, &started, &finished); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "targetId": targetID, "sourceGroupId": sourceGroupID, "status": status, "progressDone": done, "progressTotal": total, "result": json.RawMessage(result), "error": jobError, "createdAt": created, "startedAt": nullableTime(started), "finishedAt": nullableTime(finished)})
	}
	writeData(w, items)
	return rows.Err()
}

func (a *App) executeSourceDeployment(ctx context.Context, sourceID string, input sourceDeploymentRequest, progress func(int, int)) (map[string]any, error) {
	if err := normalizeDeploymentRequest(&input); err != nil {
		return nil, err
	}

	source, sourceCredential, err := a.sourceCredentials(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	if source.Status != "ACTIVE" {
		return nil, &apiError{409, "SOURCE_DELETING", "该数据源正在删除，不能创建新的托管账号"}
	}
	target, _, err := a.targetCredentials(ctx, input.TargetID)
	if err != nil {
		return nil, err
	}
	if !target.WriteEnabled {
		return nil, &apiError{409, "TARGET_WRITE_DISABLED", "目标节点未开启托管写入"}
	}

	sourceGroups, err := a.validateDeploymentSourceGroups(ctx, sourceID, input.TargetID, input.SourceGroupIDs)
	if err != nil {
		return nil, err
	}
	targetGroups, err := a.validateDeploymentTargetGroups(ctx, input.TargetID, input.TargetGroupIDs)
	if err != nil {
		return nil, err
	}

	operationCount := len(sourceGroups) + len(sourceGroups)*len(targetGroups)
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(operationCount+1)*30*time.Second)
	defer cancel()
	sourceSession, err := a.authenticateSource(requestCtx, source, sourceCredential, true)
	if err != nil {
		return nil, sourceAuthenticationActionError(source, err)
	}
	targetSession, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return nil, err
	}
	sourceAPIBase, err := a.discoverSourceAPIBaseURL(requestCtx, source)
	if err != nil {
		return nil, deploymentError("SOURCE_API_ENDPOINT_READ_FAILED", source.Name, err)
	}

	created := make([]createdDeployment, 0, len(sourceGroups))
	committed := false
	defer func() {
		if committed {
			return
		}
		rollback := append([]createdDeployment(nil), created...)
		go a.rollbackDeployment(rollback, source.BaseURL, source.Platform, sourceSession, target.BaseURL, targetSession)
	}()

	for _, group := range sourceGroups {
		keyName := managedObjectName(source.Name, group.Name, uuid.NewString()[:8])
		remoteKey, createErr := a.createGeneratedRemoteKey(requestCtx, source.BaseURL, source.Platform, sourceSession, group.RemoteID, keyName)
		if createErr != nil {
			return nil, deploymentError("UPSTREAM_KEY_CREATE_FAILED", group.Name, createErr)
		}
		item := createdDeployment{SourceGroup: group, Key: remoteKey}
		created = append(created, item)
		models, modelErr := a.readModelsWithKey(requestCtx, sourceAPIBase, remoteKey.Key)
		if modelErr != nil {
			return nil, deploymentError("UPSTREAM_MODEL_READ_FAILED", group.Name, modelErr)
		}
		if len(models) == 0 {
			return nil, &apiError{409, "SOURCE_MODELS_UNAVAILABLE", group.Name + " 未返回可用模型"}
		}
		accounts, accountErr := a.createRemoteManagedAccounts(requestCtx, target.BaseURL, targetSession, sourceAPIBase, source.Name, group.Name, remoteKey.Key, models, targetGroups, group.Multiplier, input.Priority, input.Concurrency)
		created[len(created)-1].Models = models
		created[len(created)-1].Accounts = accounts
		if accountErr != nil {
			return nil, deploymentError("TARGET_ACCOUNT_CREATE_FAILED", group.Name, accountErr)
		}
		if progress != nil {
			progress(len(created), len(sourceGroups))
		}
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result := make([]map[string]any, 0, len(sourceGroups)*len(targetGroups))
	for _, item := range created {
		keyID := uuid.NewString()
		encryptedKey, encryptErr := a.encryptSecret([]byte(item.Key.Key))
		if encryptErr != nil {
			return nil, encryptErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO source_keys(id,source_id,name,key_cipher,key_hint,production_authorized,concurrency,models,remote_id,auto_generated) VALUES($1,$2,$3,$4,$5,true,$6,$7,$8,true)`, keyID, sourceID, item.Key.Name, encryptedKey, mask(item.Key.Key), input.Concurrency, jsonValue(item.Models), item.Key.ID)
		if err != nil {
			return nil, err
		}
		channelID := uuid.NewString()
		_, err = tx.ExecContext(ctx, `INSERT INTO channels(id,source_id,source_key_id,source_group_id,lifecycle_state,state_reason,score,last_probe_at) VALUES($1,$2,$3,$4,'HEALTHY','自动映射已完成模型验证',100,now())`, channelID, sourceID, keyID, item.SourceGroup.ID)
		if err != nil {
			return nil, err
		}
		for _, account := range item.Accounts {
			managedID := uuid.NewString()
			mappingHash := managedAccountConfigHash(account.TargetGroup.Platform, modelMappingForPolicy(account.TargetGroup.Platform, item.Models, account.TargetGroup.DisabledModels))
			_, err = tx.ExecContext(ctx, `INSERT INTO managed_accounts(id,target_id,channel_id,remote_id,remote_name,platform,priority,concurrency,rate_multiplier,schedulable,ownership_marker,sync_status,model_mapping_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,false,$10,'SYNCED',$11)`, managedID, input.TargetID, channelID, account.RemoteID, account.RemoteName, account.TargetGroup.Platform, input.Priority, input.Concurrency, item.SourceGroup.Multiplier, "channel-manage:"+managedID, mappingHash)
			if err != nil {
				return nil, err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO managed_account_groups(managed_account_id,target_group_id) VALUES($1,$2)`, managedID, account.TargetGroup.ID); err != nil {
				return nil, err
			}
			result = append(result, map[string]any{"sourceGroupId": item.SourceGroup.ID, "sourceGroupName": item.SourceGroup.Name, "targetGroupId": account.TargetGroup.ID, "targetGroupName": account.TargetGroup.Name, "managedAccountId": managedID, "remoteAccountId": account.RemoteID})
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	committed = true
	for _, item := range result {
		a.audit(ctx, "AUTO_DEPLOY", "managed_account", item["managedAccountId"].(string), map[string]any{"source_id": sourceID, "source_group_id": item["sourceGroupId"], "target_id": input.TargetID, "target_group_id": item["targetGroupId"]})
	}
	return map[string]any{"created": len(result), "sourceKeysCreated": len(created), "items": result, "schedulable": false}, nil
}

func (a *App) rollbackDeployment(created []createdDeployment, sourceBase, sourcePlatform string, sourceSession remoteSession, targetBase string, targetSession remoteSession) {
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cleanupCancel()
	for index := len(created) - 1; index >= 0; index-- {
		for accountIndex := len(created[index].Accounts) - 1; accountIndex >= 0; accountIndex-- {
			a.deleteRemoteManagedAccount(cleanupCtx, targetBase, targetSession, created[index].Accounts[accountIndex].RemoteID)
		}
		a.deleteGeneratedRemoteKey(cleanupCtx, sourceBase, sourcePlatform, sourceSession, created[index].Key.ID)
	}
	log.Printf("自动绑定回滚完成: %d 个源分组", len(created))
}

func (a *App) validateDeploymentSourceGroups(ctx context.Context, sourceID, targetID string, ids []string) ([]deploymentSourceGroup, error) {
	seen := map[string]bool{}
	groups := make([]deploymentSourceGroup, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			return nil, &apiError{400, "INVALID_SOURCE_GROUP_IDS", "源分组选择无效"}
		}
		seen[id] = true
		var group deploymentSourceGroup
		var multiplier sql.NullFloat64
		err := a.db.QueryRowContext(ctx, `SELECT id,remote_id,name,multiplier FROM source_groups WHERE id=$1 AND source_id=$2`, id, sourceID).Scan(&group.ID, &group.RemoteID, &group.Name, &multiplier)
		if err == sql.ErrNoRows {
			return nil, &apiError{400, "INVALID_SOURCE_GROUP_IDS", "源分组不存在或不属于该数据源"}
		}
		if err != nil {
			return nil, err
		}
		if !multiplier.Valid || multiplier.Float64 < 0 {
			return nil, &apiError{409, "SOURCE_MULTIPLIER_UNAVAILABLE", group.Name + " 尚未获取有效倍率，请先重新扫描数据源"}
		}
		group.Multiplier = multiplier.Float64
		var existing int
		if err = a.db.QueryRowContext(ctx, `SELECT count(*) FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE m.target_id=$1 AND c.source_group_id=$2`, targetID, id).Scan(&existing); err != nil {
			return nil, err
		}
		if existing > 0 {
			return nil, &apiError{409, "GROUP_ALREADY_DEPLOYED", group.Name + " 已映射到该目标节点"}
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (a *App) validateDeploymentTargetGroups(ctx context.Context, targetID string, ids []string) ([]deploymentTargetGroup, error) {
	seen := map[string]bool{}
	groups := make([]deploymentTargetGroup, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			return nil, &apiError{400, "INVALID_TARGET_GROUP_IDS", "目标分组选择无效"}
		}
		seen[id] = true
		var group deploymentTargetGroup
		var remoteID, configData string
		if err := a.db.QueryRowContext(ctx, `SELECT tg.id,tg.remote_id,tg.name,tg.platform,COALESCE((
			SELECT v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version
			WHERE p.scope_type='TARGET_GROUP' AND p.scope_id=tg.id AND p.status='ACTIVE' LIMIT 1
		),'{}'::jsonb) FROM target_groups tg WHERE tg.id=$1 AND tg.target_id=$2`, id, targetID).Scan(&group.ID, &remoteID, &group.Name, &group.Platform, &configData); err != nil {
			return nil, &apiError{400, "INVALID_TARGET_GROUP_IDS", "目标分组不存在或不属于该节点"}
		}
		var config policyConfig
		_ = json.Unmarshal([]byte(configData), &config)
		group.DisabledModels = normalizePolicyConfig(config).DisabledModels
		numeric, err := strconv.Atoi(remoteID)
		if err != nil {
			return nil, &apiError{400, "INVALID_TARGET_GROUP_IDS", "目标分组 ID 不兼容"}
		}
		group.RemoteID = numeric
		group.Platform = managedPlatform(group.Platform)
		groups = append(groups, group)
	}
	return groups, nil
}

func (a *App) createGeneratedRemoteKey(ctx context.Context, baseURL, platform string, session remoteSession, groupRemoteID, name string) (generatedRemoteKey, error) {
	if platform == "SUB2API" {
		groupID, err := strconv.ParseInt(groupRemoteID, 10, 64)
		if err != nil {
			return generatedRemoteKey{}, &apiError{400, "SOURCE_GROUP_ID_INCOMPATIBLE", "Sub2API 分组 ID 不兼容"}
		}
		value, _, err := a.remoteJSON(ctx, baseURL, http.MethodPost, "/api/v1/keys", session, map[string]any{"name": name, "group_id": groupID})
		if err != nil {
			return generatedRemoteKey{}, err
		}
		data, err := unwrapEnvelope(value, platform)
		if err != nil {
			return generatedRemoteKey{}, err
		}
		record, _ := data.(map[string]any)
		id, idOK := number(record["id"])
		key := text(record["key"], "")
		if !idOK || key == "" {
			return generatedRemoteKey{}, &apiError{502, "SCHEMA_CHANGED", "Sub2API 创建 Key 的响应不兼容"}
		}
		return generatedRemoteKey{ID: strconv.Itoa(int(id)), Name: name, Key: key}, nil
	}

	payload := map[string]any{"name": name, "remain_quota": 0, "expired_time": -1, "unlimited_quota": true, "model_limits_enabled": false, "model_limits": "", "allow_ips": "", "group": groupRemoteID, "cross_group_retry": false}
	value, _, err := a.remoteJSON(ctx, baseURL, http.MethodPost, "/api/token/", session, payload)
	if err != nil {
		return generatedRemoteKey{}, err
	}
	if _, err = unwrapEnvelope(value, platform); err != nil {
		return generatedRemoteKey{}, err
	}
	searchPath := "/api/token/search?keyword=" + url.QueryEscape(name) + "&p=1&size=100"
	value, _, err = a.remoteJSON(ctx, baseURL, http.MethodGet, searchPath, session, nil)
	if err != nil {
		return generatedRemoteKey{}, err
	}
	data, err := unwrapEnvelope(value, platform)
	if err != nil {
		return generatedRemoteKey{}, err
	}
	var tokenID int
	for _, record := range pageRecords(data) {
		if text(record["name"], "") != name {
			continue
		}
		if id, ok := number(record["id"]); ok && int(id) > tokenID {
			tokenID = int(id)
		}
	}
	if tokenID == 0 {
		return generatedRemoteKey{}, &apiError{502, "SCHEMA_CHANGED", "New API 创建后未返回令牌 ID"}
	}
	value, _, err = a.remoteJSON(ctx, baseURL, http.MethodPost, fmt.Sprintf("/api/token/%d/key", tokenID), session, nil)
	if err != nil {
		return generatedRemoteKey{}, err
	}
	data, err = unwrapEnvelope(value, platform)
	if err != nil {
		return generatedRemoteKey{}, err
	}
	record, _ := data.(map[string]any)
	key := text(record["key"], "")
	if key == "" {
		return generatedRemoteKey{}, &apiError{502, "SCHEMA_CHANGED", "New API 未返回完整令牌"}
	}
	return generatedRemoteKey{ID: strconv.Itoa(tokenID), Name: name, Key: key}, nil
}

func pageRecords(value any) []map[string]any {
	if page, ok := value.(map[string]any); ok {
		value = page["items"]
	}
	items, _ := value.([]any)
	records := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if record, ok := item.(map[string]any); ok {
			records = append(records, record)
		}
	}
	return records
}

func (a *App) readModelsWithKey(ctx context.Context, baseURL, key string) ([]string, error) {
	value, _, err := a.remoteJSON(ctx, accountBaseURL(baseURL, "openai"), http.MethodGet, "/models", remoteSession{Authorization: "Bearer " + key}, nil)
	if err != nil {
		return nil, err
	}
	record, _ := value.(map[string]any)
	items, _ := record["data"].([]any)
	models := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		model, _ := item.(map[string]any)
		id := text(model["id"], "")
		if id != "" && !seen[id] {
			seen[id] = true
			models = append(models, id)
		}
	}
	sort.Strings(models)
	return models, nil
}

func accountBaseURL(sourceBase, targetPlatform string) string {
	base := strings.TrimRight(strings.TrimSpace(sourceBase), "/")
	endsInV1 := strings.HasSuffix(strings.ToLower(base), "/v1")
	switch managedPlatform(targetPlatform) {
	case "anthropic", "gemini":
		if endsInV1 {
			return base[:len(base)-len("/v1")]
		}
		return base
	default:
		if endsInV1 {
			return base
		}
		return base + "/v1"
	}
}

func (a *App) discoverSourceAPIBaseURL(ctx context.Context, source Source) (string, error) {
	if source.Platform != "SUB2API" {
		return source.BaseURL, nil
	}
	value, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/v1/settings/public", remoteSession{}, nil)
	if err != nil {
		if remoteRouteUnavailable(err) {
			return source.BaseURL, nil
		}
		return "", err
	}
	data, err := unwrapEnvelope(value, source.Platform)
	if err != nil {
		return "", err
	}
	record, _ := data.(map[string]any)
	publishedBase := strings.TrimSpace(text(record["api_base_url"], ""))
	if publishedBase == "" {
		return source.BaseURL, nil
	}
	normalized, err := validateRemoteURL(publishedBase)
	if err != nil {
		return "", &apiError{Status: http.StatusUnprocessableEntity, Code: "SOURCE_API_ENDPOINT_INVALID", Message: "源站发布的 API 地址无效：" + publishedBase}
	}
	return normalized, nil
}

func (a *App) createRemoteManagedAccount(ctx context.Context, targetBase string, targetSession remoteSession, sourceBase, targetPlatform, key string, models, disabledModels []string, targetGroupIDs []int, name string, rateMultiplier float64, priority, concurrency int) (string, error) {
	return a.createRemoteManagedAccountIdempotent(ctx, targetBase, targetSession, sourceBase, targetPlatform, key, models, disabledModels, targetGroupIDs, name, rateMultiplier, priority, concurrency, "")
}

func (a *App) createRemoteManagedAccountIdempotent(ctx context.Context, targetBase string, targetSession remoteSession, sourceBase, targetPlatform, key string, models, disabledModels []string, targetGroupIDs []int, name string, rateMultiplier float64, priority, concurrency int, idempotencyKey string) (string, error) {
	modelMap := modelMappingForPolicy(targetPlatform, models, disabledModels)
	return a.createRemoteManagedAccountWithMappingIdempotent(ctx, targetBase, targetSession, sourceBase, targetPlatform, key, modelMap, targetGroupIDs, name, rateMultiplier, priority, concurrency, idempotencyKey)
}

func (a *App) createRemoteManagedAccountWithMappingIdempotent(ctx context.Context, targetBase string, targetSession remoteSession, sourceBase, targetPlatform, key string, modelMap map[string]string, targetGroupIDs []int, name string, rateMultiplier float64, priority, concurrency int, idempotencyKey string) (string, error) {
	if len(modelMap) == 0 {
		return "", &apiError{409, "NO_ALLOWED_MODELS", "账号没有可复用的模型映射"}
	}
	payload := map[string]any{"name": name, "platform": managedPlatform(targetPlatform), "type": "apikey", "credentials": map[string]any{"api_key": key, "base_url": accountBaseURL(sourceBase, targetPlatform), "model_mapping": modelMap, "pool_mode": true, "pool_mode_retry_count": 3, "pool_mode_retry_status_codes": []int{401, 408, 429, 500, 502, 503, 504}}, "group_ids": targetGroupIDs, "rate_multiplier": rateMultiplier, "priority": priority, "concurrency": concurrency, "schedulable": false}
	createSession := targetSession
	createSession.IdempotencyKey = idempotencyKey
	value, _, err := a.remoteJSON(ctx, targetBase, http.MethodPost, "/api/v1/admin/accounts", createSession, payload)
	if err != nil {
		return "", err
	}
	data, err := unwrapEnvelope(value, "SUB2API")
	if err != nil {
		return "", err
	}
	record, _ := data.(map[string]any)
	remoteID, ok := number(record["id"])
	if !ok {
		return "", &apiError{502, "SCHEMA_CHANGED", "目标节点未返回账号 ID"}
	}
	remoteIDText := strconv.Itoa(int(remoteID))
	if err = a.syncTargetAccountSchedulable(ctx, targetBase, remoteIDText, targetSession, false); err != nil {
		a.deleteRemoteManagedAccount(context.Background(), targetBase, targetSession, remoteIDText)
		return "", fmt.Errorf("初始化托管账号停止状态失败: %w", err)
	}
	return remoteIDText, nil
}

func (a *App) createRemoteManagedAccounts(ctx context.Context, targetBase string, targetSession remoteSession, sourceBase, sourceName, sourceGroupName, key string, models []string, targetGroups []deploymentTargetGroup, rateMultiplier float64, priority, concurrency int) ([]createdRemoteAccount, error) {
	type accountResult struct {
		index   int
		account createdRemoteAccount
		err     error
	}
	results := make(chan accountResult, len(targetGroups))
	workers := 6
	if len(targetGroups) < workers {
		workers = len(targetGroups)
	}
	jobs := make(chan int)
	for worker := 0; worker < workers; worker++ {
		go func() {
			for index := range jobs {
				targetGroup := targetGroups[index]
				remoteName := managedAccountName(sourceName, sourceGroupName, targetGroup.Name, targetGroup.RemoteID)
				remoteID, err := a.createRemoteManagedAccount(ctx, targetBase, targetSession, sourceBase, targetGroup.Platform, key, models, targetGroup.DisabledModels, []int{targetGroup.RemoteID}, remoteName, rateMultiplier, priority, concurrency)
				results <- accountResult{index: index, account: createdRemoteAccount{RemoteID: remoteID, RemoteName: remoteName, TargetGroup: targetGroup}, err: err}
			}
		}()
	}
	go func() {
		for index := range targetGroups {
			jobs <- index
		}
		close(jobs)
	}()

	ordered := make([]accountResult, len(targetGroups))
	for range targetGroups {
		result := <-results
		ordered[result.index] = result
	}
	accounts := make([]createdRemoteAccount, 0, len(targetGroups))
	var firstErr error
	for index, result := range ordered {
		if result.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("目标分组 %s：%w", targetGroups[index].Name, result.err)
			}
			continue
		}
		accounts = append(accounts, result.account)
	}
	return accounts, firstErr
}

func (a *App) deleteGeneratedRemoteKey(ctx context.Context, baseURL, platform string, session remoteSession, id string) {
	if id == "" {
		return
	}
	path := "/api/v1/keys/" + id
	if platform == "NEW_API" {
		path = "/api/token/" + id
	}
	_, _, _ = a.remoteJSON(ctx, baseURL, http.MethodDelete, path, session, nil)
}

func (a *App) deleteRemoteManagedAccount(ctx context.Context, baseURL string, session remoteSession, id string) {
	_, _, _ = a.remoteJSON(ctx, baseURL, http.MethodDelete, "/api/v1/admin/accounts/"+id, session, nil)
}

func managedObjectName(sourceName, groupName, suffix string) string {
	prefix := "渠道管家-" + strings.TrimSpace(sourceName) + "-" + strings.TrimSpace(groupName)
	tail := "-" + strings.TrimSpace(suffix)
	if len(prefix)+len(tail) <= 50 {
		return prefix + tail
	}
	return truncateUTF8Bytes(prefix, 50-len(tail)) + tail
}

func truncateUTF8Bytes(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	end := 0
	for index, char := range value {
		size := utf8.RuneLen(char)
		if index+size > maxBytes {
			break
		}
		end = index + size
	}
	return value[:end]
}

func managedAccountName(sourceName, sourceGroupName, targetGroupName string, targetGroupRemoteID int) string {
	suffix := fmt.Sprintf(" / %s #%d", strings.TrimSpace(targetGroupName), targetGroupRemoteID)
	prefix := "[托管] " + strings.TrimSpace(sourceName) + " / " + strings.TrimSpace(sourceGroupName)
	value := prefix + suffix
	runes := []rune(value)
	if len(runes) <= 80 {
		return value
	}
	suffixRunes := []rune(suffix)
	if len(suffixRunes) >= 80 {
		return string(suffixRunes[:80])
	}
	return string([]rune(prefix)[:80-len(suffixRunes)]) + suffix
}

func deploymentError(code, groupName string, err error) error {
	log.Printf("自动绑定失败 [%s] %s: %v", code, groupName, err)
	if apiErr, ok := err.(*apiError); ok {
		message := apiErr.Message
		status := apiErr.Status
		upperMessage := strings.ToUpper(message)
		if strings.Contains(upperMessage, "TOKEN NAME IS TOO LONG") {
			status = http.StatusUnprocessableEntity
			message = "源站拒绝创建专用 Key：名称超过 50 字节限制"
		} else if strings.Contains(upperMessage, "API ENDPOINT IS NOT SERVED FROM THE PANEL DOMAIN") {
			status = http.StatusUnprocessableEntity
			message = "源站面板域名不提供 API，且未能读取有效的发布 API 地址"
		} else if insufficientBalanceError(apiErr) {
			status = http.StatusConflict
			message = "源站账户余额不足，无法验证新建专用 Key 的可用模型"
		}
		return &apiError{Status: status, Code: code, Message: groupName + "：" + message}
	}
	return &apiError{Status: 502, Code: code, Message: groupName + "：" + err.Error()}
}

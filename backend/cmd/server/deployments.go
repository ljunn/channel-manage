package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

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
}

type deploymentTargetGroup struct {
	ID, Name string
	RemoteID int
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

func (a *App) deploySourceGroups(w http.ResponseWriter, r *http.Request, sourceID string) error {
	var input sourceDeploymentRequest
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.TargetID == "" || len(input.SourceGroupIDs) == 0 || len(input.TargetGroupIDs) == 0 {
		return &apiError{400, "INVALID_INPUT", "请选择源分组、目标节点和目标分组"}
	}
	if len(input.SourceGroupIDs) > 50 {
		return &apiError{400, "TOO_MANY_GROUPS", "每次最多映射 50 个源分组"}
	}
	if len(input.SourceGroupIDs)*len(input.TargetGroupIDs) > 100 {
		return &apiError{400, "TOO_MANY_MAPPINGS", "每次最多创建 100 个独立托管账号"}
	}
	if input.Priority < 101 {
		input.Priority = 101
	}
	if input.Concurrency < 1 {
		input.Concurrency = 1
	}
	frozen, _ := a.settingBool(r.Context(), "emergency_freeze")
	if frozen {
		return &apiError{409, "EMERGENCY_FREEZE", "紧急冻结已开启，禁止远程写入"}
	}
	shadow, _ := a.settingBool(r.Context(), "shadow_mode")
	if shadow {
		return &apiError{409, "SHADOW_MODE", "请先在系统设置中关闭影子模式，再创建托管账号"}
	}

	source, sourceCredential, err := a.sourceCredentials(r.Context(), sourceID)
	if err != nil {
		return err
	}
	target, _, err := a.targetCredentials(r.Context(), input.TargetID)
	if err != nil {
		return err
	}
	if !target.WriteEnabled {
		return &apiError{409, "TARGET_WRITE_DISABLED", "目标节点未开启托管写入"}
	}

	sourceGroups, err := a.validateDeploymentSourceGroups(r.Context(), sourceID, input.TargetID, input.SourceGroupIDs)
	if err != nil {
		return err
	}
	targetGroups, err := a.validateDeploymentTargetGroups(r.Context(), input.TargetID, input.TargetGroupIDs)
	if err != nil {
		return err
	}

	operationCount := len(sourceGroups) + len(sourceGroups)*len(targetGroups)
	requestCtx, cancel := context.WithTimeout(r.Context(), time.Duration(operationCount+1)*30*time.Second)
	defer cancel()
	sourceSession, err := a.authenticateSource(requestCtx, source, sourceCredential, true)
	if err != nil {
		return err
	}
	targetSession, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return err
	}

	created := make([]createdDeployment, 0, len(sourceGroups))
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		for index := len(created) - 1; index >= 0; index-- {
			for accountIndex := len(created[index].Accounts) - 1; accountIndex >= 0; accountIndex-- {
				a.deleteRemoteManagedAccount(cleanupCtx, target.BaseURL, targetSession, created[index].Accounts[accountIndex].RemoteID)
			}
			a.deleteGeneratedRemoteKey(cleanupCtx, source.BaseURL, source.Platform, sourceSession, created[index].Key.ID)
		}
	}()

	for _, group := range sourceGroups {
		keyName := managedObjectName(source.Name, group.Name, uuid.NewString()[:8])
		remoteKey, createErr := a.createGeneratedRemoteKey(requestCtx, source.BaseURL, source.Platform, sourceSession, group.RemoteID, keyName)
		if createErr != nil {
			return deploymentError("UPSTREAM_KEY_CREATE_FAILED", group.Name, createErr)
		}
		item := createdDeployment{SourceGroup: group, Key: remoteKey}
		created = append(created, item)
		models, modelErr := a.readModelsWithKey(requestCtx, source.BaseURL, remoteKey.Key)
		if modelErr != nil {
			return deploymentError("UPSTREAM_MODEL_READ_FAILED", group.Name, modelErr)
		}
		if len(models) == 0 {
			return &apiError{409, "SOURCE_MODELS_UNAVAILABLE", group.Name + " 未返回可用模型"}
		}
		accounts, accountErr := a.createRemoteManagedAccounts(requestCtx, target.BaseURL, targetSession, source.BaseURL, source.Platform, source.Name, group.Name, remoteKey.Key, models, targetGroups, input.Priority, input.Concurrency)
		created[len(created)-1].Models = models
		created[len(created)-1].Accounts = accounts
		if accountErr != nil {
			return deploymentError("TARGET_ACCOUNT_CREATE_FAILED", group.Name, accountErr)
		}
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result := make([]map[string]any, 0, len(sourceGroups)*len(targetGroups))
	for _, item := range created {
		keyID := uuid.NewString()
		encryptedKey, encryptErr := a.encryptSecret([]byte(item.Key.Key))
		if encryptErr != nil {
			return encryptErr
		}
		_, err = tx.ExecContext(r.Context(), `INSERT INTO source_keys(id,source_id,name,key_cipher,key_hint,production_authorized,concurrency,models,remote_id,auto_generated) VALUES($1,$2,$3,$4,$5,true,$6,$7,$8,true)`, keyID, sourceID, item.Key.Name, encryptedKey, mask(item.Key.Key), input.Concurrency, jsonValue(item.Models), item.Key.ID)
		if err != nil {
			return err
		}
		channelID := uuid.NewString()
		_, err = tx.ExecContext(r.Context(), `INSERT INTO channels(id,source_id,source_key_id,source_group_id,lifecycle_state,state_reason,score,last_probe_at) VALUES($1,$2,$3,$4,'HEALTHY','自动映射已完成模型验证',100,now())`, channelID, sourceID, keyID, item.SourceGroup.ID)
		if err != nil {
			return err
		}
		for _, account := range item.Accounts {
			managedID := uuid.NewString()
			_, err = tx.ExecContext(r.Context(), `INSERT INTO managed_accounts(id,target_id,channel_id,remote_id,remote_name,priority,concurrency,schedulable,ownership_marker,sync_status) VALUES($1,$2,$3,$4,$5,$6,$7,false,$8,'SYNCED')`, managedID, input.TargetID, channelID, account.RemoteID, account.RemoteName, input.Priority, input.Concurrency, "channel-manage:"+managedID)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(r.Context(), `INSERT INTO managed_account_groups(managed_account_id,target_group_id) VALUES($1,$2)`, managedID, account.TargetGroup.ID); err != nil {
				return err
			}
			result = append(result, map[string]any{"sourceGroupId": item.SourceGroup.ID, "sourceGroupName": item.SourceGroup.Name, "targetGroupId": account.TargetGroup.ID, "targetGroupName": account.TargetGroup.Name, "managedAccountId": managedID, "remoteAccountId": account.RemoteID})
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	committed = true
	for _, item := range result {
		a.audit(r.Context(), "AUTO_DEPLOY", "managed_account", item["managedAccountId"].(string), map[string]any{"source_id": sourceID, "source_group_id": item["sourceGroupId"], "target_id": input.TargetID, "target_group_id": item["targetGroupId"]})
	}
	writeData(w, map[string]any{"created": len(result), "sourceKeysCreated": len(created), "items": result, "schedulable": false})
	return nil
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
		err := a.db.QueryRowContext(ctx, `SELECT id,remote_id,name FROM source_groups WHERE id=$1 AND source_id=$2`, id, sourceID).Scan(&group.ID, &group.RemoteID, &group.Name)
		if err == sql.ErrNoRows {
			return nil, &apiError{400, "INVALID_SOURCE_GROUP_IDS", "源分组不存在或不属于该数据源"}
		}
		if err != nil {
			return nil, err
		}
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
		var remoteID string
		if err := a.db.QueryRowContext(ctx, `SELECT id,remote_id,name FROM target_groups WHERE id=$1 AND target_id=$2`, id, targetID).Scan(&group.ID, &remoteID, &group.Name); err != nil {
			return nil, &apiError{400, "INVALID_TARGET_GROUP_IDS", "目标分组不存在或不属于该节点"}
		}
		numeric, err := strconv.Atoi(remoteID)
		if err != nil {
			return nil, &apiError{400, "INVALID_TARGET_GROUP_IDS", "目标分组 ID 不兼容"}
		}
		group.RemoteID = numeric
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
	value, _, err := a.remoteJSON(ctx, baseURL, http.MethodGet, "/v1/models", remoteSession{Authorization: "Bearer " + key}, nil)
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

func (a *App) createRemoteManagedAccount(ctx context.Context, targetBase string, targetSession remoteSession, sourceBase, sourcePlatform, key string, models []string, targetGroupIDs []int, name string, priority, concurrency int) (string, error) {
	modelMap := map[string]string{}
	for _, model := range models {
		modelMap[model] = model
	}
	payload := map[string]any{"name": name, "platform": managedPlatform(sourcePlatform), "type": "apikey", "credentials": map[string]any{"api_key": key, "base_url": strings.TrimSuffix(sourceBase, "/") + "/v1", "model_mapping": modelMap, "pool_mode": true, "pool_mode_retry_count": 3, "pool_mode_retry_status_codes": []int{401, 408, 429, 500, 502, 503, 504}}, "group_ids": targetGroupIDs, "priority": priority, "concurrency": concurrency, "schedulable": false}
	value, _, err := a.remoteJSON(ctx, targetBase, http.MethodPost, "/api/v1/admin/accounts", targetSession, payload)
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
	return strconv.Itoa(int(remoteID)), nil
}

func (a *App) createRemoteManagedAccounts(ctx context.Context, targetBase string, targetSession remoteSession, sourceBase, sourcePlatform, sourceName, sourceGroupName, key string, models []string, targetGroups []deploymentTargetGroup, priority, concurrency int) ([]createdRemoteAccount, error) {
	accounts := make([]createdRemoteAccount, 0, len(targetGroups))
	for _, targetGroup := range targetGroups {
		remoteName := managedAccountName(sourceName, sourceGroupName, targetGroup.Name, targetGroup.RemoteID)
		remoteID, err := a.createRemoteManagedAccount(ctx, targetBase, targetSession, sourceBase, sourcePlatform, key, models, []int{targetGroup.RemoteID}, remoteName, priority, concurrency)
		if err != nil {
			return accounts, fmt.Errorf("目标分组 %s：%w", targetGroup.Name, err)
		}
		accounts = append(accounts, createdRemoteAccount{RemoteID: remoteID, RemoteName: remoteName, TargetGroup: targetGroup})
	}
	return accounts, nil
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
	value := "渠道管家-" + strings.TrimSpace(sourceName) + "-" + strings.TrimSpace(groupName) + "-" + suffix
	runes := []rune(value)
	if len(runes) > 50 {
		value = string(runes[:50])
	}
	return value
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
	if apiErr, ok := err.(*apiError); ok {
		return &apiError{Status: apiErr.Status, Code: code, Message: groupName + "：" + apiErr.Message}
	}
	return &apiError{Status: 502, Code: code, Message: groupName + "：" + err.Error()}
}

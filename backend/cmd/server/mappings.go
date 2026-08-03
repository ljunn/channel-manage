package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type sourceGroupMappingRequest struct {
	TargetID       string   `json:"targetID"`
	TargetGroupIDs []string `json:"targetGroupIDs"`
}

type existingMappingAccount struct {
	ID, RemoteID, RemoteName string
	TargetGroup              deploymentTargetGroup
	Priority, Concurrency    int
	Schedulable              bool
}

type mappingChannel struct {
	ID, SourceGroupName, ModelsJSON string
	EncryptedKey                    []byte
}

func mappingDifference(current []existingMappingAccount, desired []deploymentTargetGroup) (kept []existingMappingAccount, removed []existingMappingAccount, added []deploymentTargetGroup) {
	desiredByID := make(map[string]deploymentTargetGroup, len(desired))
	for _, group := range desired {
		desiredByID[group.ID] = group
	}
	currentByID := make(map[string]existingMappingAccount, len(current))
	for _, account := range current {
		currentByID[account.TargetGroup.ID] = account
		if _, ok := desiredByID[account.TargetGroup.ID]; ok {
			kept = append(kept, account)
		} else {
			removed = append(removed, account)
		}
	}
	for _, group := range desired {
		if _, ok := currentByID[group.ID]; !ok {
			added = append(added, group)
		}
	}
	return
}

func (a *App) updateSourceGroupMapping(w http.ResponseWriter, r *http.Request, sourceID, sourceGroupID string) error {
	var input sourceGroupMappingRequest
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.TargetID == "" || len(input.TargetGroupIDs) > 100 {
		return &apiError{400, "INVALID_INPUT", "请选择目标节点，目标分组最多 100 个"}
	}
	frozen, _ := a.settingBool(r.Context(), "emergency_freeze")
	if frozen {
		return &apiError{409, "EMERGENCY_FREEZE", "紧急冻结已开启，禁止远程写入"}
	}
	shadow, _ := a.settingBool(r.Context(), "shadow_mode")
	if shadow {
		return &apiError{409, "SHADOW_MODE", "请先在系统设置中关闭影子模式，再修改绑定"}
	}

	a.mappingMu.Lock()
	defer a.mappingMu.Unlock()
	a.recoveryMu.Lock()
	defer a.recoveryMu.Unlock()

	var activeJobs int
	if err := a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM deployment_jobs WHERE source_id=$1 AND status IN ('QUEUED','RUNNING')`, sourceID).Scan(&activeJobs); err != nil {
		return err
	}
	if activeJobs > 0 {
		return &apiError{409, "DEPLOYMENT_ALREADY_RUNNING", "该数据源正在创建绑定，请等待完成后再修改"}
	}

	source, _, err := a.sourceCredentials(r.Context(), sourceID)
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
	desiredGroups, err := a.validateDeploymentTargetGroups(r.Context(), input.TargetID, input.TargetGroupIDs)
	if err != nil {
		return err
	}

	channel, current, err := a.loadSourceGroupMapping(r.Context(), sourceID, sourceGroupID, input.TargetID)
	if err != nil {
		return err
	}
	if len(current) == 0 {
		return &apiError{409, "MAPPING_NOT_CREATED", "该源分组尚未绑定，请使用保存创建首次绑定"}
	}
	kept, removed, added := mappingDifference(current, desiredGroups)
	if len(removed) == 0 && len(added) == 0 {
		writeData(w, map[string]any{"created": 0, "removed": 0, "kept": len(kept), "changed": false})
		return nil
	}

	key, err := a.decryptSecret(channel.EncryptedKey)
	if err != nil {
		return fmt.Errorf("读取托管 Key 失败: %w", err)
	}
	models := []string{}
	if err = json.Unmarshal([]byte(channel.ModelsJSON), &models); err != nil || len(models) == 0 {
		return &apiError{409, "SOURCE_MODELS_UNAVAILABLE", "源分组没有可用于更新绑定的模型列表"}
	}
	sourceAPIBase, err := a.discoverSourceAPIBaseURL(r.Context(), source)
	if err != nil {
		return deploymentError("SOURCE_API_ENDPOINT_READ_FAILED", channel.SourceGroupName, err)
	}
	targetSession, err := a.authenticateTarget(r.Context(), target, true)
	if err != nil {
		return err
	}
	priority, concurrency := current[0].Priority, current[0].Concurrency
	created, err := a.createRemoteManagedAccounts(r.Context(), target.BaseURL, targetSession, sourceAPIBase, source.Name, channel.SourceGroupName, string(key), models, added, priority, concurrency)
	if err != nil {
		for _, account := range created {
			a.deleteRemoteManagedAccount(context.Background(), target.BaseURL, targetSession, account.RemoteID)
		}
		return deploymentError("TARGET_ACCOUNT_CREATE_FAILED", channel.SourceGroupName, err)
	}

	for _, account := range removed {
		if err = a.syncTargetAccountSchedulable(r.Context(), target.BaseURL, account.RemoteID, targetSession, false); err != nil {
			a.cleanupNewMappingAccounts(target, targetSession, created)
			a.restoreMappingScheduling(target, targetSession, removed)
			return &apiError{502, "TARGET_ACCOUNT_DISABLE_FAILED", "停用待移除账号失败，原绑定已保留：" + userErrorMessage(err)}
		}
	}

	deleted := make([]existingMappingAccount, 0, len(removed))
	for _, account := range removed {
		if err = a.deleteRemoteManagedAccountChecked(r.Context(), target.BaseURL, targetSession, account.RemoteID); err != nil {
			rollbackErr := a.restoreDeletedMappingAccounts(r.Context(), target, targetSession, sourceAPIBase, string(key), models, deleted)
			a.cleanupNewMappingAccounts(target, targetSession, created)
			a.restoreMappingScheduling(target, targetSession, removed[len(deleted):])
			if rollbackErr != nil {
				a.reportMappingRollbackFailure(source, sourceGroupID, input.TargetID, channel.SourceGroupName, rollbackErr)
				return &apiError{500, "MAPPING_ROLLBACK_FAILED", "删除失败且远端回滚未完全成功，已生成高优先级事件"}
			}
			return &apiError{502, "TARGET_ACCOUNT_DELETE_FAILED", "删除待移除账号失败，已恢复原绑定，请重试：" + userErrorMessage(err)}
		}
		deleted = append(deleted, account)
	}

	if err = a.commitSourceGroupMapping(r.Context(), input.TargetID, channel, models, created, removed, priority, concurrency); err != nil {
		rollbackErr := a.restoreDeletedMappingAccounts(r.Context(), target, targetSession, sourceAPIBase, string(key), models, deleted)
		a.cleanupNewMappingAccounts(target, targetSession, created)
		if rollbackErr != nil {
			a.reportMappingRollbackFailure(source, sourceGroupID, input.TargetID, channel.SourceGroupName, rollbackErr)
			return &apiError{500, "MAPPING_ROLLBACK_FAILED", "保存失败且远端回滚未完全成功，已生成高优先级事件"}
		}
		return err
	}

	a.audit(r.Context(), "UPDATE_SOURCE_GROUP_MAPPING", "source_group", sourceGroupID, map[string]any{"target_id": input.TargetID, "created": len(created), "removed": len(removed), "kept": len(kept), "target_group_ids": input.TargetGroupIDs})
	a.resolveEvent(r.Context(), "mapping-sync:"+sourceGroupID+":"+input.TargetID)
	go a.runPolicyEvaluation(context.Background())
	writeData(w, map[string]any{"created": len(created), "removed": len(removed), "kept": len(kept), "changed": true})
	return nil
}

func (a *App) loadSourceGroupMapping(ctx context.Context, sourceID, sourceGroupID, targetID string) (mappingChannel, []existingMappingAccount, error) {
	var channel mappingChannel
	err := a.db.QueryRowContext(ctx, `SELECT c.id,sg.name,k.key_cipher,k.models FROM channels c JOIN source_groups sg ON sg.id=c.source_group_id JOIN source_keys k ON k.id=c.source_key_id WHERE c.source_id=$1 AND c.source_group_id=$2 AND EXISTS(SELECT 1 FROM managed_accounts m WHERE m.channel_id=c.id AND m.target_id=$3) ORDER BY k.auto_generated DESC,c.created_at LIMIT 1`, sourceID, sourceGroupID, targetID).Scan(&channel.ID, &channel.SourceGroupName, &channel.EncryptedKey, &channel.ModelsJSON)
	if err == sql.ErrNoRows {
		var name string
		if groupErr := a.db.QueryRowContext(ctx, `SELECT name FROM source_groups WHERE id=$1 AND source_id=$2`, sourceGroupID, sourceID).Scan(&name); groupErr == sql.ErrNoRows {
			return channel, nil, &apiError{404, "SOURCE_GROUP_NOT_FOUND", "源分组不存在"}
		} else if groupErr != nil {
			return channel, nil, groupErr
		}
		channel.SourceGroupName = name
		return channel, nil, nil
	}
	if err != nil {
		return channel, nil, err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.remote_id,m.remote_name,m.priority,m.concurrency,m.schedulable,tg.id,tg.name,tg.platform,tg.remote_id,COALESCE((
		SELECT v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version
		WHERE p.scope_type='TARGET_GROUP' AND p.scope_id=tg.id AND p.status='ACTIVE' LIMIT 1
	),'{}'::jsonb) FROM managed_accounts m JOIN managed_account_groups mag ON mag.managed_account_id=m.id JOIN target_groups tg ON tg.id=mag.target_group_id JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1 AND c.source_group_id=$2 AND m.target_id=$3 ORDER BY tg.name`, sourceID, sourceGroupID, targetID)
	if err != nil {
		return channel, nil, err
	}
	defer rows.Close()
	items := []existingMappingAccount{}
	seen := map[string]bool{}
	seenAccounts := map[string]bool{}
	for rows.Next() {
		var item existingMappingAccount
		var remoteGroupID, configData string
		if err = rows.Scan(&item.ID, &item.RemoteID, &item.RemoteName, &item.Priority, &item.Concurrency, &item.Schedulable, &item.TargetGroup.ID, &item.TargetGroup.Name, &item.TargetGroup.Platform, &remoteGroupID, &configData); err != nil {
			return channel, nil, err
		}
		var config policyConfig
		_ = json.Unmarshal([]byte(configData), &config)
		item.TargetGroup.DisabledModels = normalizePolicyConfig(config).DisabledModels
		if seen[item.TargetGroup.ID] || seenAccounts[item.ID] {
			return channel, nil, &apiError{409, "MAPPING_DATA_CONFLICT", "同一源分组重复绑定了目标分组，请先处理数据冲突"}
		}
		seen[item.TargetGroup.ID] = true
		seenAccounts[item.ID] = true
		if item.TargetGroup.RemoteID, err = strconv.Atoi(remoteGroupID); err != nil {
			return channel, nil, &apiError{409, "MAPPING_DATA_CONFLICT", "目标分组 ID 不兼容"}
		}
		item.TargetGroup.Platform = managedPlatform(item.TargetGroup.Platform)
		items = append(items, item)
	}
	return channel, items, rows.Err()
}

func (a *App) commitSourceGroupMapping(ctx context.Context, targetID string, channel mappingChannel, models []string, created []createdRemoteAccount, removed []existingMappingAccount, priority, concurrency int) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, account := range created {
		managedID := uuid.NewString()
		mappingHash := managedAccountConfigHash(account.TargetGroup.Platform, modelMappingForPolicy(account.TargetGroup.Platform, models, account.TargetGroup.DisabledModels))
		if _, err = tx.ExecContext(ctx, `INSERT INTO managed_accounts(id,target_id,channel_id,remote_id,remote_name,platform,priority,concurrency,schedulable,ownership_marker,sync_status,model_mapping_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,false,$9,'SYNCED',$10)`, managedID, targetID, channel.ID, account.RemoteID, account.RemoteName, account.TargetGroup.Platform, priority, concurrency, "channel-manage:"+managedID, mappingHash); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO managed_account_groups(managed_account_id,target_group_id) VALUES($1,$2)`, managedID, account.TargetGroup.ID); err != nil {
			return err
		}
	}
	for _, account := range removed {
		if _, err = tx.ExecContext(ctx, `UPDATE action_intents SET status='REJECTED',error='绑定已移除' WHERE managed_account_id=$1 AND status IN ('PENDING','APPROVED')`, account.ID); err != nil {
			return err
		}
		result, deleteErr := tx.ExecContext(ctx, `DELETE FROM managed_accounts WHERE id=$1`, account.ID)
		if deleteErr != nil {
			return deleteErr
		}
		affected, affectedErr := result.RowsAffected()
		if affectedErr != nil || affected != 1 {
			return &apiError{409, "MAPPING_CHANGED", "绑定数据已变化，请刷新后重试"}
		}
	}
	return tx.Commit()
}

func (a *App) deleteRemoteManagedAccountChecked(ctx context.Context, baseURL string, session remoteSession, id string) error {
	if id == "" {
		return nil
	}
	_, _, err := a.remoteJSON(ctx, baseURL, http.MethodDelete, "/api/v1/admin/accounts/"+id, session, nil)
	if err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Code == "REMOTE_NOT_FOUND" {
			return nil
		}
	}
	return err
}

func (a *App) cleanupNewMappingAccounts(target Target, session remoteSession, accounts []createdRemoteAccount) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, account := range accounts {
		_ = a.deleteRemoteManagedAccountChecked(ctx, target.BaseURL, session, account.RemoteID)
	}
}

func (a *App) restoreMappingScheduling(target Target, session remoteSession, accounts []existingMappingAccount) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, account := range accounts {
		if account.Schedulable {
			_ = a.syncTargetAccountSchedulable(ctx, target.BaseURL, account.RemoteID, session, true)
		}
	}
}

func (a *App) restoreDeletedMappingAccounts(ctx context.Context, target Target, session remoteSession, sourceAPIBase, key string, models []string, accounts []existingMappingAccount) error {
	var failures []string
	for _, account := range accounts {
		remoteID, err := a.createRemoteManagedAccount(ctx, target.BaseURL, session, sourceAPIBase, account.TargetGroup.Platform, key, models, account.TargetGroup.DisabledModels, []int{account.TargetGroup.RemoteID}, account.RemoteName, account.Priority, account.Concurrency)
		if err != nil {
			failures = append(failures, account.TargetGroup.Name+": "+userErrorMessage(err))
			continue
		}
		if account.Schedulable {
			if err = a.syncTargetAccountSchedulable(ctx, target.BaseURL, remoteID, session, true); err != nil {
				failures = append(failures, account.TargetGroup.Name+": 恢复调度失败")
			}
		}
		if _, err = a.db.ExecContext(ctx, `UPDATE managed_accounts SET remote_id=$2,platform=$3,model_mapping_hash=$4,sync_status='SYNCED',last_error='',updated_at=now() WHERE id=$1`, account.ID, remoteID, account.TargetGroup.Platform, managedAccountConfigHash(account.TargetGroup.Platform, modelMappingForPolicy(account.TargetGroup.Platform, models, account.TargetGroup.DisabledModels))); err != nil {
			failures = append(failures, account.TargetGroup.Name+": 保存恢复账号失败")
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return errors.New(fmt.Sprint(failures))
	}
	return nil
}

func (a *App) reportMappingRollbackFailure(source Source, sourceGroupID, targetID, groupName string, err error) {
	detail := source.Name + " / " + groupName + "：" + err.Error()
	log.Printf("绑定更新回滚失败: %s", detail)
	a.openEvent(context.Background(), "P0", "ACTION_EXECUTION", "绑定更新回滚未完成", detail, "mapping-sync:"+sourceGroupID+":"+targetID)
}

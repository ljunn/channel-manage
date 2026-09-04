package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Target struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	BaseURL      string     `json:"baseUrl"`
	KeyHint      string     `json:"usernameHint"`
	Status       string     `json:"status"`
	Version      string     `json:"version"`
	WriteEnabled bool       `json:"writeEnabled"`
	LastSyncAt   *time.Time `json:"lastSyncAt"`
	LastError    string     `json:"lastError"`
	GroupCount   int        `json:"groupCount"`
	ManagedCount int        `json:"managedCount"`
	CreatedAt    time.Time  `json:"createdAt"`
}

func (a *App) listTargets(ctx context.Context) ([]Target, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT t.id,t.name,t.base_url,t.key_hint,t.status,t.version,t.write_enabled,t.last_sync_at,t.last_error,t.created_at,(SELECT count(*) FROM target_groups g WHERE g.target_id=t.id),(SELECT count(*) FROM managed_accounts m WHERE m.target_id=t.id) FROM targets t ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Target{}
	for rows.Next() {
		var item Target
		var lastSync sql.NullTime
		if err := rows.Scan(&item.ID, &item.Name, &item.BaseURL, &item.KeyHint, &item.Status, &item.Version, &item.WriteEnabled, &lastSync, &item.LastError, &item.CreatedAt, &item.GroupCount, &item.ManagedCount); err != nil {
			return nil, err
		}
		if lastSync.Valid {
			item.LastSyncAt = &lastSync.Time
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (a *App) createTarget(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Name, BaseURL, Username, Password string
		WriteEnabled                      bool
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Name == "" || input.Username == "" || input.Password == "" {
		return &apiError{400, "INVALID_INPUT", "请填写节点名称和管理员凭据"}
	}
	baseURL, err := validateRemoteURL(input.BaseURL)
	if err != nil {
		return err
	}
	encrypted, err := a.encryptSecret([]byte(jsonValue(sourceCredentials{AuthMode: "PASSWORD", Username: input.Username, Password: input.Password})))
	if err != nil {
		return err
	}
	id := uuid.NewString()
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO targets(id,name,base_url,api_key_cipher,key_hint,write_enabled) VALUES($1,$2,$3,$4,$5,$6)`, id, input.Name, baseURL, encrypted, mask(input.Username), input.WriteEnabled)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return &apiError{409, "TARGET_ALREADY_EXISTS", "该目标节点已添加"}
		}
		return err
	}
	a.audit(r.Context(), "CREATE", "target", id, map[string]any{"name": input.Name, "base_url": baseURL, "write_enabled": input.WriteEnabled})
	go a.syncTarget(context.Background(), id)
	writeData(w, map[string]any{"id": id, "status": "ACCEPTED"})
	return nil
}

func (a *App) targetCredentials(ctx context.Context, id string) (Target, sourceCredentials, error) {
	var target Target
	var encrypted []byte
	err := a.db.QueryRowContext(ctx, `SELECT id,name,base_url,api_key_cipher,key_hint,status,version,write_enabled FROM targets WHERE id=$1`, id).Scan(&target.ID, &target.Name, &target.BaseURL, &encrypted, &target.KeyHint, &target.Status, &target.Version, &target.WriteEnabled)
	if err == sql.ErrNoRows {
		return target, sourceCredentials{}, &apiError{404, "TARGET_NOT_FOUND", "目标节点不存在"}
	}
	if err != nil {
		return target, sourceCredentials{}, err
	}
	plain, err := a.decryptSecret(encrypted)
	if err != nil {
		return target, sourceCredentials{}, err
	}
	var credential sourceCredentials
	if json.Unmarshal(plain, &credential) != nil {
		return target, credential, fmt.Errorf("invalid target credentials")
	}
	return target, credential, nil
}

func (a *App) syncTarget(ctx context.Context, id string) error {
	assetLock := a.targetAssetLock(id)
	assetLock.Lock()
	defer assetLock.Unlock()

	target, _, err := a.targetCredentials(ctx, id)
	if err != nil {
		return err
	}
	requestCtx, cancel := timeoutContext(ctx)
	defer cancel()
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		a.targetSyncFailed(ctx, target, err)
		return err
	}
	version, groups, err := a.fetchTargetAssets(requestCtx, target.BaseURL, session)
	if err != nil {
		a.targetSyncFailed(ctx, target, err)
		return err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, record := range groups {
		idNumber, ok := number(record["id"])
		if !ok {
			continue
		}
		remoteID := strconv.Itoa(int(idNumber))
		multiplier := sub2APIGroupMultiplier(record, nil, remoteID)
		platform := managedPlatform(text(record["platform"], "openai"))
		models := targetGroupProbeModels(record, platform)
		_, err = tx.ExecContext(ctx, `INSERT INTO target_groups(target_id,remote_id,name,platform,multiplier,multiplier_captured_at,models,updated_at) VALUES($1,$2,$3,$4,$5,now(),$6,now()) ON CONFLICT(target_id,remote_id) DO UPDATE SET name=excluded.name,platform=excluded.platform,multiplier=excluded.multiplier,multiplier_captured_at=now(),models=excluded.models,updated_at=now()`, id, remoteID, text(record["name"], remoteID), platform, multiplier, jsonValue(models))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE targets SET status='ONLINE',version=$2,last_sync_at=now(),last_error='',updated_at=now() WHERE id=$1`, id, version)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if err = a.ensureTargetProbeModels(ctx, id); err != nil {
		return err
	}
	a.resolveEvent(ctx, "target-sync:"+id)
	a.resolveEvent(ctx, "target-rate-limit:"+id)
	go func() {
		platformCtx, platformCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer platformCancel()
		a.syncManagedAccountSchedulableStates(platformCtx, target, session)
		a.syncManagedAccountPlatforms(platformCtx, target, session)
		a.syncManagedAccountRateMultipliers(platformCtx, target, session)
		a.syncManagedAccountModelMappings(platformCtx, target, session)
	}()
	return nil
}

func (a *App) targetAssetLock(targetID string) *sync.Mutex {
	if value, ok := a.targetAssetLocks.Load(targetID); ok {
		return value.(*sync.Mutex)
	}
	created := &sync.Mutex{}
	actual, _ := a.targetAssetLocks.LoadOrStore(targetID, created)
	return actual.(*sync.Mutex)
}

func (a *App) reconcileDynamicTargetGroupMultiplier(ctx context.Context, policyID, targetGroupID string, quote dynamicMultiplierQuote) error {
	var targetID string
	if err := a.db.QueryRowContext(ctx, `SELECT target_id FROM target_groups WHERE id=$1`, targetGroupID).Scan(&targetID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &apiError{404, "TARGET_GROUP_NOT_FOUND", "动态倍率对应的目标分组不存在"}
		}
		return err
	}
	assetLock := a.targetAssetLock(targetID)
	assetLock.Lock()
	defer assetLock.Unlock()

	var remoteID, groupName string
	var current sql.NullFloat64
	if err := a.db.QueryRowContext(ctx, `SELECT remote_id,name,multiplier FROM target_groups WHERE id=$1 AND target_id=$2`, targetGroupID, targetID).Scan(&remoteID, &groupName, &current); err != nil {
		return err
	}
	if current.Valid && !rateMultiplierNeedsSync(current.Float64, true, quote.Desired) {
		return nil
	}
	target, _, err := a.targetCredentials(ctx, targetID)
	if err != nil {
		return err
	}
	if !target.WriteEnabled {
		return &apiError{409, "TARGET_WRITE_DISABLED", "目标节点未开启托管写入，无法同步动态倍率"}
	}
	requestCtx, cancel := timeoutContext(ctx)
	defer cancel()
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return err
	}
	if err = a.updateRemoteTargetGroupMultiplier(requestCtx, target.BaseURL, remoteID, session, quote.Desired); err != nil {
		return err
	}
	if _, err = a.db.ExecContext(context.Background(), `UPDATE target_groups SET multiplier=$2,multiplier_captured_at=now(),updated_at=now() WHERE id=$1`, targetGroupID, quote.Desired); err != nil {
		return err
	}
	a.audit(context.Background(), "SYNC_DYNAMIC_MULTIPLIER", "target_group", targetGroupID, map[string]any{
		"policy_id": policyID, "remote_id": remoteID, "group": groupName,
		"source_group": quote.SourceGroup, "lowest": quote.Lowest,
		"before": nullableFloat(current), "desired": quote.Desired,
	})
	return nil
}

func (a *App) updateRemoteTargetGroupMultiplier(ctx context.Context, baseURL, remoteID string, session remoteSession, multiplier float64) error {
	value, _, err := a.remoteJSON(ctx, baseURL, http.MethodPut, "/api/v1/admin/groups/"+url.PathEscape(remoteID), session, map[string]any{"rate_multiplier": multiplier})
	if err != nil {
		return err
	}
	_, err = unwrapEnvelope(value, "SUB2API")
	return err
}

func (a *App) syncPolicyModelMappings(ctx context.Context, targetGroupID string) {
	var targetID string
	if err := a.db.QueryRowContext(ctx, `SELECT target_id FROM target_groups WHERE id=$1`, targetGroupID).Scan(&targetID); err != nil {
		log.Printf("读取策略目标分组失败 [%s]: %v", targetGroupID, err)
		return
	}
	requestCtx, cancel := timeoutContext(ctx)
	defer cancel()
	target, _, err := a.targetCredentials(requestCtx, targetID)
	if err != nil {
		log.Printf("读取策略目标节点失败 [%s]: %v", targetID, err)
		return
	}
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		log.Printf("认证策略目标节点失败 [%s]: %v", targetID, err)
		return
	}
	a.syncManagedAccountModelMappings(requestCtx, target, session)
}

func (a *App) syncManagedAccountSchedulableStates(ctx context.Context, target Target, session remoteSession) {
	if !target.WriteEnabled {
		return
	}
	a.targetSchedulableMu.Lock()
	if a.targetSchedulableSyncs == nil {
		a.targetSchedulableSyncs = make(map[string]struct{})
	}
	if _, running := a.targetSchedulableSyncs[target.ID]; running {
		a.targetSchedulableMu.Unlock()
		return
	}
	a.targetSchedulableSyncs[target.ID] = struct{}{}
	a.targetSchedulableMu.Unlock()
	defer func() {
		a.targetSchedulableMu.Lock()
		delete(a.targetSchedulableSyncs, target.ID)
		a.targetSchedulableMu.Unlock()
	}()

	type managedState struct {
		id, remoteID, remoteName string
		schedulable              bool
	}
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.remote_id,m.remote_name,m.schedulable
		FROM managed_accounts m
		WHERE m.target_id=$1 AND m.remote_id<>'' AND m.ownership_marker LIKE 'channel-manage:%'
		AND NOT EXISTS(SELECT 1 FROM action_intents i WHERE i.managed_account_id=m.id AND i.action_type IN ('SET_SCHEDULABLE','ROTATE_FALLBACK','RECREATE_FALLBACK') AND i.status IN ('PENDING','APPROVED'))`, target.ID)
	if err != nil {
		log.Printf("读取托管账号启停状态失败 [%s]: %v", target.ID, err)
		return
	}
	local := map[string]managedState{}
	for rows.Next() {
		var item managedState
		if err = rows.Scan(&item.id, &item.remoteID, &item.remoteName, &item.schedulable); err != nil {
			break
		}
		local[item.remoteID] = item
	}
	_ = rows.Close()
	if err != nil || len(local) == 0 {
		return
	}

	accounts, err := a.fetchPaged(ctx, target.BaseURL, "/api/v1/admin/accounts?search="+url.QueryEscape("[托管]"), session)
	if err != nil {
		log.Printf("读取远端托管账号启停状态失败 [%s]: %v", target.ID, err)
		return
	}
	remote := map[string]bool{}
	for _, account := range accounts {
		id, ok := number(account["id"])
		if !ok {
			continue
		}
		remoteID := strconv.Itoa(int(id))
		if _, managed := local[remoteID]; !managed {
			continue
		}
		if schedulable, ok := account["schedulable"].(bool); ok {
			remote[remoteID] = schedulable
		}
	}

	failed := 0
	corrected := 0
	for remoteID, item := range local {
		actual, found := remote[remoteID]
		if !found || actual == item.schedulable {
			continue
		}
		if err = a.syncTargetAccountSchedulable(ctx, target.BaseURL, remoteID, session, item.schedulable); err != nil {
			failed++
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET sync_status='FAILED',last_error=$2,updated_at=now() WHERE id=$1`, item.id, truncate("远端调度状态校正失败: "+err.Error(), 500))
			continue
		}
		corrected++
		_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET sync_status='SYNCED',last_error='',updated_at=now() WHERE id=$1`, item.id)
		a.audit(context.Background(), "RECONCILE_SCHEDULABLE", "managed_account", item.id, map[string]any{"remote_id": remoteID, "remote_before": actual, "desired": item.schedulable})
	}
	if corrected > 0 {
		log.Printf("已校正目标节点 %s 的远端托管账号启停漂移: %d 个", target.Name, corrected)
	}
	if failed > 0 {
		detail := fmt.Sprintf("%s 有 %d 个本系统托管账号的远端启停状态与策略不一致，自动校正失败。请检查目标节点写入权限。", target.Name, failed)
		a.openEvent(context.Background(), "P0", "ACTION_EXECUTION", "托管账号远端启停状态校正失败", detail, "target-schedulable-drift:"+target.ID)
	} else {
		a.resolveEvent(context.Background(), "target-schedulable-drift:"+target.ID)
	}
}

func (a *App) syncManagedAccountRateMultipliers(ctx context.Context, target Target, session remoteSession) {
	if !target.WriteEnabled {
		return
	}
	a.targetRateMu.Lock()
	if a.targetRateSyncs == nil {
		a.targetRateSyncs = make(map[string]struct{})
	}
	if _, running := a.targetRateSyncs[target.ID]; running {
		a.targetRateMu.Unlock()
		return
	}
	a.targetRateSyncs[target.ID] = struct{}{}
	a.targetRateMu.Unlock()
	defer func() {
		a.targetRateMu.Lock()
		delete(a.targetRateSyncs, target.ID)
		a.targetRateMu.Unlock()
	}()

	type managedRate struct {
		id, remoteID string
		desired      float64
	}
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.remote_id,sg.multiplier
		FROM managed_accounts m
		JOIN channels c ON c.id=m.channel_id
		JOIN source_groups sg ON sg.id=c.source_group_id
		JOIN sources s ON s.id=c.source_id
		WHERE m.target_id=$1 AND m.remote_id<>'' AND m.ownership_marker LIKE 'channel-manage:%'
		AND s.manually_untrusted=false AND sg.multiplier IS NOT NULL`, target.ID)
	if err != nil {
		log.Printf("读取托管账号倍率失败 [%s]: %v", target.ID, err)
		return
	}
	items := map[string]managedRate{}
	for rows.Next() {
		var item managedRate
		if err = rows.Scan(&item.id, &item.remoteID, &item.desired); err != nil {
			break
		}
		items[item.remoteID] = item
	}
	_ = rows.Close()
	if err != nil || len(items) == 0 {
		return
	}

	accounts, err := a.fetchPaged(ctx, target.BaseURL, "/api/v1/admin/accounts?search="+url.QueryEscape("[托管]"), session)
	if err != nil {
		log.Printf("读取远端托管账号倍率失败 [%s]: %v", target.ID, err)
		detail := target.Name + " 无法读取托管账号倍率，自动校正未执行：" + userErrorMessage(err)
		a.openEvent(context.Background(), "P1", "ACCOUNT_RATE_SYNC", "账号倍率同步失败", detail, "target-rate-sync:"+target.ID)
		return
	}
	actualRates := map[string]float64{}
	for _, account := range accounts {
		id, ok := number(account["id"])
		if !ok {
			continue
		}
		remoteID := strconv.Itoa(int(id))
		if _, managed := items[remoteID]; !managed {
			continue
		}
		if rate, ok := number(account["rate_multiplier"]); ok {
			actualRates[remoteID] = rate
		}
	}

	corrected, failed := 0, 0
	for remoteID, item := range items {
		actual, found := actualRates[remoteID]
		if !rateMultiplierNeedsSync(actual, found, item.desired) {
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET rate_multiplier=$2 WHERE id=$1`, item.id, actual)
			continue
		}
		if err = a.syncTargetAccountFields(ctx, target.BaseURL, remoteID, session, map[string]any{"rate_multiplier": item.desired}); err != nil {
			failed++
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET sync_status='FAILED',last_error=$2,updated_at=now() WHERE id=$1`, item.id, truncate("账号倍率校正失败: "+err.Error(), 500))
			continue
		}
		corrected++
		_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET rate_multiplier=$2,sync_status='SYNCED',last_error='',updated_at=now() WHERE id=$1`, item.id, item.desired)
		a.audit(context.Background(), "RECONCILE_RATE_MULTIPLIER", "managed_account", item.id, map[string]any{"remote_id": remoteID, "remote_before": actual, "remote_value_found": found, "desired": item.desired})
	}
	if corrected > 0 {
		log.Printf("已校正目标节点 %s 的托管账号倍率: %d 个", target.Name, corrected)
	}
	if failed > 0 {
		detail := fmt.Sprintf("%s 有 %d 个托管账号的倍率未能按源分组同步，系统会自动重试。", target.Name, failed)
		a.openEvent(context.Background(), "P1", "ACCOUNT_RATE_SYNC", "账号倍率同步失败", detail, "target-rate-sync:"+target.ID)
	} else {
		a.resolveEvent(context.Background(), "target-rate-sync:"+target.ID)
	}
}

func rateMultiplierNeedsSync(actual float64, found bool, desired float64) bool {
	return !found || math.Abs(actual-desired) > multiplierComparisonTolerance
}

func (a *App) syncSourceManagedAccountRateMultipliers(sourceID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	rows, err := a.db.QueryContext(ctx, `SELECT DISTINCT m.target_id FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1`, sourceID)
	if err != nil {
		return
	}
	var targetIDs []string
	for rows.Next() {
		var targetID string
		if rows.Scan(&targetID) == nil {
			targetIDs = append(targetIDs, targetID)
		}
	}
	_ = rows.Close()
	for _, targetID := range targetIDs {
		target, _, targetErr := a.targetCredentials(ctx, targetID)
		if targetErr != nil || !target.WriteEnabled {
			continue
		}
		session, authErr := a.authenticateTarget(ctx, target, true)
		if authErr != nil {
			continue
		}
		a.syncManagedAccountRateMultipliers(ctx, target, session)
	}
}

func (a *App) syncManagedAccountPlatforms(ctx context.Context, target Target, session remoteSession) {
	if !target.WriteEnabled {
		return
	}
	a.targetPlatformMu.Lock()
	if a.targetPlatformSyncs == nil {
		a.targetPlatformSyncs = make(map[string]struct{})
	}
	if _, running := a.targetPlatformSyncs[target.ID]; running {
		a.targetPlatformMu.Unlock()
		return
	}
	a.targetPlatformSyncs[target.ID] = struct{}{}
	a.targetPlatformMu.Unlock()
	defer func() {
		a.targetPlatformMu.Lock()
		delete(a.targetPlatformSyncs, target.ID)
		a.targetPlatformMu.Unlock()
	}()
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.remote_id,m.remote_name,m.priority,m.concurrency,m.schedulable,
		tg.platform,tg.remote_id,s.id,s.name,s.platform,s.base_url,k.key_cipher,k.models,sg.multiplier,COALESCE((
			SELECT v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version
			WHERE p.scope_type='TARGET_GROUP' AND p.scope_id=tg.id AND p.status='ACTIVE' LIMIT 1
		),'{}'::jsonb)
		FROM managed_accounts m
		JOIN managed_account_groups mg ON mg.managed_account_id=m.id
		JOIN target_groups tg ON tg.id=mg.target_group_id
		JOIN channels c ON c.id=m.channel_id
		JOIN source_groups sg ON sg.id=c.source_group_id
		JOIN sources s ON s.id=c.source_id
		JOIN source_keys k ON k.id=c.source_key_id
		WHERE m.target_id=$1 AND s.manually_untrusted=false AND m.platform<>tg.platform AND m.remote_id<>'' AND sg.multiplier IS NOT NULL`, target.ID)
	if err != nil {
		log.Printf("读取托管账号平台失败 [%s]: %v", target.ID, err)
		return
	}
	type accountPlatform struct {
		id, remoteID, remoteName, platform, targetGroupRemoteID string
		priority, concurrency                                   int
		schedulable                                             bool
		source                                                  Source
		encryptedKey                                            []byte
		modelsJSON                                              string
		rateMultiplier                                          float64
		disabledModels                                          []string
	}
	items := []accountPlatform{}
	for rows.Next() {
		var item accountPlatform
		var configData string
		if err = rows.Scan(&item.id, &item.remoteID, &item.remoteName, &item.priority, &item.concurrency, &item.schedulable,
			&item.platform, &item.targetGroupRemoteID, &item.source.ID, &item.source.Name, &item.source.Platform, &item.source.BaseURL,
			&item.encryptedKey, &item.modelsJSON, &item.rateMultiplier, &configData); err != nil {
			break
		}
		var config policyConfig
		_ = json.Unmarshal([]byte(configData), &config)
		item.disabledModels = normalizePolicyConfig(config).DisabledModels
		item.platform = managedPlatform(item.platform)
		items = append(items, item)
	}
	_ = rows.Close()
	if err != nil {
		log.Printf("读取托管账号平台失败 [%s]: %v", target.ID, err)
		return
	}
	failed := 0
	for _, item := range items {
		if err = a.replaceManagedAccountPlatform(ctx, target, session, item.id, item.remoteID, item.remoteName, item.platform, item.targetGroupRemoteID, item.rateMultiplier, item.priority, item.concurrency, item.schedulable, item.source, item.encryptedKey, item.modelsJSON, item.disabledModels); err != nil {
			failed++
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET sync_status='FAILED',last_error=$2,updated_at=now() WHERE id=$1`, item.id, truncate(err.Error(), 500))
		}
	}
	if failed > 0 {
		detail := fmt.Sprintf("%s 有 %d 个托管账号的平台类型未能按目标分组同步，系统会在下一轮目标同步时重试。", target.Name, failed)
		a.openEvent(context.Background(), "P1", "ACCOUNT_PLATFORM_SYNC", "账号平台同步失败", detail, "target-platform-sync:"+target.ID)
	} else {
		a.resolveEvent(context.Background(), "target-platform-sync:"+target.ID)
	}
}

func (a *App) syncManagedAccountModelMappings(ctx context.Context, target Target, session remoteSession) {
	if !target.WriteEnabled {
		return
	}
	a.targetModelMu.Lock()
	if a.targetModelSyncs == nil {
		a.targetModelSyncs = make(map[string]struct{})
	}
	if _, running := a.targetModelSyncs[target.ID]; running {
		a.targetModelMu.Unlock()
		return
	}
	a.targetModelSyncs[target.ID] = struct{}{}
	a.targetModelMu.Unlock()
	defer func() {
		a.targetModelMu.Lock()
		delete(a.targetModelSyncs, target.ID)
		a.targetModelMu.Unlock()
	}()

	type mappingAccount struct {
		id, remoteID, platform, sourceID, sourceName, sourcePlatform, sourceBase, modelsJSON, currentHash string
		encryptedKey                                                                                      []byte
		disabledModels                                                                                    []string
		mapping                                                                                           map[string]string
		desiredHash                                                                                       string
	}
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.remote_id,tg.platform,s.id,s.name,s.platform,s.base_url,k.models,m.model_mapping_hash,k.key_cipher,COALESCE((
			SELECT v.config FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version
			WHERE p.scope_type='TARGET_GROUP' AND p.scope_id=tg.id AND p.status='ACTIVE' LIMIT 1
		),'{}'::jsonb)
		FROM managed_accounts m
		JOIN managed_account_groups mg ON mg.managed_account_id=m.id
		JOIN target_groups tg ON tg.id=mg.target_group_id
		JOIN channels c ON c.id=m.channel_id
		JOIN sources s ON s.id=c.source_id
		JOIN source_keys k ON k.id=c.source_key_id
		WHERE m.target_id=$1 AND s.manually_untrusted=false AND m.remote_id<>'' AND m.ownership_marker LIKE 'channel-manage:%'`, target.ID)
	if err != nil {
		log.Printf("读取托管账号模型映射失败 [%s]: %v", target.ID, err)
		return
	}
	items := []mappingAccount{}
	for rows.Next() {
		var item mappingAccount
		var configData string
		if err = rows.Scan(&item.id, &item.remoteID, &item.platform, &item.sourceID, &item.sourceName, &item.sourcePlatform, &item.sourceBase, &item.modelsJSON, &item.currentHash, &item.encryptedKey, &configData); err != nil {
			break
		}
		var config policyConfig
		_ = json.Unmarshal([]byte(configData), &config)
		item.disabledModels = normalizePolicyConfig(config).DisabledModels
		item.mapping = modelMappingForPolicy(item.platform, decodeModels(item.modelsJSON), item.disabledModels)
		item.desiredHash = managedAccountConfigHash(item.platform, item.mapping)
		if item.desiredHash == item.currentHash {
			continue
		}
		items = append(items, item)
	}
	_ = rows.Close()
	if err != nil {
		log.Printf("读取托管账号模型映射失败 [%s]: %v", target.ID, err)
		return
	}

	sourceBases := map[string]string{}
	sourceErrors := map[string]error{}
	for _, item := range items {
		if _, known := sourceBases[item.sourceID]; known {
			continue
		}
		if _, failed := sourceErrors[item.sourceID]; failed {
			continue
		}
		base, discoverErr := a.discoverSourceAPIBaseURL(ctx, Source{ID: item.sourceID, Name: item.sourceName, Platform: item.sourcePlatform, BaseURL: item.sourceBase})
		if discoverErr != nil {
			sourceErrors[item.sourceID] = discoverErr
			continue
		}
		sourceBases[item.sourceID] = base
	}

	corrected := 0
	failed := 0
	for _, item := range items {
		if len(item.mapping) == 0 {
			_ = a.syncTargetAccountSchedulable(ctx, target.BaseURL, item.remoteID, session, false)
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET schedulable=false,updated_at=now() WHERE id=$1`, item.id)
		}
		sourceBase, ok := sourceBases[item.sourceID]
		if !ok {
			failed++
			message := "读取源站 API 地址失败"
			if sourceErrors[item.sourceID] != nil {
				message += ": " + sourceErrors[item.sourceID].Error()
			}
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET sync_status='FAILED',last_error=$2,updated_at=now() WHERE id=$1`, item.id, truncate(message, 500))
			continue
		}
		key, decryptErr := a.decryptSecret(item.encryptedKey)
		if decryptErr != nil {
			failed++
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET sync_status='FAILED',last_error='读取托管 Key 失败',updated_at=now() WHERE id=$1`, item.id)
			continue
		}
		credentials := map[string]any{
			"api_key":                      string(key),
			"base_url":                     accountBaseURL(sourceBase, item.platform),
			"model_mapping":                item.mapping,
			"pool_mode":                    true,
			"pool_mode_retry_count":        3,
			"pool_mode_retry_status_codes": []int{401, 408, 429, 500, 502, 503, 504},
		}
		if err = a.syncTargetAccountFields(ctx, target.BaseURL, item.remoteID, session, map[string]any{"credentials": credentials}); err != nil {
			failed++
			_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET sync_status='FAILED',last_error=$2,updated_at=now() WHERE id=$1`, item.id, truncate("模型映射校正失败: "+err.Error(), 500))
			continue
		}
		corrected++
		_, _ = a.db.ExecContext(context.Background(), `UPDATE managed_accounts SET model_mapping_hash=$2,sync_status='SYNCED',last_error='',updated_at=now() WHERE id=$1`, item.id, item.desiredHash)
		a.audit(context.Background(), "RECONCILE_MODEL_MAPPING", "managed_account", item.id, map[string]any{"remote_id": item.remoteID, "platform": item.platform, "models": len(item.mapping)})
	}
	if corrected > 0 {
		log.Printf("已校正目标节点 %s 的托管账号模型族映射: %d 个", target.Name, corrected)
	}
	if failed > 0 {
		detail := fmt.Sprintf("%s 有 %d 个托管账号的模型族映射校正失败，系统会在下一轮目标同步时重试。", target.Name, failed)
		a.openEvent(context.Background(), "P1", "ACCOUNT_MODEL_SYNC", "账号模型映射同步失败", detail, "target-model-sync:"+target.ID)
	} else {
		a.resolveEvent(context.Background(), "target-model-sync:"+target.ID)
	}
}

func (a *App) replaceManagedAccountPlatform(ctx context.Context, target Target, session remoteSession, managedID, oldRemoteID, remoteName, platform, targetGroupRemoteID string, rateMultiplier float64, priority, concurrency int, schedulable bool, source Source, encryptedKey []byte, modelsJSON string, disabledModels []string) error {
	groupID, err := strconv.Atoi(targetGroupRemoteID)
	if err != nil {
		return fmt.Errorf("目标分组 ID 不兼容: %w", err)
	}
	key, err := a.decryptSecret(encryptedKey)
	if err != nil {
		return fmt.Errorf("读取托管 Key 失败: %w", err)
	}
	models := []string{}
	if err = json.Unmarshal([]byte(modelsJSON), &models); err != nil || len(models) == 0 {
		return fmt.Errorf("托管账号没有可用于重建的模型列表")
	}
	sourceAPIBase, err := a.discoverSourceAPIBaseURL(ctx, source)
	if err != nil {
		return fmt.Errorf("读取源站 API 地址失败: %w", err)
	}
	newRemoteID, err := a.createRemoteManagedAccount(ctx, target.BaseURL, session, sourceAPIBase, platform, string(key), models, disabledModels, []int{groupID}, remoteName, rateMultiplier, priority, concurrency)
	if err != nil {
		return fmt.Errorf("创建正确类型账号失败: %w", err)
	}
	rollbackNew := true
	restoreOldScheduling := false
	defer func() {
		if restoreOldScheduling {
			_ = a.syncTargetAccountSchedulable(context.Background(), target.BaseURL, oldRemoteID, session, true)
		}
		if rollbackNew {
			a.deleteRemoteManagedAccount(context.Background(), target.BaseURL, session, newRemoteID)
		}
	}()
	if schedulable {
		if err = a.syncTargetAccountSchedulable(ctx, target.BaseURL, oldRemoteID, session, false); err != nil {
			return fmt.Errorf("暂停旧账号失败: %w", err)
		}
		restoreOldScheduling = true
		if err = a.syncTargetAccountSchedulable(ctx, target.BaseURL, newRemoteID, session, true); err != nil {
			return fmt.Errorf("恢复新账号调度状态失败: %w", err)
		}
	}
	result, err := a.db.ExecContext(ctx, `UPDATE managed_accounts SET remote_id=$2,platform=$3,model_mapping_hash=$5,rate_multiplier=$6,sync_status='SYNCED',last_error='',updated_at=now() WHERE id=$1 AND remote_id=$4`, managedID, newRemoteID, platform, oldRemoteID, managedAccountConfigHash(platform, modelMappingForPolicy(platform, models, disabledModels)), rateMultiplier)
	if err != nil {
		return fmt.Errorf("保存新账号关联失败: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return fmt.Errorf("账号关联已变化，取消平台替换")
	}
	restoreOldScheduling = false
	rollbackNew = false
	a.deleteRemoteManagedAccount(context.Background(), target.BaseURL, session, oldRemoteID)
	a.audit(context.Background(), "REPLACE_PLATFORM", "managed_account", managedID, map[string]any{"old_remote_id": oldRemoteID, "new_remote_id": newRemoteID, "platform": platform})
	return nil
}

func (a *App) fetchTargetAssets(ctx context.Context, baseURL string, session remoteSession) (string, []map[string]any, error) {
	version := ""
	if raw, _, err := a.remoteJSON(ctx, baseURL, http.MethodGet, "/api/v1/admin/system/version", session, nil); err == nil {
		if value, unwrapErr := unwrapEnvelope(raw, "SUB2API"); unwrapErr == nil {
			record, _ := value.(map[string]any)
			version = text(record["version"], "")
		}
	}
	groups, err := a.fetchPaged(ctx, baseURL, "/api/v1/admin/groups", session)
	return version, groups, err
}

func (a *App) authenticateTarget(ctx context.Context, target Target, validate bool) (remoteSession, error) {
	a.targetAuthMu.Lock()
	defer a.targetAuthMu.Unlock()

	currentTarget, credential, err := a.targetCredentials(ctx, target.ID)
	if err != nil {
		return remoteSession{}, err
	}
	target = currentTarget
	if credentialHasSession(credential) {
		session := sessionFromCredential(credential)
		if !validate {
			return session, nil
		}
		_, _, validationErr := a.remoteJSON(ctx, target.BaseURL, http.MethodGet, "/api/v1/admin/groups?page=1&page_size=1", session, nil)
		if validationErr == nil {
			return session, nil
		}
		if !remoteUnauthorized(validationErr) {
			return remoteSession{}, validationErr
		}
	}

	if credential.RefreshToken != "" {
		pair, refreshErr := a.refreshSub2APIToken(ctx, target.BaseURL, credential.RefreshToken)
		if refreshErr == nil {
			session := remoteSession{Authorization: "Bearer " + pair.AccessToken, RefreshToken: pair.RefreshToken}
			return session, a.persistTargetSession(ctx, target.ID, credential, session)
		}
		if !remoteAuthenticationExpired(refreshErr) && !remoteRouteUnavailable(refreshErr) {
			return remoteSession{}, refreshErr
		}
	}
	if credential.Username == "" || credential.Password == "" {
		return remoteSession{}, &apiError{Status: 401, Code: "TARGET_REAUTH_REQUIRED", Message: "目标节点会话已失效且没有可用的账号密码"}
	}
	session, err := a.loginRemote(ctx, target.BaseURL, "SUB2API", credential.Username, credential.Password)
	if err != nil {
		return remoteSession{}, err
	}
	return session, a.persistTargetSession(ctx, target.ID, credential, session)
}

func (a *App) persistTargetSession(ctx context.Context, targetID string, credential sourceCredentials, session remoteSession) error {
	applySessionToCredential(&credential, session)
	encrypted, err := a.encryptSecret([]byte(jsonValue(credential)))
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `UPDATE targets SET api_key_cipher=$2,updated_at=now() WHERE id=$1`, targetID, encrypted)
	return err
}

func (a *App) targetSyncFailed(ctx context.Context, target Target, cause error) {
	if remoteRateLimited(cause) {
		_, _ = a.db.ExecContext(ctx, `UPDATE targets SET last_error=$2,updated_at=now() WHERE id=$1`, target.ID, truncate(cause.Error(), 500))
		a.resolveEvent(ctx, "target-sync:"+target.ID)
		a.openEvent(ctx, "P2", "TARGET_SYNC", "目标节点请求受限", target.Name+": "+cause.Error(), "target-rate-limit:"+target.ID)
		return
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE targets SET status='OFFLINE',last_error=$2,updated_at=now() WHERE id=$1`, target.ID, truncate(cause.Error(), 500))
	a.resolveEvent(ctx, "target-rate-limit:"+target.ID)
	a.openEvent(ctx, "P1", "TARGET_SYNC", "目标节点同步失败", target.Name+": "+cause.Error(), "target-sync:"+target.ID)
}

func (a *App) fetchPaged(ctx context.Context, baseURL, path string, session remoteSession) ([]map[string]any, error) {
	const pageSize = 100
	result := []map[string]any{}
	for page := 1; page <= 100; page++ {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		raw, _, err := a.remoteJSON(ctx, baseURL, http.MethodGet, path+separator+"page="+strconv.Itoa(page)+"&page_size="+strconv.Itoa(pageSize), session, nil)
		if err != nil {
			return nil, err
		}
		value, err := unwrapEnvelope(raw, "SUB2API")
		if err != nil {
			return nil, err
		}
		record, ok := value.(map[string]any)
		if !ok {
			return nil, &apiError{502, "SCHEMA_CHANGED", "目标节点分页格式不兼容"}
		}
		items, ok := record["items"].([]any)
		if !ok {
			return nil, &apiError{502, "SCHEMA_CHANGED", "目标节点列表格式不兼容"}
		}
		for _, item := range items {
			if typed, ok := item.(map[string]any); ok {
				result = append(result, typed)
			}
		}
		pages, _ := number(record["pages"])
		if page >= int(pages) || len(items) == 0 {
			break
		}
	}
	return result, nil
}

func (a *App) targetStatus(w http.ResponseWriter, r *http.Request, id, kind string) error {
	if kind == "groups" {
		if err := a.ensureTargetMultiplierCacheForRead(r.Context(), id); err != nil {
			return err
		}
		rows, err := a.db.QueryContext(r.Context(), `SELECT id,remote_id,name,platform,multiplier,multiplier_captured_at,models,probe_model,updated_at FROM target_groups WHERE target_id=$1 ORDER BY name`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var groupID, remoteID, name, platform, models, probeModel string
			var multiplier sql.NullFloat64
			var multiplierCaptured sql.NullTime
			var updated time.Time
			if err := rows.Scan(&groupID, &remoteID, &name, &platform, &multiplier, &multiplierCaptured, &models, &probeModel, &updated); err != nil {
				return err
			}
			items = append(items, map[string]any{"id": groupID, "remoteId": remoteID, "name": name, "platform": platform, "multiplier": nullableFloat(multiplier), "models": json.RawMessage(models), "probeModel": probeModel, "multiplierCapturedAt": nullableTime(multiplierCaptured), "updatedAt": updated})
		}
		writeData(w, items)
		return nil
	}
	if kind == "managed-accounts" {
		return a.listManagedAccountsForTarget(w, r, id)
	}
	return &apiError{Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "接口不存在"}
}

const targetMultiplierCacheTTL = 3 * time.Minute

func (a *App) ensureTargetMultiplierCacheForRead(ctx context.Context, targetID string) error {
	var total, missing, stale int
	if err := a.db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE multiplier IS NULL OR multiplier_captured_at IS NULL),count(*) FILTER (WHERE multiplier_captured_at<=now()-interval '3 minutes') FROM target_groups WHERE target_id=$1`, targetID).Scan(&total, &missing, &stale); err != nil {
		return err
	}
	if total == 0 || missing > 0 {
		return a.ensureTargetMultiplierCache(ctx, targetID)
	}
	if stale > 0 {
		a.refreshTargetMultiplierCacheAsync(targetID)
	}
	return nil
}

func (a *App) refreshTargetMultiplierCacheAsync(targetID string) {
	a.targetMultiplierMu.Lock()
	if a.targetMultiplierRefreshes == nil {
		a.targetMultiplierRefreshes = make(map[string]struct{})
	}
	if _, refreshing := a.targetMultiplierRefreshes[targetID]; refreshing {
		a.targetMultiplierMu.Unlock()
		return
	}
	a.targetMultiplierRefreshes[targetID] = struct{}{}
	a.targetMultiplierMu.Unlock()

	go func() {
		defer func() {
			a.targetMultiplierMu.Lock()
			delete(a.targetMultiplierRefreshes, targetID)
			a.targetMultiplierMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err := a.syncTarget(ctx, targetID); err != nil {
			log.Printf("后台刷新目标分组倍率失败 [%s]: %v", targetID, err)
		}
	}()
}

func (a *App) ensureTargetMultiplierCache(ctx context.Context, targetID string) error {
	var total, stale int
	if err := a.db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE multiplier IS NULL OR multiplier_captured_at IS NULL OR multiplier_captured_at<=now()-interval '3 minutes') FROM target_groups WHERE target_id=$1`, targetID).Scan(&total, &stale); err != nil {
		return err
	}
	if total == 0 || stale > 0 {
		if err := a.syncTarget(ctx, targetID); err != nil {
			return err
		}
	}
	if err := a.db.QueryRowContext(ctx, `SELECT count(*) FROM target_groups WHERE target_id=$1`, targetID).Scan(&total); err != nil {
		return err
	}
	if total == 0 {
		return &apiError{502, "TARGET_GROUPS_UNAVAILABLE", "目标节点未返回分组数据"}
	}
	return nil
}

func (a *App) ensureManagedTargetMultiplierCaches(ctx context.Context) error {
	rows, err := a.db.QueryContext(ctx, `SELECT DISTINCT target_id FROM managed_accounts`)
	if err != nil {
		return err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := a.ensureTargetMultiplierCache(ctx, id); err != nil {
			return err
		}
	}
	var missing int
	if err := a.db.QueryRowContext(ctx, `SELECT count(*) FROM managed_account_groups mg JOIN target_groups tg ON tg.id=mg.target_group_id WHERE tg.multiplier IS NULL`).Scan(&missing); err != nil {
		return err
	}
	if missing > 0 {
		return &apiError{502, "TARGET_MULTIPLIER_UNAVAILABLE", "托管账号所在目标分组未返回倍率，无法执行策略"}
	}
	return nil
}

func nullableInt(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
}

func (a *App) updateTarget(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		Name, Username, Password string
		WriteEnabled             *bool
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Name != "" {
		_, _ = a.db.ExecContext(r.Context(), `UPDATE targets SET name=$2,updated_at=now() WHERE id=$1`, id, input.Name)
	}
	if input.Username != "" && input.Password != "" {
		encrypted, err := a.encryptSecret([]byte(jsonValue(sourceCredentials{AuthMode: "PASSWORD", Username: input.Username, Password: input.Password})))
		if err != nil {
			return err
		}
		_, _ = a.db.ExecContext(r.Context(), `UPDATE targets SET api_key_cipher=$2,key_hint=$3,updated_at=now() WHERE id=$1`, id, encrypted, mask(input.Username))
	}
	if input.WriteEnabled != nil {
		_, _ = a.db.ExecContext(r.Context(), `UPDATE targets SET write_enabled=$2,updated_at=now() WHERE id=$1`, id, *input.WriteEnabled)
	}
	a.audit(r.Context(), "UPDATE", "target", id, map[string]any{"write_enabled": input.WriteEnabled})
	go a.syncTarget(context.Background(), id)
	writeData(w, map[string]any{"id": id, "status": "ACCEPTED"})
	return nil
}

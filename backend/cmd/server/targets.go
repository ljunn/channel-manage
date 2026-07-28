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
	version := ""
	if raw, _, requestErr := a.remoteJSON(requestCtx, target.BaseURL, http.MethodGet, "/api/v1/admin/system/version", session, nil); requestErr == nil {
		if value, unwrapErr := unwrapEnvelope(raw, "SUB2API"); unwrapErr == nil {
			record, _ := value.(map[string]any)
			version = text(record["version"], "")
		}
	}
	groups, err := a.fetchPaged(requestCtx, target.BaseURL, "/api/v1/admin/groups", session)
	if err != nil {
		a.targetSyncFailed(ctx, target, err)
		return err
	}
	accounts, err := a.fetchPaged(requestCtx, target.BaseURL, "/api/v1/admin/accounts?lite=true", session)
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
		_, err = tx.ExecContext(ctx, `INSERT INTO target_groups(target_id,remote_id,name,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(target_id,remote_id) DO UPDATE SET name=excluded.name,updated_at=now()`, id, remoteID, text(record["name"], remoteID))
		if err != nil {
			return err
		}
	}
	for _, record := range accounts {
		idNumber, ok := number(record["id"])
		if !ok {
			continue
		}
		remoteID := strconv.Itoa(int(idNumber))
		name := text(record["name"], remoteID)
		if strings.HasPrefix(name, "[托管]") {
			continue
		}
		priority, _ := number(record["priority"])
		concurrency, _ := number(record["concurrency"])
		schedulable, _ := record["schedulable"].(bool)
		_, err = tx.ExecContext(ctx, `INSERT INTO protected_accounts(target_id,remote_id,name,platform,group_ids,schedulable,priority,concurrency,captured_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()) ON CONFLICT(target_id,remote_id) DO UPDATE SET name=excluded.name,platform=excluded.platform,group_ids=excluded.group_ids,schedulable=excluded.schedulable,priority=excluded.priority,concurrency=excluded.concurrency,captured_at=now()`, id, remoteID, name, text(record["platform"], ""), jsonValue(stringSlice(record["group_ids"])), schedulable, int(priority), int(concurrency))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE targets SET status='ONLINE',version=$2,last_sync_at=now(),last_error='',updated_at=now() WHERE id=$1`, id, version)
	if err != nil {
		return err
	}
	return tx.Commit()
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
		a.openEvent(ctx, "P2", "TARGET_SYNC", "目标节点请求受限", target.Name+": "+cause.Error(), "target-rate-limit:"+target.ID)
		return
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE targets SET status='OFFLINE',last_error=$2,updated_at=now() WHERE id=$1`, target.ID, truncate(cause.Error(), 500))
	a.openEvent(ctx, "P1", "TARGET_SYNC", "目标节点同步失败", target.Name+": "+cause.Error(), "target-sync:"+target.ID)
}

func (a *App) fetchPaged(ctx context.Context, baseURL, path string, session remoteSession) ([]map[string]any, error) {
	result := []map[string]any{}
	for page := 1; page <= 100; page++ {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		raw, _, err := a.remoteJSON(ctx, baseURL, http.MethodGet, path+separator+"page="+strconv.Itoa(page)+"&page_size=1000", session, nil)
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
		rows, err := a.db.QueryContext(r.Context(), `SELECT id,remote_id,name,protected_best_priority,updated_at FROM target_groups WHERE target_id=$1 ORDER BY name`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var groupID, remoteID, name string
			var priority int
			var updated time.Time
			if err := rows.Scan(&groupID, &remoteID, &name, &priority, &updated); err != nil {
				return err
			}
			items = append(items, map[string]any{"id": groupID, "remoteId": remoteID, "name": name, "protectedBestPriority": priority, "updatedAt": updated})
		}
		writeData(w, items)
		return nil
	}
	query := `SELECT remote_id,name,platform,group_ids,schedulable,priority,concurrency,captured_at FROM protected_accounts WHERE target_id=$1 ORDER BY name`
	if kind == "managed-accounts" {
		return a.listManagedAccountsForTarget(w, r, id)
	}
	rows, err := a.db.QueryContext(r.Context(), query, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var remoteID, name, platform, groups string
		var schedulable bool
		var priority, concurrency sql.NullInt64
		var captured time.Time
		if err := rows.Scan(&remoteID, &name, &platform, &groups, &schedulable, &priority, &concurrency, &captured); err != nil {
			return err
		}
		items = append(items, map[string]any{"remoteId": remoteID, "name": name, "platform": platform, "groupIds": json.RawMessage(groups), "schedulable": schedulable, "priority": nullableInt(priority), "concurrency": nullableInt(concurrency), "capturedAt": captured})
	}
	writeData(w, items)
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

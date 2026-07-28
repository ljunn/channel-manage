package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Source struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Platform            string     `json:"platform"`
	BaseURL             string     `json:"baseUrl"`
	Status              string     `json:"status"`
	ValueDivisor        float64    `json:"valueDivisor"`
	UsernameHint        string     `json:"usernameHint"`
	Version             string     `json:"version"`
	ScanIntervalSeconds int        `json:"scanIntervalSeconds"`
	ScanStatus          string     `json:"scanStatus"`
	LastScanAt          *time.Time `json:"lastScanAt"`
	LastError           string     `json:"lastError"`
	Balance             *float64   `json:"balance"`
	BalanceCurrency     string     `json:"balanceCurrency"`
	KeyCount            int        `json:"keyCount"`
	GroupCount          int        `json:"groupCount"`
	CreatedAt           time.Time  `json:"createdAt"`
}

type sourceCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) listSources(ctx context.Context) ([]Source, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT s.id,s.name,s.platform,s.base_url,s.status,s.value_divisor,s.username_hint,s.version,s.scan_interval_seconds,s.scan_status,s.last_scan_at,s.last_error,s.balance,s.balance_currency,s.created_at,
		(SELECT count(*) FROM source_keys k WHERE k.source_id=s.id),(SELECT count(*) FROM source_groups g WHERE g.source_id=s.id) FROM sources s ORDER BY s.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Source{}
	for rows.Next() {
		var item Source
		var lastScan sql.NullTime
		var balance sql.NullFloat64
		if err := rows.Scan(&item.ID, &item.Name, &item.Platform, &item.BaseURL, &item.Status, &item.ValueDivisor, &item.UsernameHint, &item.Version, &item.ScanIntervalSeconds, &item.ScanStatus, &lastScan, &item.LastError, &balance, &item.BalanceCurrency, &item.CreatedAt, &item.KeyCount, &item.GroupCount); err != nil {
			return nil, err
		}
		if lastScan.Valid {
			item.LastScanAt = &lastScan.Time
		}
		if balance.Valid {
			item.Balance = &balance.Float64
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (a *App) createSource(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Name, Platform, Type, BaseURL, Username, Password string
		ValueNumerator, ValueDenominator                  float64
		ScanIntervalSeconds                               int
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	platform := strings.ToUpper(input.Platform)
	if platform == "" {
		platform = strings.ToUpper(input.Type)
	}
	if platform != "SUB2API" && platform != "NEW_API" {
		return &apiError{400, "INVALID_TYPE", "数据源类型必须是 Sub2API 或 New API"}
	}
	if strings.TrimSpace(input.Name) == "" || input.Username == "" || input.Password == "" {
		return &apiError{400, "INVALID_INPUT", "请填写名称、账号和密码"}
	}
	baseURL, err := validateRemoteURL(input.BaseURL)
	if err != nil {
		return err
	}
	credential, err := a.encryptSecret([]byte(jsonValue(sourceCredentials{input.Username, input.Password})))
	if err != nil {
		return err
	}
	divisor, err := sourceValueDivisor(input.ValueNumerator, input.ValueDenominator)
	if err != nil {
		return err
	}
	interval := input.ScanIntervalSeconds
	if interval < 60 {
		interval = 900
	}
	id := uuid.NewString()
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO sources(id,name,platform,base_url,value_divisor,credential_cipher,username_hint,scan_interval_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, strings.TrimSpace(input.Name), platform, baseURL, divisor, credential, mask(input.Username), interval)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return &apiError{409, "SOURCE_ALREADY_EXISTS", "该平台地址已添加"}
		}
		return err
	}
	a.audit(r.Context(), "CREATE", "source", id, map[string]any{"name": input.Name, "platform": platform, "base_url": baseURL, "value_divisor": divisor})
	go a.scanSource(context.Background(), id)
	writeData(w, map[string]any{"id": id, "status": "ACCEPTED"})
	return nil
}

func (a *App) updateSource(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		Name                             string
		ValueNumerator, ValueDenominator float64
		ScanIntervalSeconds              int
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if strings.TrimSpace(input.Name) == "" {
		return &apiError{400, "INVALID_INPUT", "请填写数据源名称"}
	}
	divisor, err := sourceValueDivisor(input.ValueNumerator, input.ValueDenominator)
	if err != nil {
		return err
	}
	if input.ScanIntervalSeconds < 60 {
		input.ScanIntervalSeconds = 900
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldDivisor float64
	if err = tx.QueryRowContext(r.Context(), `SELECT value_divisor FROM sources WHERE id=$1 FOR UPDATE`, id).Scan(&oldDivisor); err == sql.ErrNoRows {
		return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
	} else if err != nil {
		return err
	}
	scale := oldDivisor / divisor
	if _, err = tx.ExecContext(r.Context(), `UPDATE sources SET name=$2,value_divisor=$3,scan_interval_seconds=$4,balance=balance*$5,updated_at=now() WHERE id=$1`, id, strings.TrimSpace(input.Name), divisor, input.ScanIntervalSeconds, scale); err != nil {
		return err
	}
	if oldDivisor != divisor {
		if _, err = tx.ExecContext(r.Context(), `UPDATE source_groups SET multiplier=multiplier*$2 WHERE source_id=$1 AND multiplier IS NOT NULL`, id, scale); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE group_samples SET multiplier=multiplier*$2,balance=balance*$2 WHERE source_id=$1`, id, scale); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "UPDATE", "source", id, map[string]any{"name": strings.TrimSpace(input.Name), "value_divisor": divisor, "previous_value_divisor": oldDivisor})
	go a.scanSource(context.Background(), id)
	writeData(w, map[string]any{"id": id, "valueDivisor": divisor, "status": "ACCEPTED"})
	return nil
}

func sourceValueDivisor(numerator, denominator float64) (float64, error) {
	if numerator == 0 && denominator == 0 {
		return 1, nil
	}
	if numerator <= 0 || denominator <= 0 {
		return 0, &apiError{400, "INVALID_VALUE_RATIO", "余额/倍率换算比例必须大于 0"}
	}
	divisor := denominator / numerator
	if math.IsNaN(divisor) || math.IsInf(divisor, 0) || divisor <= 0 || divisor > 1e9 {
		return 0, &apiError{400, "INVALID_VALUE_RATIO", "余额/倍率换算比例无效"}
	}
	return divisor, nil
}

func mask(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

func (a *App) sourceCredentials(ctx context.Context, id string) (Source, sourceCredentials, error) {
	var source Source
	var encrypted []byte
	err := a.db.QueryRowContext(ctx, `SELECT id,name,platform,base_url,status,value_divisor,credential_cipher,scan_interval_seconds FROM sources WHERE id=$1`, id).Scan(&source.ID, &source.Name, &source.Platform, &source.BaseURL, &source.Status, &source.ValueDivisor, &encrypted, &source.ScanIntervalSeconds)
	if err == sql.ErrNoRows {
		return source, sourceCredentials{}, &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
	}
	if err != nil {
		return source, sourceCredentials{}, err
	}
	plain, err := a.decryptSecret(encrypted)
	if err != nil {
		return source, sourceCredentials{}, err
	}
	var credential sourceCredentials
	if json.Unmarshal(plain, &credential) != nil {
		return source, credential, fmt.Errorf("invalid source credential")
	}
	return source, credential, nil
}

func (a *App) scanSource(ctx context.Context, id string) error {
	result, err := a.db.ExecContext(ctx, `UPDATE sources SET scan_status='RUNNING',last_error='',updated_at=now() WHERE id=$1 AND scan_status<>'RUNNING'`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return nil
	}
	source, credential, err := a.sourceCredentials(ctx, id)
	if err == nil {
		requestCtx, cancel := timeoutContext(ctx)
		defer cancel()
		var session remoteSession
		session, err = a.loginRemote(requestCtx, source.BaseURL, source.Platform, credential.Username, credential.Password)
		if err == nil {
			err = a.collectSource(requestCtx, source, session)
		}
	}
	if err != nil {
		_, _ = a.db.ExecContext(ctx, `UPDATE sources SET scan_status='FAILED',last_error=$2,updated_at=now() WHERE id=$1`, id, truncate(err.Error(), 500))
		a.openEvent(ctx, "P1", "SOURCE_SCAN", "数据源扫描失败", source.Name+": "+err.Error(), "source-scan:"+id)
		return err
	}
	_, err = a.db.ExecContext(ctx, `UPDATE sources SET scan_status='SUCCESS',last_scan_at=now(),last_error='',updated_at=now() WHERE id=$1`, id)
	return err
}

func (a *App) collectSource(ctx context.Context, source Source, session remoteSession) error {
	type group struct {
		RemoteID, Name string
		Multiplier     *float64
		Models         []string
	}
	groups := []group{}
	var balance *float64
	if source.Platform == "SUB2API" {
		rawGroups, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/v1/groups/available", session, nil)
		if err != nil {
			return err
		}
		data, err := unwrapEnvelope(rawGroups, source.Platform)
		if err != nil {
			return err
		}
		rawRates, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/v1/groups/rates", session, nil)
		if err != nil {
			return err
		}
		ratesValue, err := unwrapEnvelope(rawRates, source.Platform)
		if err != nil {
			return err
		}
		rates, _ := ratesValue.(map[string]any)
		items, ok := data.([]any)
		if !ok {
			return &apiError{502, "SCHEMA_CHANGED", "分组接口返回格式不兼容"}
		}
		for _, value := range items {
			record, _ := value.(map[string]any)
			idNumber, ok := number(record["id"])
			if !ok {
				continue
			}
			remoteID := fmt.Sprintf("%.0f", idNumber)
			var multiplier *float64
			if v, ok := number(rates[remoteID]); ok {
				multiplier = &v
			}
			groups = append(groups, group{remoteID, text(record["name"], remoteID), multiplier, []string{}})
		}
		profileRaw, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/v1/user/profile", session, nil)
		if err == nil {
			profileValue, _ := unwrapEnvelope(profileRaw, source.Platform)
			profile, _ := profileValue.(map[string]any)
			if v, ok := number(profile["balance"]); ok {
				balance = &v
			}
		}
	} else {
		raw, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/user/self/groups", session, nil)
		if err != nil {
			return err
		}
		data, err := unwrapEnvelope(raw, source.Platform)
		if err != nil {
			return err
		}
		records, ok := data.(map[string]any)
		if !ok {
			return &apiError{502, "SCHEMA_CHANGED", "分组接口返回格式不兼容"}
		}
		for remoteID, value := range records {
			record, _ := value.(map[string]any)
			var multiplier *float64
			if v, ok := number(record["ratio"]); ok {
				multiplier = &v
			}
			groups = append(groups, group{remoteID, text(record["desc"], remoteID), multiplier, []string{}})
		}
		profileRaw, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/user/self", session, nil)
		if err == nil {
			profileValue, _ := unwrapEnvelope(profileRaw, source.Platform)
			profile, _ := profileValue.(map[string]any)
			if quota, ok := number(profile["quota"]); ok {
				v := quota / 500000
				balance = &v
			}
		}
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT value_divisor FROM sources WHERE id=$1 FOR UPDATE`, source.ID).Scan(&source.ValueDivisor); err != nil {
		return err
	}
	if source.ValueDivisor <= 0 {
		source.ValueDivisor = 1
	}
	for index := range groups {
		if groups[index].Multiplier != nil {
			value := *groups[index].Multiplier / source.ValueDivisor
			groups[index].Multiplier = &value
		}
	}
	if balance != nil {
		value := *balance / source.ValueDivisor
		balance = &value
	}
	for _, item := range groups {
		var groupID string
		err = tx.QueryRowContext(ctx, `INSERT INTO source_groups(source_id,remote_id,name,multiplier,models,captured_at) VALUES($1,$2,$3,$4,$5,now()) ON CONFLICT(source_id,remote_id) DO UPDATE SET name=excluded.name,multiplier=excluded.multiplier,models=excluded.models,captured_at=now() RETURNING id`, source.ID, item.RemoteID, item.Name, item.Multiplier, jsonValue(item.Models)).Scan(&groupID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO group_samples(source_id,group_id,multiplier,balance) VALUES($1,$2,$3,$4)`, source.ID, groupID, item.Multiplier, balance)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE sources SET balance=$2,capabilities=$3::jsonb WHERE id=$1`, source.ID, balance, jsonValue(map[string]bool{"AUTHENTICATE": true, "GROUPS": true, "BALANCE": true, "MODELS": source.Platform == "NEW_API"}))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO channels(source_id,source_key_id,source_group_id,state_reason) SELECT k.source_id,k.id,g.id,'等待首次探测' FROM source_keys k JOIN source_groups g ON g.source_id=k.source_id WHERE k.source_id=$1 AND k.production_authorized=true ON CONFLICT DO NOTHING`, source.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func truncate(value string, max int) string {
	r := []rune(value)
	if len(r) <= max {
		return value
	}
	return string(r[:max])
}

func (a *App) addSourceKey(w http.ResponseWriter, r *http.Request, sourceID string) error {
	var input struct {
		Name, APIKey         string
		ProductionAuthorized bool
		Concurrency          int
		Models               []string
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Name == "" || input.APIKey == "" {
		return &apiError{400, "INVALID_UPSTREAM_KEY", "请填写 Key 名称和内容"}
	}
	if input.Concurrency < 1 {
		input.Concurrency = 1
	}
	encrypted, err := a.encryptSecret([]byte(input.APIKey))
	if err != nil {
		return err
	}
	id := uuid.NewString()
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO source_keys(id,source_id,name,key_cipher,key_hint,production_authorized,concurrency,models) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, sourceID, input.Name, encrypted, mask(input.APIKey), input.ProductionAuthorized, input.Concurrency, jsonValue(input.Models))
	if err != nil {
		return err
	}
	if input.ProductionAuthorized {
		_, err = a.db.ExecContext(r.Context(), `INSERT INTO channels(source_id,source_key_id,source_group_id,state_reason) SELECT $1,$2,id,'等待首次探测' FROM source_groups WHERE source_id=$1 ON CONFLICT DO NOTHING`, sourceID, id)
	}
	a.audit(r.Context(), "CREATE", "source_key", id, map[string]any{"source_id": sourceID, "production_authorized": input.ProductionAuthorized})
	writeData(w, map[string]any{"id": id})
	return err
}

func (a *App) sourceDetail(w http.ResponseWriter, r *http.Request, id string) error {
	sources, err := a.listSources(r.Context())
	if err != nil {
		return err
	}
	var source *Source
	for index := range sources {
		if sources[index].ID == id {
			source = &sources[index]
			break
		}
	}
	if source == nil {
		return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,name,key_hint,production_authorized,status,models,concurrency,created_at FROM source_keys WHERE source_id=$1 ORDER BY created_at`, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	keys := []map[string]any{}
	for rows.Next() {
		var keyID, name, hint, authorized, status, models string
		var production bool
		var concurrency int
		var created time.Time
		if err := rows.Scan(&keyID, &name, &hint, &production, &status, &models, &concurrency, &created); err != nil {
			return err
		}
		_ = authorized
		keys = append(keys, map[string]any{"id": keyID, "name": name, "keyHint": hint, "productionAuthorized": production, "status": status, "models": json.RawMessage(models), "concurrency": concurrency, "createdAt": created})
	}
	groupRows, err := a.db.QueryContext(r.Context(), `SELECT id,remote_id,name,multiplier,group_type,models,captured_at FROM source_groups WHERE source_id=$1 ORDER BY name`, id)
	if err != nil {
		return err
	}
	defer groupRows.Close()
	groups := []map[string]any{}
	for groupRows.Next() {
		var groupID, remoteID, name, groupType, models string
		var multiplier sql.NullFloat64
		var captured time.Time
		if err := groupRows.Scan(&groupID, &remoteID, &name, &multiplier, &groupType, &models, &captured); err != nil {
			return err
		}
		groups = append(groups, map[string]any{"id": groupID, "remoteId": remoteID, "name": name, "multiplier": nullableFloat(multiplier), "groupType": groupType, "models": json.RawMessage(models), "capturedAt": captured})
	}
	writeData(w, map[string]any{"source": source, "keys": keys, "groups": groups})
	return nil
}

func nullableFloat(value sql.NullFloat64) any {
	if value.Valid {
		return value.Float64
	}
	return nil
}

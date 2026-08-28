package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Source struct {
	ID                    string     `json:"id"`
	Name                  string     `json:"name"`
	Platform              string     `json:"platform"`
	BaseURL               string     `json:"baseUrl"`
	RechargeURL           string     `json:"rechargeUrl"`
	Status                string     `json:"status"`
	ManuallyUntrusted     bool       `json:"manuallyUntrusted"`
	ManuallyUntrustedAt   *time.Time `json:"manuallyUntrustedAt"`
	SchedulingPaused      bool       `json:"schedulingPaused"`
	SchedulingPausedAt    *time.Time `json:"schedulingPausedAt"`
	ValueDivisor          float64    `json:"valueDivisor"`
	UsernameHint          string     `json:"usernameHint"`
	Version               string     `json:"version"`
	ScanIntervalSeconds   int        `json:"scanIntervalSeconds"`
	ScanStatus            string     `json:"scanStatus"`
	LastScanAt            *time.Time `json:"lastScanAt"`
	LastError             string     `json:"lastError"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt"`
	LastTokenRefreshAt    *time.Time `json:"lastTokenRefreshAt"`
	TokenRefreshNextAt    *time.Time `json:"tokenRefreshNextAt"`
	TokenRefreshFailures  int        `json:"tokenRefreshFailures"`
	TokenRefreshError     string     `json:"tokenRefreshError"`
	Balance               *float64   `json:"balance"`
	BalanceCurrency       string     `json:"balanceCurrency"`
	BalanceBurnRate       *float64   `json:"balanceBurnRate"`
	BalanceEtaHours       *float64   `json:"balanceEtaHours"`
	BalanceSampleCount    int        `json:"balanceSampleCount"`
	KeyCount              int        `json:"keyCount"`
	GroupCount            int        `json:"groupCount"`
	BoundGroupCount       int        `json:"boundGroupCount"`
	ManagedAccountCount   int        `json:"managedAccountCount"`
	StabilityStatus       string     `json:"stabilityStatus"`
	StabilityConfidence   string     `json:"stabilityConfidence"`
	StabilityReasons      []string   `json:"stabilityReasons"`
	BusinessRequests7d    int        `json:"businessRequests7d"`
	BusinessSuccessRate7d *float64   `json:"businessSuccessRate7d"`
	FirstTokenP95Ms7d     *float64   `json:"firstTokenP95Ms7d"`
	FirstTokenSource      string     `json:"firstTokenSource"`
	ProbeSamples7d        int        `json:"probeSamples7d"`
	ProbeSuccessRate7d    *float64   `json:"probeSuccessRate7d"`
	ScanIncidents7d       int        `json:"scanIncidents7d"`
	CreatedAt             time.Time  `json:"createdAt"`
}

type sourceCredentials struct {
	AuthMode     string `json:"authMode,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	Cookie       string `json:"cookie,omitempty"`
	UserID       string `json:"userId,omitempty"`
	SessionID    string `json:"sessionId,omitempty"`
}

func (a *App) listSources(ctx context.Context) ([]Source, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT s.id,s.name,s.platform,s.base_url,s.recharge_url,s.status,s.manually_untrusted,s.manually_untrusted_at,s.scheduling_paused,s.scheduling_paused_at,s.value_divisor,s.username_hint,s.version,s.scan_interval_seconds,s.scan_status,s.last_scan_at,s.last_error,s.access_token_expires_at,s.last_token_refresh_at,s.token_refresh_next_at,s.token_refresh_failures,s.token_refresh_error,s.balance,s.balance_currency,s.created_at,
		(SELECT count(*) FROM source_keys k WHERE k.source_id=s.id),
		(SELECT count(*) FROM source_groups g WHERE g.source_id=s.id),
		(SELECT count(DISTINCT c.source_group_id) FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=s.id AND c.source_group_id IS NOT NULL),
		(SELECT count(*) FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=s.id)
		FROM sources s ORDER BY s.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Source{}
	for rows.Next() {
		var item Source
		var lastScan, manuallyUntrustedAt, schedulingPausedAt, accessTokenExpiresAt, lastTokenRefreshAt, tokenRefreshNextAt sql.NullTime
		var balance sql.NullFloat64
		if err := rows.Scan(&item.ID, &item.Name, &item.Platform, &item.BaseURL, &item.RechargeURL, &item.Status, &item.ManuallyUntrusted, &manuallyUntrustedAt, &item.SchedulingPaused, &schedulingPausedAt, &item.ValueDivisor, &item.UsernameHint, &item.Version, &item.ScanIntervalSeconds, &item.ScanStatus, &lastScan, &item.LastError, &accessTokenExpiresAt, &lastTokenRefreshAt, &tokenRefreshNextAt, &item.TokenRefreshFailures, &item.TokenRefreshError, &balance, &item.BalanceCurrency, &item.CreatedAt, &item.KeyCount, &item.GroupCount, &item.BoundGroupCount, &item.ManagedAccountCount); err != nil {
			return nil, err
		}
		if lastScan.Valid {
			item.LastScanAt = &lastScan.Time
		}
		if manuallyUntrustedAt.Valid {
			item.ManuallyUntrustedAt = &manuallyUntrustedAt.Time
		}
		if schedulingPausedAt.Valid {
			item.SchedulingPausedAt = &schedulingPausedAt.Time
		}
		if balance.Valid {
			item.Balance = &balance.Float64
		}
		if accessTokenExpiresAt.Valid {
			item.AccessTokenExpiresAt = &accessTokenExpiresAt.Time
		}
		if lastTokenRefreshAt.Valid {
			item.LastTokenRefreshAt = &lastTokenRefreshAt.Time
		}
		if tokenRefreshNextAt.Valid {
			item.TokenRefreshNextAt = &tokenRefreshNextAt.Time
		}
		result = append(result, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for index := range result {
		forecast, forecastErr := a.sourceBalanceForecast(ctx, result[index].ID)
		if forecastErr != nil || !forecast.Known {
			continue
		}
		result[index].BalanceBurnRate = &forecast.BurnRate
		result[index].BalanceEtaHours = &forecast.EtaHours
		result[index].BalanceSampleCount = forecast.Samples
	}
	if err := a.applySourceStabilityAssessments(ctx, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *App) createSource(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Name, Platform, Type, BaseURL, RechargeURL, AuthMode, Username, Password, AccessToken, RefreshToken string
		ValueNumerator, ValueDenominator                                                                    float64
		ScanIntervalSeconds                                                                                 int
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
	if strings.TrimSpace(input.Name) == "" {
		return &apiError{400, "INVALID_INPUT", "请填写数据源名称"}
	}
	authMode := strings.ToUpper(strings.TrimSpace(input.AuthMode))
	if authMode == "" {
		authMode = "PASSWORD"
	}
	if authMode != "PASSWORD" && authMode != "TOKEN" {
		return &apiError{400, "INVALID_AUTH_MODE", "认证方式必须是账号密码或令牌"}
	}
	if platform != "SUB2API" && authMode != "PASSWORD" {
		return &apiError{400, "INVALID_AUTH_MODE", "New API 仅支持账号密码认证"}
	}
	credential := sourceCredentials{AuthMode: authMode}
	credentialHint := ""
	if authMode == "TOKEN" {
		accessToken := normalizeAccessToken(input.AccessToken)
		refreshToken := strings.TrimSpace(input.RefreshToken)
		if platform != "SUB2API" || accessToken == "" || refreshToken == "" {
			return &apiError{400, "INVALID_INPUT", "令牌认证需要填写 Access Token 和 Refresh Token"}
		}
		credential.AccessToken = accessToken
		credential.RefreshToken = refreshToken
		credentialHint = "令牌认证"
	} else {
		if strings.TrimSpace(input.Username) == "" || input.Password == "" {
			return &apiError{400, "INVALID_INPUT", "请填写账号和密码"}
		}
		credential.AuthMode = "PASSWORD"
		credential.Username = strings.TrimSpace(input.Username)
		credential.Password = input.Password
		credentialHint = mask(input.Username)
	}
	baseURL, err := validateSourceURL(input.BaseURL)
	if err != nil {
		return err
	}
	rechargeURL, err := normalizeOptionalLink(input.RechargeURL)
	if err != nil {
		return err
	}
	encryptedCredential, err := a.encryptSecret([]byte(jsonValue(credential)))
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
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO sources(id,name,platform,base_url,recharge_url,value_divisor,credential_cipher,username_hint,scan_interval_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, strings.TrimSpace(input.Name), platform, baseURL, rechargeURL, divisor, encryptedCredential, credentialHint, interval)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return &apiError{409, "SOURCE_ALREADY_EXISTS", "该平台地址已添加"}
		}
		return err
	}
	a.audit(r.Context(), "CREATE", "source", id, map[string]any{"name": input.Name, "platform": platform, "base_url": baseURL, "value_divisor": divisor, "auth_mode": credential.AuthMode})
	go a.scanSource(context.Background(), id)
	writeData(w, map[string]any{"id": id, "status": "ACCEPTED"})
	return nil
}

func normalizeAccessToken(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 7 && strings.EqualFold(value[:7], "Bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return value
}

func (a *App) updateSource(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		Name, RechargeURL                                       string
		AuthMode, Username, Password, AccessToken, RefreshToken string
		ValueNumerator, ValueDenominator                        float64
		ScanIntervalSeconds                                     int
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
	rechargeURL, err := normalizeOptionalLink(input.RechargeURL)
	if err != nil {
		return err
	}
	if input.ScanIntervalSeconds < 60 {
		input.ScanIntervalSeconds = 900
	}
	credentialChanged := input.AuthMode != "" || input.Username != "" || input.Password != "" || input.AccessToken != "" || input.RefreshToken != ""
	var encryptedCredential []byte
	credentialHint := ""
	credentialMode := ""
	if credentialChanged {
		source, _, credentialErr := a.sourceCredentials(r.Context(), id)
		if credentialErr != nil {
			return credentialErr
		}
		credentialMode = strings.ToUpper(strings.TrimSpace(input.AuthMode))
		if credentialMode == "" {
			credentialMode = "PASSWORD"
		}
		credential := sourceCredentials{AuthMode: credentialMode}
		if credentialMode == "TOKEN" {
			credential.AccessToken = normalizeAccessToken(input.AccessToken)
			credential.RefreshToken = strings.TrimSpace(input.RefreshToken)
			if source.Platform != "SUB2API" || credential.AccessToken == "" || credential.RefreshToken == "" {
				return &apiError{400, "INVALID_INPUT", "令牌认证需要同时填写 Access Token 和 Refresh Token"}
			}
			credentialHint = "令牌认证"
		} else if credentialMode == "PASSWORD" {
			credential.Username = strings.TrimSpace(input.Username)
			credential.Password = input.Password
			if credential.Username == "" || credential.Password == "" {
				return &apiError{400, "INVALID_INPUT", "重新认证时请同时填写账号和密码"}
			}
			credentialHint = mask(credential.Username)
		} else {
			return &apiError{400, "INVALID_AUTH_MODE", "认证方式必须是账号密码或令牌"}
		}
		encryptedCredential, err = a.encryptSecret([]byte(jsonValue(credential)))
		if err != nil {
			return err
		}
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldDivisor float64
	var sourceStatus string
	if err = tx.QueryRowContext(r.Context(), `SELECT value_divisor,status FROM sources WHERE id=$1 FOR UPDATE`, id).Scan(&oldDivisor, &sourceStatus); err == sql.ErrNoRows {
		return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
	} else if err != nil {
		return err
	}
	if sourceStatus != "ACTIVE" {
		return &apiError{409, "SOURCE_DELETING", "该数据源正在删除，不能修改设置"}
	}
	scale := oldDivisor / divisor
	if _, err = tx.ExecContext(r.Context(), `UPDATE sources SET name=$2,recharge_url=$3,value_divisor=$4,scan_interval_seconds=$5,balance=balance*$6,updated_at=now() WHERE id=$1`, id, strings.TrimSpace(input.Name), rechargeURL, divisor, input.ScanIntervalSeconds, scale); err != nil {
		return err
	}
	if credentialChanged {
		if _, err = tx.ExecContext(r.Context(), `UPDATE sources SET credential_cipher=$2,username_hint=$3,scan_status='UNKNOWN',last_error='',access_token_expires_at=NULL,last_token_refresh_at=NULL,token_refresh_next_at=CASE WHEN $3='令牌认证' THEN now() ELSE NULL END,token_refresh_failures=0,token_refresh_error='',updated_at=now() WHERE id=$1`, id, encryptedCredential, credentialHint); err != nil {
			return err
		}
	}
	if oldDivisor != divisor {
		if _, err = tx.ExecContext(r.Context(), `UPDATE source_groups SET multiplier=multiplier*$2 WHERE source_id=$1 AND multiplier IS NOT NULL`, id, scale); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE group_samples SET multiplier=multiplier*$2,balance=balance*$2 WHERE source_id=$1`, id, scale); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `DELETE FROM source_balance_samples WHERE source_id=$1`, id); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "UPDATE", "source", id, map[string]any{"name": strings.TrimSpace(input.Name), "value_divisor": divisor, "previous_value_divisor": oldDivisor, "credentials_changed": credentialChanged, "auth_mode": credentialMode})
	go a.scanSource(context.Background(), id)
	writeData(w, map[string]any{"id": id, "valueDivisor": divisor, "status": "ACCEPTED"})
	return nil
}

func normalizeOptionalLink(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", &apiError{400, "INVALID_RECHARGE_URL", "充值地址必须是完整的 HTTP 或 HTTPS 地址"}
	}
	if parsed.Scheme == "http" && !envBool("ALLOW_INSECURE_UPSTREAMS", false) {
		return "", &apiError{400, "INSECURE_RECHARGE_URL", "充值地址必须使用 HTTPS"}
	}
	parsed.Fragment = ""
	return parsed.String(), nil
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
	result, err := a.db.ExecContext(ctx, `UPDATE sources SET scan_status='RUNNING',last_error='',updated_at=now() WHERE id=$1 AND status='ACTIVE' AND scan_status NOT IN ('RUNNING','AUTH_REQUIRED')`, id)
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
		session, err = a.authenticateSource(requestCtx, source, credential, false)
		if err == nil {
			err = a.collectSource(requestCtx, source, session)
			if remoteUnauthorized(err) {
				session, err = a.renewSourceSession(requestCtx, source, credential)
				if err == nil {
					err = a.collectSource(requestCtx, source, session)
				}
			}
		}
	}
	if err != nil {
		reported := sourceAuthenticationActionError(source, err)
		status := "FAILED"
		if remoteInteractiveAuthRequired(err) {
			status = "AUTH_REQUIRED"
		}
		message := userErrorMessage(reported)
		_, _ = a.db.ExecContext(ctx, `UPDATE sources SET scan_status=$2,last_scan_at=now(),last_error=$3,updated_at=now() WHERE id=$1`, id, status, truncate(message, 500))
		if !a.sourceIsManuallyUntrusted(ctx, id) {
			a.openEvent(ctx, "P1", "SOURCE_SCAN", "数据源扫描失败", source.Name+": "+message, "source-scan:"+id)
		}
		return reported
	}
	_, err = a.db.ExecContext(ctx, `UPDATE sources SET scan_status='SUCCESS',last_scan_at=now(),last_error='',updated_at=now() WHERE id=$1`, id)
	if err == nil {
		if !a.sourceIsManuallyUntrusted(ctx, id) {
			a.resolveEvent(ctx, "source-scan:"+id)
			a.evaluateSourceBalance(ctx, id)
		}
		go a.syncSourceManagedAccountRateMultipliers(id)
	}
	return err
}

func sourceAuthenticationActionError(source Source, err error) error {
	if !remoteInteractiveAuthRequired(err) {
		return err
	}
	action := "远端要求完成滑块验证"
	if strings.Contains(strings.ToLower(err.Error()), "auth_session_limit") || strings.Contains(strings.ToLower(err.Error()), "session limit") {
		action = "远端登录会话已达到上限"
	}
	return &apiError{Status: 409, Code: "SOURCE_AUTH_ACTION_REQUIRED", Message: fmt.Sprintf("%s：%s。系统已停止自动重登；请登录源站处理后，在数据源编辑中更新 Access Token + Refresh Token", source.Name, action)}
}

func (a *App) retrySourceScan(ctx context.Context, id string) error {
	result, err := a.db.ExecContext(ctx, `UPDATE sources SET scan_status='UNKNOWN',last_error='',updated_at=now() WHERE id=$1 AND status='ACTIVE'`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
	}
	go a.scanSource(context.Background(), id)
	return nil
}

func (a *App) authenticateSource(ctx context.Context, source Source, credential sourceCredentials, validate bool) (remoteSession, error) {
	if source.Platform != "SUB2API" && source.Platform != "NEW_API" {
		return a.loginRemote(ctx, source.BaseURL, source.Platform, credential.Username, credential.Password)
	}
	if !credentialHasSession(credential) {
		return a.renewSourceSession(ctx, source, credential)
	}
	session := sessionFromCredential(credential)
	if !validate {
		return session, nil
	}
	path := "/api/v1/groups/available"
	if source.Platform == "NEW_API" {
		path = "/api/user/self/groups"
	}
	_, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, path, session, nil)
	if err == nil {
		return session, nil
	}
	if !remoteUnauthorized(err) {
		return remoteSession{}, err
	}
	return a.renewSourceSession(ctx, source, credential)
}

func (a *App) renewSourceSession(ctx context.Context, source Source, expected sourceCredentials) (remoteSession, error) {
	lock := a.sourceAuthLock(source.ID)
	lock.Lock()
	defer lock.Unlock()
	return a.renewSourceSessionLocked(ctx, source, expected)
}

func (a *App) sourceAuthLock(sourceID string) *sync.Mutex {
	if value, ok := a.sourceAuthLocks.Load(sourceID); ok {
		return value.(*sync.Mutex)
	}
	created := &sync.Mutex{}
	actual, _ := a.sourceAuthLocks.LoadOrStore(sourceID, created)
	return actual.(*sync.Mutex)
}

func (a *App) renewSourceSessionLocked(ctx context.Context, source Source, expected sourceCredentials) (remoteSession, error) {

	_, current, err := a.sourceCredentials(ctx, source.ID)
	if err != nil {
		return remoteSession{}, err
	}
	if credentialHasSession(current) && (current.AccessToken != expected.AccessToken || current.Cookie != expected.Cookie || current.RefreshToken != expected.RefreshToken) {
		return sessionFromCredential(current), nil
	}

	var session remoteSession
	if source.Platform == "SUB2API" && current.RefreshToken != "" {
		pair, refreshErr := a.refreshSub2APIToken(ctx, source.BaseURL, current.RefreshToken)
		if refreshErr == nil {
			session = remoteSession{Authorization: "Bearer " + pair.AccessToken, RefreshToken: pair.RefreshToken}
			return session, a.persistSourceSession(ctx, source.ID, current, session)
		}
		if !remoteAuthenticationExpired(refreshErr) && !remoteRouteUnavailable(refreshErr) {
			return remoteSession{}, refreshErr
		}
	}
	if source.Platform == "NEW_API" && current.Cookie != "" && current.SessionID != "" {
		refreshed, refreshErr := a.refreshNewAPISession(ctx, source.BaseURL, sessionFromCredential(current))
		if refreshErr == nil {
			return refreshed, a.persistSourceSession(ctx, source.ID, current, refreshed)
		}
		if !remoteAuthenticationExpired(refreshErr) && !remoteRouteUnavailable(refreshErr) {
			return remoteSession{}, refreshErr
		}
	}
	if current.Username == "" || current.Password == "" {
		return remoteSession{}, &apiError{Status: 401, Code: "SOURCE_REAUTH_REQUIRED", Message: "远端会话已失效且没有可用的账号密码"}
	}
	session, err = a.loginRemote(ctx, source.BaseURL, source.Platform, current.Username, current.Password)
	if err != nil {
		return remoteSession{}, err
	}
	return session, a.persistSourceSession(ctx, source.ID, current, session)
}

func (a *App) persistSourceSession(ctx context.Context, sourceID string, credential sourceCredentials, session remoteSession) error {
	applySessionToCredential(&credential, session)
	encrypted, err := a.encryptSecret([]byte(jsonValue(credential)))
	if err != nil {
		return err
	}
	var accessTokenExpiresAt, tokenRefreshNextAt any
	if accessToken := strings.TrimSpace(strings.TrimPrefix(session.Authorization, "Bearer ")); accessToken != "" {
		now := time.Now()
		if expiresAt, ok := accessTokenExpiry(accessToken); ok {
			accessTokenExpiresAt = expiresAt
			nextAt := nextTokenRefreshAt(expiresAt, now)
			tokenRefreshNextAt = nextAt
		} else {
			tokenRefreshNextAt = now.Add(tokenRefreshFallback)
		}
	}
	if _, err = a.db.ExecContext(ctx, `UPDATE sources SET credential_cipher=$2,access_token_expires_at=$3,last_token_refresh_at=CASE WHEN $4 IS NOT NULL THEN now() ELSE last_token_refresh_at END,token_refresh_next_at=$4,token_refresh_failures=0,token_refresh_error='',scan_status=CASE WHEN scan_status='AUTH_REQUIRED' THEN 'UNKNOWN' ELSE scan_status END,last_error=CASE WHEN scan_status='AUTH_REQUIRED' THEN '' ELSE last_error END,last_scan_at=CASE WHEN scan_status='AUTH_REQUIRED' THEN NULL ELSE last_scan_at END,updated_at=now() WHERE id=$1`, sourceID, encrypted, accessTokenExpiresAt, tokenRefreshNextAt); err != nil {
		return err
	}
	return nil
}

func accessTokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	var payload []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		payload, err = encoding.DecodeString(parts[1])
		if err == nil {
			break
		}
	}
	if err != nil {
		return time.Time{}, false
	}
	var claims map[string]json.RawMessage
	if err = json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	var seconds float64
	if raw, ok := claims["exp"]; !ok || json.Unmarshal(raw, &seconds) != nil || seconds <= 0 {
		return time.Time{}, false
	}
	if seconds > 1e12 {
		seconds /= 1000
	}
	expiresAt := time.Unix(int64(seconds), 0)
	if expiresAt.IsZero() {
		return time.Time{}, false
	}
	return expiresAt, true
}

func nextTokenRefreshAt(expiresAt, now time.Time) time.Time {
	remaining := expiresAt.Sub(now)
	lead := tokenRefreshLead
	if remaining > 0 && remaining/5 < lead {
		lead = remaining / 5
	}
	if lead < time.Minute {
		lead = time.Minute
	}
	next := expiresAt.Add(-lead)
	if next.Before(now) {
		return now
	}
	return next
}

func tokenRefreshBackoff(failures int) time.Duration {
	switch {
	case failures <= 1:
		return time.Minute
	case failures == 2:
		return 5 * time.Minute
	case failures == 3:
		return 15 * time.Minute
	case failures == 4:
		return time.Hour
	default:
		return 6 * time.Hour
	}
}

func (a *App) refreshSourceToken(ctx context.Context, sourceID string) error {
	source, _, err := a.sourceCredentials(ctx, sourceID)
	if err != nil {
		return err
	}
	lock := a.sourceAuthLock(sourceID)
	lock.Lock()
	defer lock.Unlock()

	source, current, err := a.sourceCredentials(ctx, sourceID)
	if err != nil {
		return err
	}
	if source.Status != "ACTIVE" {
		return nil
	}
	var nextAt sql.NullTime
	if err = a.db.QueryRowContext(ctx, `SELECT token_refresh_next_at FROM sources WHERE id=$1`, sourceID).Scan(&nextAt); err != nil {
		return err
	}
	if nextAt.Valid && nextAt.Time.After(time.Now()) {
		return nil
	}
	if current.RefreshToken == "" && !(source.Platform == "NEW_API" && current.Cookie != "" && current.SessionID != "") {
		_, err = a.db.ExecContext(ctx, `UPDATE sources SET token_refresh_next_at=now()+$2 * interval '1 second',updated_at=now() WHERE id=$1`, sourceID, int(tokenRefreshFallback.Seconds()))
		return err
	}
	_, err = a.renewSourceSessionLocked(ctx, source, current)
	if err == nil {
		log.Printf("数据源 %s 会话保活成功", sourceID)
		return nil
	}
	if recordErr := a.recordSourceTokenRefreshFailure(ctx, sourceID, err); recordErr != nil {
		logDatabaseError("记录数据源令牌刷新失败", recordErr)
	}
	return err
}

func (a *App) recordSourceTokenRefreshFailure(ctx context.Context, sourceID string, cause error) error {
	var failures int
	if err := a.db.QueryRowContext(ctx, `SELECT token_refresh_failures FROM sources WHERE id=$1`, sourceID).Scan(&failures); err != nil {
		return err
	}
	failures++
	backoff := tokenRefreshBackoff(failures)
	_, err := a.db.ExecContext(ctx, `UPDATE sources SET token_refresh_failures=$2,token_refresh_error=$3,token_refresh_next_at=now()+$4 * interval '1 second',updated_at=now() WHERE id=$1`, sourceID, failures, truncate(cause.Error(), 500), int(backoff.Seconds()))
	return err
}

func (a *App) collectSource(ctx context.Context, source Source, session remoteSession) error {
	type group struct {
		RemoteID, Name, Description, GroupType string
		Multiplier                             *float64
		Models                                 []string
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
			multiplier := sub2APIGroupMultiplier(record, rates, remoteID)
			groups = append(groups, group{remoteID, text(record["name"], remoteID), text(record["description"], ""), text(record["platform"], "default"), multiplier, []string{}})
		}
		profileRaw, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/v1/user/profile", session, nil)
		if err != nil {
			return fmt.Errorf("读取账户余额失败: %w", err)
		}
		profileValue, err := unwrapEnvelope(profileRaw, source.Platform)
		if err != nil {
			return err
		}
		profile, ok := profileValue.(map[string]any)
		if !ok {
			return &apiError{502, "SCHEMA_CHANGED", "账户资料接口返回格式不兼容"}
		}
		if v, ok := sourceProfileBalance(profile); ok {
			balance = &v
		} else {
			return &apiError{502, "SCHEMA_CHANGED", "账户资料缺少 balance 或 credit_balance 余额字段"}
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
			groups = append(groups, group{remoteID, text(record["name"], remoteID), text(record["desc"], ""), "default", multiplier, []string{}})
		}
		profileRaw, _, err := a.remoteJSON(ctx, source.BaseURL, http.MethodGet, "/api/user/self", session, nil)
		if err != nil {
			return fmt.Errorf("读取账户余额失败: %w", err)
		}
		profileValue, err := unwrapEnvelope(profileRaw, source.Platform)
		if err != nil {
			return err
		}
		profile, ok := profileValue.(map[string]any)
		if !ok {
			return &apiError{502, "SCHEMA_CHANGED", "账户资料接口返回格式不兼容"}
		}
		if quota, ok := number(profile["quota"]); ok {
			v := quota / 500000
			balance = &v
		} else {
			return &apiError{502, "SCHEMA_CHANGED", "账户资料缺少 quota 余额字段"}
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
		if _, err = tx.ExecContext(ctx, `INSERT INTO source_balance_samples(source_id,balance,value_divisor,captured_at) VALUES($1,$2,$3,now())`, source.ID, value, source.ValueDivisor); err != nil {
			return err
		}
	}
	for _, item := range groups {
		var groupID string
		err = tx.QueryRowContext(ctx, `INSERT INTO source_groups(source_id,remote_id,name,description,multiplier,group_type,models,captured_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()) ON CONFLICT(source_id,remote_id) DO UPDATE SET name=excluded.name,description=excluded.description,multiplier=excluded.multiplier,group_type=excluded.group_type,models=excluded.models,captured_at=now() RETURNING id`, source.ID, item.RemoteID, item.Name, item.Description, item.Multiplier, item.GroupType, jsonValue(item.Models)).Scan(&groupID)
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
	_, err = tx.ExecContext(ctx, `INSERT INTO channels(source_id,source_key_id,source_group_id,state_reason) SELECT k.source_id,k.id,g.id,'等待首次探测' FROM source_keys k JOIN source_groups g ON g.source_id=k.source_id WHERE k.source_id=$1 AND k.production_authorized=true AND k.auto_generated=false ON CONFLICT DO NOTHING`, source.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func sourceProfileBalance(profile map[string]any) (float64, bool) {
	for _, key := range []string{"balance", "credit_balance", "creditBalance"} {
		if value, ok := number(profile[key]); ok {
			return value, true
		}
	}
	return 0, false
}

func sub2APIGroupMultiplier(record, rates map[string]any, remoteID string) *float64 {
	// /groups/rates contains the current user's custom group rates. Sub2API
	// bills with that value when present, otherwise it uses the group default.
	if value, ok := number(rates[remoteID]); ok {
		return &value
	}
	for _, field := range []string{"rate_multiplier", "rate", "ratio", "multiplier", "group_ratio"} {
		if value, ok := number(record[field]); ok {
			return &value
		}
	}
	return nil
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
		input.Concurrency = 1000
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
	groupRows, err := a.db.QueryContext(r.Context(), `SELECT g.id,g.remote_id,g.name,g.description,g.multiplier,g.group_type,g.models,g.captured_at,
		COALESCE(jsonb_agg(DISTINCT jsonb_build_object(
			'targetId',t.id,'targetName',t.name,'targetGroupId',tg.id,'targetGroupName',tg.name,
			'managedAccountId',m.id,'priority',m.priority,'concurrency',m.concurrency,
			'policyActive',EXISTS(SELECT 1 FROM policies p WHERE p.scope_type='TARGET_GROUP' AND p.scope_id=tg.id AND p.status='ACTIVE')
		)) FILTER (WHERE t.id IS NOT NULL AND tg.id IS NOT NULL),'[]'::jsonb)
		FROM source_groups g
		LEFT JOIN channels c ON c.source_group_id=g.id
		LEFT JOIN managed_accounts m ON m.channel_id=c.id
		LEFT JOIN targets t ON t.id=m.target_id
		LEFT JOIN managed_account_groups mag ON mag.managed_account_id=m.id
		LEFT JOIN target_groups tg ON tg.id=mag.target_group_id
		WHERE g.source_id=$1 GROUP BY g.id ORDER BY g.name`, id)
	if err != nil {
		return err
	}
	defer groupRows.Close()
	groups := []map[string]any{}
	for groupRows.Next() {
		var groupID, remoteID, name, description, groupType, models, deployments string
		var multiplier sql.NullFloat64
		var captured time.Time
		if err := groupRows.Scan(&groupID, &remoteID, &name, &description, &multiplier, &groupType, &models, &captured, &deployments); err != nil {
			return err
		}
		groups = append(groups, map[string]any{"id": groupID, "remoteId": remoteID, "name": name, "description": description, "multiplier": nullableFloat(multiplier), "groupType": groupType, "models": json.RawMessage(models), "deployments": json.RawMessage(deployments), "capturedAt": captured})
	}
	writeData(w, map[string]any{"source": source, "groups": groups})
	return nil
}

func nullableFloat(value sql.NullFloat64) any {
	if value.Valid {
		return value.Float64
	}
	return nil
}

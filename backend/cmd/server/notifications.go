package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type emailNotificationConfig struct {
	APIKey    string `json:"apiKey"`
	FromEmail string `json:"fromEmail"`
	ToEmail   string `json:"toEmail"`
}

type astrbotNotificationConfig struct {
	Endpoint      string `json:"endpoint"`
	APIKey        string `json:"apiKey"`
	RequestToken  string `json:"requestToken"`
	TargetGroupID string `json:"targetGroupID"`
}

type astrbotMultiplierChangePayload struct {
	Event          string `json:"event"`
	GroupName      string `json:"group_name"`
	Before         string `json:"before"`
	After          string `json:"after"`
	IdempotencyKey string `json:"idempotency_key"`
}

type astrbotMultiplierSnapshotPayload struct {
	Event          string `json:"event"`
	GroupName      string `json:"group_name"`
	Current        string `json:"current"`
	Confirmed      bool   `json:"confirmed"`
	IdempotencyKey string `json:"idempotency_key"`
}

type notificationChannelConfig struct {
	Type    string
	Email   emailNotificationConfig
	AstrBot astrbotNotificationConfig
}

func (a *App) listNotificationChannels(ctx context.Context) ([]map[string]any, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,name,type,recipient_hint,status,last_test_at,last_error,created_at FROM notification_channels ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, kind, hint, status, lastError string
		var lastTest sql.NullTime
		var created time.Time
		if err := rows.Scan(&id, &name, &kind, &hint, &status, &lastTest, &lastError, &created); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "name": name, "type": kind, "recipientHint": hint, "status": status, "lastTestAt": nullableTime(lastTest), "lastError": lastError, "createdAt": created})
	}
	return items, rows.Err()
}

func (a *App) createNotificationChannel(w http.ResponseWriter, r *http.Request) error {
	var input struct {
		Name          string `json:"name"`
		Type          string `json:"type"`
		APIKey        string `json:"apiKey"`
		FromEmail     string `json:"fromEmail"`
		ToEmail       string `json:"toEmail"`
		Endpoint      string `json:"endpoint"`
		RequestToken  string `json:"requestToken"`
		TargetGroupID string `json:"targetGroupID"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	input.Type = strings.ToUpper(strings.TrimSpace(input.Type))
	if input.Type == "" {
		input.Type = "EMAIL"
	}
	if input.Name == "" {
		return &apiError{400, "INVALID_NOTIFICATION", "请输入通知渠道名称"}
	}
	var encrypted []byte
	var recipientHint string
	var err error
	switch input.Type {
	case "EMAIL":
		if input.APIKey == "" || !strings.Contains(input.FromEmail, "@") || !strings.Contains(input.ToEmail, "@") {
			return &apiError{400, "INVALID_NOTIFICATION", "请完整填写 Resend 邮件配置"}
		}
		encrypted, err = a.encryptSecret([]byte(jsonValue(emailNotificationConfig{input.APIKey, input.FromEmail, input.ToEmail})))
		recipientHint = maskEmail(input.ToEmail)
	case "ASTRBOT":
		parsed, parseErr := url.Parse(strings.TrimSpace(input.Endpoint))
		if parseErr != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return &apiError{400, "INVALID_NOTIFICATION", "请输入有效的 AstrBot HTTP 接口地址"}
		}
		if input.APIKey == "" {
			return &apiError{400, "INVALID_NOTIFICATION", "请填写 AstrBot API Key"}
		}
		encrypted, err = a.encryptSecret([]byte(jsonValue(astrbotNotificationConfig{
			Endpoint: input.Endpoint, APIKey: input.APIKey, RequestToken: input.RequestToken, TargetGroupID: input.TargetGroupID,
		})))
		recipientHint = "AstrBot QQ 群"
	default:
		return &apiError{400, "INVALID_NOTIFICATION", "不支持的通知渠道类型"}
	}
	if err != nil {
		return err
	}
	id := uuid.NewString()
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO notification_channels(id,name,type,config_cipher,recipient_hint) VALUES($1,$2,$3,$4,$5)`, id, input.Name, input.Type, encrypted, recipientHint)
	if err != nil {
		return err
	}
	a.audit(r.Context(), "CREATE", "notification_channel", id, map[string]string{"type": input.Type, "recipient": recipientHint})
	writeData(w, map[string]string{"id": id})
	return nil
}

func maskEmail(value string) string {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return "****"
	}
	return mask(parts[0]) + "@" + parts[1]
}

func (a *App) notificationConfig(ctx context.Context, id string) (notificationChannelConfig, error) {
	var kind string
	var encrypted []byte
	if err := a.db.QueryRowContext(ctx, `SELECT type,config_cipher FROM notification_channels WHERE id=$1`, id).Scan(&kind, &encrypted); err != nil {
		return notificationChannelConfig{}, err
	}
	plain, err := a.decryptSecret(encrypted)
	if err != nil {
		return notificationChannelConfig{}, err
	}
	config := notificationChannelConfig{Type: strings.ToUpper(kind)}
	var target any
	switch config.Type {
	case "EMAIL":
		target = &config.Email
	case "ASTRBOT":
		target = &config.AstrBot
	default:
		return notificationChannelConfig{}, fmt.Errorf("unsupported notification type")
	}
	if json.Unmarshal(plain, target) != nil {
		return config, fmt.Errorf("invalid notification config")
	}
	return config, nil
}

func (a *App) testNotification(w http.ResponseWriter, r *http.Request, id string) error {
	config, err := a.notificationConfig(r.Context(), id)
	if err == sql.ErrNoRows {
		return &apiError{404, "NOTIFICATION_CHANNEL_NOT_FOUND", "通知渠道不存在"}
	}
	if err != nil {
		return err
	}
	var sendErr error
	responseData := map[string]any{"delivered": true}
	switch config.Type {
	case "EMAIL":
		sendErr = a.sendEmail(r.Context(), config.Email, "渠道管家测试通知", "Resend 邮件通知已连接成功。", "")
	case "ASTRBOT":
		var input struct {
			Confirmed bool   `json:"confirmed"`
			RequestID string `json:"requestID"`
		}
		if err := decodeJSON(r, &input); err != nil {
			return err
		}
		if !input.Confirmed {
			return &apiError{409, "ASTRBOT_CONFIRMATION_REQUIRED", "发送当前倍率前必须明确确认"}
		}
		requestID := strings.TrimSpace(input.RequestID)
		if requestID == "" {
			requestID = uuid.NewString()
		} else if _, err := uuid.Parse(requestID); err != nil {
			return &apiError{400, "INVALID_REQUEST_ID", "请求标识格式无效"}
		}
		payload, err := a.sendAstrBotCurrentMultiplier(r.Context(), config.AstrBot, id, requestID)
		responseData["groupName"] = payload.GroupName
		responseData["current"] = payload.Current
		sendErr = err
		status := "SUCCEEDED"
		errorMessage := ""
		if sendErr != nil {
			status = "FAILED"
			errorMessage = truncate(sendErr.Error(), 500)
		}
		_, _ = a.db.ExecContext(r.Context(), `INSERT INTO notification_deliveries(event_id,channel_id,status,error) VALUES(NULL,$1,$2,$3)`, id, status, errorMessage)
		_, _ = a.db.ExecContext(r.Context(), `UPDATE notification_channels SET last_test_at=now(),last_error=$2,updated_at=now() WHERE id=$1`, id, errorMessage)
		a.audit(r.Context(), "TEST_CURRENT_MULTIPLIER", "notification_channel", id, map[string]any{
			"target_group": config.AstrBot.TargetGroupID,
			"group":        payload.GroupName,
			"current":      payload.Current,
			"request_id":   requestID,
			"status":       status,
		})
	}
	err = sendErr
	if err != nil {
		_, _ = a.db.ExecContext(r.Context(), `UPDATE notification_channels SET last_test_at=now(),last_error=$2 WHERE id=$1`, id, truncate(err.Error(), 500))
		return err
	}
	_, err = a.db.ExecContext(r.Context(), `UPDATE notification_channels SET last_test_at=now(),last_error='' WHERE id=$1`, id)
	if err != nil {
		return err
	}
	writeData(w, responseData)
	return nil
}

func (a *App) sendEmail(ctx context.Context, config emailNotificationConfig, subject, content, idempotencyKey string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		var retryable bool
		retryable, lastErr = a.sendEmailOnce(ctx, config, subject, content, idempotencyKey)
		if lastErr == nil || !retryable {
			return lastErr
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 500 * time.Millisecond):
			}
		}
	}
	return lastErr
}

func (a *App) sendEmailOnce(ctx context.Context, config emailNotificationConfig, subject, content, idempotencyKey string) (bool, error) {
	payload, err := json.Marshal(map[string]any{"from": "渠道管家 <" + config.FromEmail + ">", "to": []string{config.ToEmail}, "subject": subject, "text": content})
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+config.APIKey)
	request.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := a.httpClient.Do(request)
	if err != nil {
		return true, fmt.Errorf("邮件服务暂时无法连接")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return true, fmt.Errorf("读取邮件服务响应失败")
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return false, fmt.Errorf("Resend 邮件配置无效，请检查 API Key 和发件域名")
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return true, fmt.Errorf("邮件服务暂时不可用 (%d)", response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("邮件发送被拒绝 (%d)，请检查发件人与收件人配置", response.StatusCode)
	}
	var result struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(body, &result) != nil || result.ID == "" {
		return false, fmt.Errorf("邮件服务返回了无法识别的数据")
	}
	return false, nil
}

func (a *App) sendAstrBotMultiplierChange(ctx context.Context, config astrbotNotificationConfig, groupName string, before, after float64, idempotencyKey string) error {
	return a.sendAstrBotPayload(ctx, config, astrbotMultiplierChangePayload{
		Event:          "dynamic_multiplier_changed",
		GroupName:      strings.TrimSpace(groupName),
		Before:         formatNotificationMultiplier(before),
		After:          formatNotificationMultiplier(after),
		IdempotencyKey: idempotencyKey,
	})
}

func (a *App) sendAstrBotCurrentMultiplier(ctx context.Context, config astrbotNotificationConfig, channelID, requestID string) (astrbotMultiplierSnapshotPayload, error) {
	payload := astrbotMultiplierSnapshotPayload{
		Event:          "current_multiplier_snapshot",
		Confirmed:      true,
		IdempotencyKey: fmt.Sprintf("current-multiplier/%s/%s/%s", config.TargetGroupID, requestID, channelID),
	}
	if config.TargetGroupID == "" {
		return payload, &apiError{409, "ASTRBOT_TARGET_GROUP_REQUIRED", "手动发送当前倍率必须配置目标分组"}
	}

	var targetID, remoteID, groupName string
	if err := a.db.QueryRowContext(ctx, `SELECT target_id,remote_id,name FROM target_groups WHERE id=$1`, config.TargetGroupID).Scan(&targetID, &remoteID, &groupName); err != nil {
		if err == sql.ErrNoRows {
			return payload, &apiError{404, "TARGET_GROUP_NOT_FOUND", "通知渠道配置的目标分组不存在"}
		}
		return payload, err
	}
	target, _, err := a.targetCredentials(ctx, targetID)
	if err != nil {
		return payload, err
	}
	requestCtx, cancel := timeoutContext(ctx)
	defer cancel()
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return payload, err
	}
	groups, err := a.fetchPaged(requestCtx, target.BaseURL, "/api/v1/admin/groups", session)
	if err != nil {
		return payload, err
	}
	var current *float64
	for _, record := range groups {
		id, ok := number(record["id"])
		if !ok || strconv.Itoa(int(id)) != remoteID {
			continue
		}
		if remoteName := strings.TrimSpace(text(record["name"], "")); remoteName != "" {
			groupName = remoteName
		}
		current = sub2APIGroupMultiplier(record, nil, remoteID)
		break
	}
	if current == nil || math.IsNaN(*current) || math.IsInf(*current, 0) || *current < 0 {
		return payload, &apiError{502, "TARGET_GROUP_MULTIPLIER_UNAVAILABLE", "远端未返回目标分组当前倍率"}
	}
	groupName = strings.TrimSpace(groupName)
	if groupName == "" || strings.ContainsAny(groupName, "\r\n") {
		return payload, &apiError{502, "TARGET_GROUP_NAME_INVALID", "远端目标分组名称无效"}
	}
	payload.GroupName = groupName
	payload.Current = formatNotificationMultiplier(*current)
	return payload, a.sendAstrBotPayload(ctx, config, payload)
}

func (a *App) sendAstrBotPayload(ctx context.Context, config astrbotNotificationConfig, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		var retryable bool
		retryable, lastErr = a.sendAstrBotOnce(ctx, config, body)
		if lastErr == nil || !retryable {
			return lastErr
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 500 * time.Millisecond):
			}
		}
	}
	return lastErr
}

func (a *App) sendAstrBotOnce(ctx context.Context, config astrbotNotificationConfig, payload []byte) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "ApiKey "+config.APIKey)
	request.Header.Set("Content-Type", "application/json")
	if config.RequestToken != "" {
		request.Header.Set("X-Junliai-Token", config.RequestToken)
	}
	response, err := a.httpClient.Do(request)
	if err != nil {
		return true, fmt.Errorf("AstrBot 暂时无法连接")
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		return true, fmt.Errorf("读取 AstrBot 响应失败")
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return false, fmt.Errorf("AstrBot API Key 或推送令牌无效")
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return true, fmt.Errorf("AstrBot 暂时不可用 (%d)", response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("AstrBot 拒绝了消息 (%d)", response.StatusCode)
	}
	var result struct {
		Status string `json:"status"`
		Data   struct {
			Sent         bool `json:"sent"`
			Deduplicated bool `json:"deduplicated"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &result) != nil || result.Status != "ok" || (!result.Data.Sent && !result.Data.Deduplicated) {
		return false, fmt.Errorf("AstrBot 未确认消息投递")
	}
	return false, nil
}

func (a *App) notifyEvent(ctx context.Context, eventID, severity, title, detail string) {
	var category, dedupeKey string
	var createdAt time.Time
	var resolvedAt sql.NullTime
	if err := a.db.QueryRowContext(ctx, `SELECT category,dedupe_key,created_at,resolved_at FROM events WHERE id=$1`, eventID).Scan(&category, &dedupeKey, &createdAt, &resolvedAt); err != nil {
		return
	}
	sourceID := sourceIDFromEvent(category, dedupeKey)
	if sourceID != "" && a.sourceIsManuallyUntrusted(ctx, sourceID) {
		return
	}
	if !a.eventEmailEnabled(ctx, category, severity) {
		return
	}
	guidance := eventEmailGuidanceFor(category, severity == "恢复")
	messageTime := createdAt
	if severity == "恢复" && resolvedAt.Valid {
		messageTime = resolvedAt.Time
	}
	if category == "SOURCE_BALANCE" && severity == "恢复" && sourceID != "" {
		detail = a.currentBalanceEmailDetail(ctx, sourceID, true, detail)
	} else if category == "SOURCE_BALANCE" && sourceID != "" {
		detail = a.currentBalanceEmailDetail(ctx, sourceID, false, detail)
	}
	subject := eventEmailSubject(severity, category, title, detail, guidance)
	content := formatEventEmail(eventID, severity, title, detail, messageTime, guidance)
	if category == "SOURCE_BALANCE" {
		content = formatBalanceEmail(severity, detail, messageTime)
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM notification_channels WHERE status='ACTIVE'`)
	if err != nil {
		return
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		config, configErr := a.notificationConfig(ctx, id)
		deliveryStatus := "SUCCEEDED"
		errorMessage := ""
		if configErr == nil && config.Type == "EMAIL" {
			configErr = a.sendEmail(ctx, config.Email, subject, content, fmt.Sprintf("event/%s/%s/%s", eventID, id, emailDeliveryKind(severity)))
		} else if configErr == nil {
			continue
		}
		if configErr != nil {
			deliveryStatus = "FAILED"
			errorMessage = truncate(configErr.Error(), 500)
		}
		_, _ = a.db.ExecContext(ctx, `INSERT INTO notification_deliveries(event_id,channel_id,status,error) VALUES($1,$2,$3,$4)`, eventID, id, deliveryStatus, errorMessage)
		_, _ = a.db.ExecContext(ctx, `UPDATE notification_channels SET last_error=$2,updated_at=now() WHERE id=$1`, id, errorMessage)
	}
}

func (a *App) notifyDynamicMultiplierChange(ctx context.Context, targetGroupID string, before, desired float64) {
	var groupName string
	if err := a.db.QueryRowContext(ctx, `SELECT name FROM target_groups WHERE id=$1`, targetGroupID).Scan(&groupName); err != nil {
		log.Printf("读取动态倍率目标分组名称失败 [%s]: %v", targetGroupID, err)
		return
	}
	idempotencyKey := fmt.Sprintf("dynamic-multiplier/%s/%s/%s", targetGroupID, formatNotificationMultiplier(before), formatNotificationMultiplier(desired))
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM notification_channels WHERE type='ASTRBOT' AND status='ACTIVE'`)
	if err != nil {
		log.Printf("读取 AstrBot 通知渠道失败: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			continue
		}
		config, configErr := a.notificationConfig(ctx, id)
		if configErr == nil && config.Type == "ASTRBOT" && config.AstrBot.TargetGroupID != "" && config.AstrBot.TargetGroupID != targetGroupID {
			continue
		}
		if configErr == nil {
			configErr = a.sendAstrBotMultiplierChange(ctx, config.AstrBot, groupName, before, desired, idempotencyKey+"/"+id)
		}
		deliveryStatus := "SUCCEEDED"
		errorMessage := ""
		if configErr != nil {
			deliveryStatus = "FAILED"
			errorMessage = truncate(configErr.Error(), 500)
		}
		_, _ = a.db.ExecContext(ctx, `INSERT INTO notification_deliveries(event_id,channel_id,status,error) VALUES(NULL,$1,$2,$3)`, id, deliveryStatus, errorMessage)
		_, _ = a.db.ExecContext(ctx, `UPDATE notification_channels SET last_error=$2,updated_at=now() WHERE id=$1`, id, errorMessage)
	}
}

func formatNotificationMultiplier(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64) + "x"
}

func (a *App) currentBalanceEmailDetail(ctx context.Context, sourceID string, replace bool, detail string) string {
	var name, baseURL, rechargeURL, accountHint, currency string
	var balance sql.NullFloat64
	if a.db.QueryRowContext(ctx, `SELECT name,base_url,recharge_url,username_hint,balance,balance_currency FROM sources WHERE id=$1`, sourceID).Scan(&name, &baseURL, &rechargeURL, &accountHint, &balance, &currency) != nil {
		return detail
	}
	if rechargeURL == "" {
		rechargeURL = baseURL
	}
	if replace {
		detail = "数据源：" + name
	}
	fields := []struct{ name, value string }{
		{"数据源", name},
		{"充值地址", rechargeURL},
		{"充值账号", accountHint},
	}
	if balance.Valid {
		fields = append(fields, struct{ name, value string }{"当前余额", fmt.Sprintf("%.2f %s", balance.Float64, currency)})
	}
	for _, field := range fields {
		if field.value != "" && eventDetailField(detail, field.name) == "" {
			detail += "\n" + field.name + "：" + field.value
		}
	}
	return strings.TrimSpace(detail)
}

func formatBalanceEmail(severity, detail string, eventTime time.Time) string {
	location := time.FixedZone("UTC+8", 8*60*60)
	lines := []string{}
	if balance := eventDetailField(detail, "当前余额"); balance != "" {
		lines = append(lines, "当前余额："+balance)
	}
	if threshold := eventDetailField(detail, "提醒阈值"); threshold != "" {
		lines = append(lines, "提醒阈值："+threshold)
	}
	if severity == "恢复" {
		lines = append(lines, "恢复时间："+eventTime.In(location).Format("2006-01-02 15:04 UTC+8"))
		return strings.Join(lines, "\n")
	}
	if recharge := eventDetailField(detail, "建议最低充值"); recharge != "" {
		lines = append(lines, "建议充值：至少 "+recharge)
	}
	if exhaustion := eventDetailField(detail, "预计耗尽时间"); exhaustion != "" {
		lines = append(lines, "预计耗尽："+exhaustion)
	}
	if account := eventDetailField(detail, "充值账号"); account != "" {
		lines = append(lines, "充值账号："+account)
	}
	if rechargeURL := eventDetailField(detail, "充值地址"); rechargeURL != "" {
		lines = append(lines, "", "前往充值："+rechargeURL)
	}
	return strings.Join(lines, "\n")
}

func eventEmailSubject(severity, category, title, detail string, guidance eventEmailGuidance) string {
	fallback := fmt.Sprintf("[%s][%s] %s", severity, guidance.Scene, title)
	if category != "SOURCE_BALANCE" {
		return fallback
	}
	source := strings.TrimSpace(strings.TrimRight(eventDetailField(detail, "数据源"), "。.!！"))
	if source == "" {
		return fallback
	}
	if severity == "恢复" {
		return fmt.Sprintf("[恢复] %s余额已恢复", source)
	}
	balance := eventDetailField(detail, "当前余额")
	if strings.Contains(title, "预计") {
		subject := fmt.Sprintf("[%s] %s余额预计不足", severity, source)
		if balance != "" {
			subject += "，当前 " + balance
		}
		if remaining := eventDetailField(detail, "预计剩余"); remaining != "" {
			subject += "，预计剩余 " + remaining
		}
		return subject
	}
	subject := fmt.Sprintf("[%s] %s余额不足", severity, source)
	if balance != "" {
		subject += "，当前 " + balance
	}
	return subject
}

func eventDetailField(detail, field string) string {
	prefix := field + "："
	for _, line := range strings.Split(detail, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func emailDeliveryKind(severity string) string {
	if severity == "恢复" {
		return "recovery"
	}
	return strings.ToLower(severity)
}

type eventEmailGuidance struct {
	Scene      string
	Impact     string
	Action     string
	Automation string
}

func (a *App) eventEmailEnabled(ctx context.Context, category, severity string) bool {
	if severity == "恢复" {
		return false
	}
	return category == "SOURCE_BALANCE" || category == "GROUP_AVAILABILITY"
}

func eventEmailGuidanceFor(category string, recovered bool) eventEmailGuidance {
	if recovered {
		return eventEmailGuidance{
			Scene:      eventScene(category),
			Impact:     "相关影响已经解除，系统已恢复正常状态。",
			Action:     "无需操作。如果业务侧仍有异常，请打开事件中心查看同一事件的最新状态。",
			Automation: "系统已自动关闭事件，并继续按正常周期监控。",
		}
	}
	switch category {
	case "SOURCE_BALANCE":
		return eventEmailGuidance{"账户余额不足", "该数据源下的托管渠道可能无法请求，相关目标分组可能停止调度。", "请登录邮件中所列的数据源账户充值。充值到账后无需手动恢复。", "系统会持续复检余额和渠道；确认可用后自动恢复调度并关闭事件，不发送恢复邮件。"}
	case "SOURCE_SCAN":
		return eventEmailGuidance{"数据源扫描失败", "余额、源分组和倍率暂时无法刷新，调度会继续使用最近一次有效数据。", "请检查对应源站是否在线、登录凭据是否失效，以及服务器到源站的网络是否可达。", "系统会按扫描周期自动重试，恢复后自动关闭事件。"}
	case "TARGET_SYNC":
		return eventEmailGuidance{"目标节点同步失败", "目标分组倍率或账号状态可能不是最新值，后续调度写入可能延迟。", "请检查目标节点是否在线，以及管理员账号和写入权限是否有效。", "系统会自动重试同步；成功后刷新缓存并关闭事件。"}
	case "GROUP_AVAILABILITY":
		return eventEmailGuidance{"目标分组无人可调度", "该目标分组当前没有可用托管账号，流量无法正常分配。", "请打开“调度运行”，展开该分组的未参与账号，按显示原因优先处理余额、倍率或渠道状态；如果是模型能力检测，前往“渠道雷达”手动检测或在确认风险后人工放行。", "系统最快每 15 秒复检待恢复账号；任一账号恢复后会自动重新参与调度，不会自动重复模型能力检测。"}
	case "ACTION_EXECUTION":
		return eventEmailGuidance{"远程调度写入失败", "系统判定的启停或优先级变更没有完整写入目标节点。", "请打开“调度运行”的执行记录，查看失败账号和远端返回原因后处理。", "系统会保留失败记录并继续执行后续有效调度；故障解除后自动恢复。"}
	case "ACCOUNT_PLATFORM_SYNC":
		return eventEmailGuidance{"账号平台校正失败", "托管账号的平台格式可能与目标分组不一致，该账号不会可靠参与调度。", "请检查目标分组的平台类型以及目标节点的账号创建权限，不要手动删除旧账号。", "系统会安全重建格式正确的账号，成功后切换绑定并清理旧账号。"}
	case "ACCOUNT_MODEL_SYNC":
		return eventEmailGuidance{"账号模型映射校正失败", "托管账号的模型映射没有按目标分组策略完整更新，相关模型可能无法正确调度。", "请检查目标节点的账号写入权限和远端返回错误，不要手动覆盖托管账号配置。", "系统会在下一轮目标同步时重试模型映射，成功后自动关闭事件。"}
	case "ACCOUNT_RATE_SYNC":
		return eventEmailGuidance{"账号倍率校正失败", "托管账号倍率与源分组不一致，目标节点上的计费和成本核算可能出现偏差。", "请检查目标节点是否在线，以及管理员账号和账号写入权限是否有效。", "系统会在下一轮目标同步时重试倍率校正，成功后自动关闭事件。"}
	default:
		return eventEmailGuidance{"生产运行异常", "相关业务可能受到影响，具体范围请查看邮件中的事件详情。", "请打开事件中心定位对应事件，并按详情中的对象和错误信息处理。", "系统会继续监控并在满足恢复条件后自动关闭事件。"}
	}
}

func eventScene(category string) string {
	guidance := eventEmailGuidanceFor(category, false)
	return guidance.Scene
}

func formatEventEmail(eventID, severity, title, detail string, createdAt time.Time, guidance eventEmailGuidance) string {
	location := time.FixedZone("UTC+8", 8*60*60)
	return fmt.Sprintf(`渠道管家生产通知

级别：%s
场景：%s
时间：%s
事件 ID：%s

发生了什么
%s
%s

影响
%s

你需要做什么
%s

系统会自动做什么
%s`, severity, guidance.Scene, createdAt.In(location).Format("2006-01-02 15:04:05 UTC+8"), eventID, title, strings.TrimSpace(detail), guidance.Impact, guidance.Action, guidance.Automation)
}

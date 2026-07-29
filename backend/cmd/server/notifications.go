package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type emailNotificationConfig struct {
	APIKey    string `json:"apiKey"`
	FromEmail string `json:"fromEmail"`
	ToEmail   string `json:"toEmail"`
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
	var input struct{ Name, APIKey, FromEmail, ToEmail string }
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	if input.Name == "" || input.APIKey == "" || !strings.Contains(input.FromEmail, "@") || !strings.Contains(input.ToEmail, "@") {
		return &apiError{400, "INVALID_NOTIFICATION", "请完整填写 Resend 邮件配置"}
	}
	encrypted, err := a.encryptSecret([]byte(jsonValue(emailNotificationConfig{input.APIKey, input.FromEmail, input.ToEmail})))
	if err != nil {
		return err
	}
	id := uuid.NewString()
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO notification_channels(id,name,config_cipher,recipient_hint) VALUES($1,$2,$3,$4)`, id, input.Name, encrypted, maskEmail(input.ToEmail))
	if err != nil {
		return err
	}
	a.audit(r.Context(), "CREATE", "notification_channel", id, map[string]string{"recipient": maskEmail(input.ToEmail)})
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

func (a *App) notificationConfig(ctx context.Context, id string) (emailNotificationConfig, error) {
	var encrypted []byte
	if err := a.db.QueryRowContext(ctx, `SELECT config_cipher FROM notification_channels WHERE id=$1`, id).Scan(&encrypted); err != nil {
		return emailNotificationConfig{}, err
	}
	plain, err := a.decryptSecret(encrypted)
	if err != nil {
		return emailNotificationConfig{}, err
	}
	var config emailNotificationConfig
	if json.Unmarshal(plain, &config) != nil {
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
	err = a.sendEmail(r.Context(), config, "渠道管家测试通知", "Resend 邮件通知已连接成功。", "")
	if err != nil {
		_, _ = a.db.ExecContext(r.Context(), `UPDATE notification_channels SET last_test_at=now(),last_error=$2 WHERE id=$1`, id, truncate(err.Error(), 500))
		return err
	}
	_, err = a.db.ExecContext(r.Context(), `UPDATE notification_channels SET last_test_at=now(),last_error='' WHERE id=$1`, id)
	if err != nil {
		return err
	}
	writeData(w, map[string]bool{"delivered": true})
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

func (a *App) notifyEvent(ctx context.Context, eventID, severity, title, detail string) {
	var category string
	var createdAt time.Time
	if err := a.db.QueryRowContext(ctx, `SELECT category,created_at FROM events WHERE id=$1`, eventID).Scan(&category, &createdAt); err != nil {
		return
	}
	if !a.eventEmailEnabled(ctx, category, severity) {
		return
	}
	guidance := eventEmailGuidanceFor(category, severity == "恢复")
	subject := fmt.Sprintf("[%s][%s] %s", severity, guidance.Scene, title)
	content := formatEventEmail(eventID, severity, title, detail, createdAt, guidance)
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
		if configErr == nil {
			configErr = a.sendEmail(ctx, config, subject, content, fmt.Sprintf("event/%s/%s/%s", eventID, id, emailDeliveryKind(severity)))
		}
		if configErr != nil {
			deliveryStatus = "FAILED"
			errorMessage = truncate(configErr.Error(), 500)
		}
		_, _ = a.db.ExecContext(ctx, `INSERT INTO notification_deliveries(event_id,channel_id,status,error) VALUES($1,$2,$3,$4)`, eventID, id, deliveryStatus, errorMessage)
		_, _ = a.db.ExecContext(ctx, `UPDATE notification_channels SET last_error=$2,updated_at=now() WHERE id=$1`, id, errorMessage)
	}
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

func eventEmailSetting(category string) string {
	switch category {
	case "SOURCE_BALANCE":
		return "email_alert_source_balance"
	case "SOURCE_SCAN":
		return "email_alert_source_scan"
	case "TARGET_SYNC":
		return "email_alert_target_sync"
	case "GROUP_AVAILABILITY":
		return "email_alert_group_availability"
	case "ACTION_EXECUTION":
		return "email_alert_action_execution"
	case "ACCOUNT_PLATFORM_SYNC":
		return "email_alert_platform_sync"
	default:
		return ""
	}
}

func (a *App) eventEmailEnabled(ctx context.Context, category, severity string) bool {
	if severity == "恢复" && !a.settingBoolDefault(ctx, "email_alert_recovery", true) {
		return false
	}
	setting := eventEmailSetting(category)
	return setting == "" || a.settingBoolDefault(ctx, setting, true)
}

func (a *App) settingBoolDefault(ctx context.Context, key string, fallback bool) bool {
	value, err := a.settingBool(ctx, key)
	if err != nil {
		return fallback
	}
	return value
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
		return eventEmailGuidance{"账户余额不足", "该数据源下的托管渠道可能无法请求，相关目标分组可能停止调度。", "请登录邮件中所列的数据源账户充值。充值到账后无需手动恢复。", "系统会持续复检余额和渠道；确认可用后自动恢复调度并发送恢复邮件。"}
	case "SOURCE_SCAN":
		return eventEmailGuidance{"数据源扫描失败", "余额、源分组和倍率暂时无法刷新，调度会继续使用最近一次有效数据。", "请检查对应源站是否在线、登录凭据是否失效，以及服务器到源站的网络是否可达。", "系统会按扫描周期自动重试，恢复后自动关闭事件。"}
	case "TARGET_SYNC":
		return eventEmailGuidance{"目标节点同步失败", "目标分组倍率或账号状态可能不是最新值，后续调度写入可能延迟。", "请检查目标节点是否在线，以及管理员账号和写入权限是否有效。", "系统会自动重试同步；成功后刷新缓存并关闭事件。"}
	case "GROUP_AVAILABILITY":
		return eventEmailGuidance{"目标分组无人可调度", "该目标分组当前没有可用托管账号，流量无法正常分配。", "请打开“调度运行”，展开该分组的未参与账号，按显示原因优先处理余额、倍率或渠道状态。", "系统最快每 15 秒复检待恢复账号；任一账号恢复后会自动重新参与调度。"}
	case "ACTION_EXECUTION":
		return eventEmailGuidance{"远程调度写入失败", "系统判定的启停或优先级变更没有完整写入目标节点。", "请打开“调度运行”的执行记录，查看失败账号和远端返回原因后处理。", "系统会保留失败记录并继续执行后续有效调度；故障解除后自动恢复。"}
	case "ACCOUNT_PLATFORM_SYNC":
		return eventEmailGuidance{"账号平台校正失败", "托管账号的平台格式可能与目标分组不一致，该账号不会可靠参与调度。", "请检查目标分组的平台类型以及目标节点的账号创建权限，不要手动删除旧账号。", "系统会安全重建格式正确的账号，成功后切换绑定并清理旧账号。"}
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

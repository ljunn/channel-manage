package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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
	err = a.sendEmail(r.Context(), config, "渠道管家测试通知", "Resend 邮件通知已连接成功。")
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

func (a *App) sendEmail(ctx context.Context, config emailNotificationConfig, subject, content string) error {
	_, _, err := a.remoteJSON(ctx, "https://api.resend.com", http.MethodPost, "/emails", remoteSession{Authorization: "Bearer " + config.APIKey}, map[string]any{"from": config.FromEmail, "to": []string{config.ToEmail}, "subject": subject, "text": content})
	return err
}

func (a *App) notifyEvent(ctx context.Context, eventID, severity, title, detail string) {
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
			configErr = a.sendEmail(ctx, config, "["+severity+"] "+title, detail)
		}
		if configErr != nil {
			deliveryStatus = "FAILED"
			errorMessage = truncate(configErr.Error(), 500)
		}
		_, _ = a.db.ExecContext(ctx, `INSERT INTO notification_deliveries(event_id,channel_id,status,error) VALUES($1,$2,$3,$4)`, eventID, id, deliveryStatus, errorMessage)
	}
}

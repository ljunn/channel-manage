package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const firstTokenRecoveryTimeout = 65 * time.Second

func isSlowFirstTokenQuarantine(state, reason string) bool {
	return state == "QUARANTINED" && strings.Contains(reason, "真实业务首 Token")
}

func slowRecoveryIntervalSeconds(failures, recoverySuccesses int) int {
	if recoverySuccesses > 0 {
		return 30
	}
	switch failures {
	case 0:
		return 60
	case 1:
		return 5 * 60
	case 2:
		return 30 * 60
	case 3:
		return 2 * 60 * 60
	case 4:
		return 6 * 60 * 60
	default:
		return 24 * 60 * 60
	}
}

func selectFirstTokenProbeModel(models []string) string {
	excluded := []string{"auto-review", "embedding", "rerank", "moderation", "whisper", "audio", "realtime", "tts", "image", "dall-e", "video"}
	for _, model := range models {
		value := strings.ToLower(strings.TrimSpace(model))
		if value == "" {
			continue
		}
		blocked := false
		for _, marker := range excluded {
			if strings.Contains(value, marker) {
				blocked = true
				break
			}
		}
		if !blocked {
			return model
		}
	}
	return ""
}

func (a *App) measureFirstToken(ctx context.Context, baseURL, key, model string) (int, error) {
	payload, err := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": "Reply with OK."}},
		"max_tokens": 1,
		"stream":     true,
	})
	if err != nil {
		return 0, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, firstTokenRecoveryTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, strings.TrimSuffix(baseURL, "/")+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("User-Agent", "channel-manage/"+Version)

	client := *a.httpClient
	client.Timeout = firstTokenRecoveryTimeout
	if transport, ok := a.httpClient.Transport.(*http.Transport); ok {
		cloned := transport.Clone()
		cloned.ResponseHeaderTimeout = firstTokenRecoveryTimeout
		client.Transport = cloned
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return int(time.Since(started).Milliseconds()), err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return int(time.Since(started).Milliseconds()), fmt.Errorf("抽样请求失败 (%d): %s", response.StatusCode, truncate(strings.TrimSpace(string(data)), 200))
	}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 1<<20))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if line == "" || line == "[DONE]" {
				continue
			}
		}
		return int(time.Since(started).Milliseconds()), nil
	}
	if err = scanner.Err(); err != nil {
		return int(time.Since(started).Milliseconds()), err
	}
	return int(time.Since(started).Milliseconds()), fmt.Errorf("抽样响应没有返回有效流式数据")
}

func (a *App) probeSlowFirstTokenRecovery(ctx context.Context, id, sourceID, sourceName, sourceBase, keyName, groupName, key, modelsJSON string) error {
	models := []string{}
	_ = json.Unmarshal([]byte(modelsJSON), &models)
	model := selectFirstTokenProbeModel(models)
	firstTokenMs := 0
	var requestErr error
	if model == "" {
		requestErr = fmt.Errorf("慢首响抽样没有可用的文本模型")
	} else {
		firstTokenMs, requestErr = a.measureFirstToken(ctx, sourceBase, key, model)
	}
	success := requestErr == nil && firstTokenMs <= maxFirstTokenMs
	errorType, summary := classifyProbeFailure(requestErr)
	if requestErr != nil && errorType != "BALANCE_EXHAUSTED" {
		summary = truncate(requestErr.Error(), 200)
	}
	if requestErr == nil && !success {
		errorType = "FIRST_TOKEN_TOO_SLOW"
		summary = fmt.Sprintf("抽样首 Token %.2f 秒超过 60 秒", float64(firstTokenMs)/1000)
	}
	if success {
		summary = fmt.Sprintf("抽样首 Token %.2f 秒", float64(firstTokenMs)/1000)
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO probe_runs(channel_id,kind,success,latency_ms,first_token_ms,error_type,response_summary,finished_at) VALUES($1,'RECOVERY',$2,$3,$3,$4,$5,now())`, id, success, firstTokenMs, truncate(errorType, 100), summary)
	if err != nil {
		return err
	}
	recoverySuccesses := 0
	if success {
		rows, queryErr := tx.QueryContext(ctx, `SELECT success FROM probe_runs WHERE channel_id=$1 AND kind='RECOVERY' ORDER BY started_at DESC LIMIT $2`, id, recoverySuccessSamples)
		if queryErr != nil {
			return queryErr
		}
		for rows.Next() {
			var passed bool
			if err = rows.Scan(&passed); err != nil {
				rows.Close()
				return err
			}
			if !passed {
				break
			}
			recoverySuccesses++
		}
		if err = rows.Close(); err != nil {
			return err
		}
	}
	recovered := success && recoverySuccesses >= recoverySuccessSamples
	if recovered {
		_, err = tx.ExecContext(ctx, `UPDATE channels SET lifecycle_state='HEALTHY',state_reason=$2,score=100,consecutive_failures=0,last_probe_at=now(),state_changed_at=now() WHERE id=$1`, id, fmt.Sprintf("真实业务首 Token 连续 %d 次抽样通过，已恢复", recoverySuccessSamples))
	} else if success {
		_, err = tx.ExecContext(ctx, `UPDATE channels SET lifecycle_state='QUARANTINED',state_reason=$2,consecutive_failures=0,last_probe_at=now() WHERE id=$1`, id, fmt.Sprintf("真实业务首 Token 隔离抽样：连续通过 %d/%d，本次 %.2f 秒", recoverySuccesses, recoverySuccessSamples, float64(firstTokenMs)/1000))
	} else {
		nextFailures := 0
		_ = tx.QueryRowContext(ctx, `SELECT consecutive_failures+1 FROM channels WHERE id=$1`, id).Scan(&nextFailures)
		nextInterval := slowRecoveryIntervalSeconds(nextFailures, 0)
		reason := fmt.Sprintf("真实业务首 Token 隔离抽样失败：%s；下次约 %s后检查", summary, recoveryIntervalText(nextInterval))
		_, err = tx.ExecContext(ctx, `UPDATE channels SET lifecycle_state='QUARANTINED',state_reason=$2,score=0,consecutive_failures=consecutive_failures+1,last_probe_at=now() WHERE id=$1`, id, reason)
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if errorType == "BALANCE_EXHAUSTED" {
		detail := fmt.Sprintf("数据源：%s\n渠道：%s / %s\n源站明确返回账户可用余额不足。", sourceName, groupName, keyName)
		a.openEvent(ctx, "P0", "SOURCE_BALANCE", "源站账户余额不足", detail, "source-balance:"+sourceID)
	} else if recovered {
		a.evaluateSourceBalance(ctx, sourceID)
	}
	return requestErr
}

func recoveryIntervalText(seconds int) string {
	switch {
	case seconds < 60:
		return fmt.Sprintf("%d 秒", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%d 分钟", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%d 小时", seconds/3600)
	default:
		return fmt.Sprintf("%d 天", seconds/86400)
	}
}

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	poolModeRetryStatusCodesSetting = "pool_mode_retry_status_codes"
	defaultPoolModeRetryStatusCodes = "401,403,429"
)

// parsePoolModeRetryStatusCodes validates the comma-separated HTTP status code
// setting used by managed accounts running in pool mode. Empty input means the
// target API default (401, 403, 429).
func parsePoolModeRetryStatusCodes(configured string) ([]int, error) {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		configured = defaultPoolModeRetryStatusCodes
	}
	seen := map[int]struct{}{}
	codes := make([]int, 0, 8)
	for _, part := range strings.Split(configured, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, &apiError{400, "INVALID_POOL_MODE_RETRY_STATUS_CODES", "同账号重试状态码必须是以英文逗号分隔的 100-599 HTTP 状态码"}
		}
		code, err := strconv.Atoi(part)
		if err != nil || code < 100 || code > 599 {
			return nil, &apiError{400, "INVALID_POOL_MODE_RETRY_STATUS_CODES", "同账号重试状态码必须是 100-599 的 HTTP 状态码"}
		}
		if _, exists := seen[code]; exists {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
	}
	sort.Ints(codes)
	return codes, nil
}

func formatPoolModeRetryStatusCodes(codes []int) string {
	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		parts = append(parts, strconv.Itoa(code))
	}
	return strings.Join(parts, ",")
}

func poolModeRetryStatusCodesHash(codes []int) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(formatPoolModeRetryStatusCodes(codes))))
}

// loadPoolModeRetryStatusCodes intentionally falls back to the target API
// default if an older or malformed database value is encountered. A bad
// runtime setting must never make account creation fail unexpectedly.
func (a *App) loadPoolModeRetryStatusCodes(ctx context.Context) []int {
	defaultCodes, _ := parsePoolModeRetryStatusCodes("")
	if a.db == nil {
		return defaultCodes
	}
	var raw string
	if err := a.db.QueryRowContext(ctx, `SELECT value::text FROM settings WHERE key=$1`, poolModeRetryStatusCodesSetting).Scan(&raw); err != nil {
		return defaultCodes
	}
	var configured string
	if err := json.Unmarshal([]byte(raw), &configured); err != nil {
		return defaultCodes
	}
	codes, err := parsePoolModeRetryStatusCodes(configured)
	if err != nil {
		return defaultCodes
	}
	return codes
}

// Apply a saved retry-policy change to existing managed accounts immediately,
// without waiting for the next periodic target sync.
func (a *App) refreshPoolModeRetryStatusCodes() {
	rows, err := a.db.QueryContext(context.Background(), `SELECT id FROM targets WHERE write_enabled=true`)
	if err != nil {
		log.Printf("读取目标节点以同步池模式重试状态码失败: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var targetID string
		if err = rows.Scan(&targetID); err != nil {
			log.Printf("读取目标节点以同步池模式重试状态码失败: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		target, _, targetErr := a.targetCredentials(ctx, targetID)
		if targetErr == nil {
			session, authErr := a.authenticateTarget(ctx, target, true)
			if authErr == nil {
				a.syncManagedAccountModelMappings(ctx, target, session)
			} else {
				log.Printf("目标节点 %s 同步池模式重试状态码认证失败: %v", target.Name, authErr)
			}
		} else {
			log.Printf("读取目标节点 %s 以同步池模式重试状态码失败: %v", targetID, targetErr)
		}
		cancel()
	}
}

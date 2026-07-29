package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type businessMetricBucket struct {
	ChannelID  string
	Window     time.Time
	Requests   int
	Errors     int
	Timeouts   int
	RateLimits int
	Durations  []int
	FirstToken []int
}

func (a *App) syncDueTargetMetrics(ctx context.Context) {
	rows, err := a.db.QueryContext(ctx, `SELECT DISTINCT t.id FROM targets t JOIN managed_accounts m ON m.target_id=t.id WHERE t.status='ONLINE' AND (t.last_metrics_at IS NULL OR t.last_metrics_at<now()-interval '1 minute')`)
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
		if err := a.syncTargetMetrics(ctx, id); err != nil {
			logDatabaseError("同步目标业务指标", err)
			a.openEvent(ctx, "P2", "TARGET_LOG", "目标业务日志不可用", err.Error(), "target-log:"+id)
		} else {
			a.resolveEvent(ctx, "target-log:"+id)
		}
	}
}

func (a *App) syncTargetMetrics(ctx context.Context, targetID string) error {
	target, _, err := a.targetCredentials(ctx, targetID)
	if err != nil {
		return err
	}
	requestCtx, cancel := timeoutContext(ctx)
	defer cancel()
	session, err := a.authenticateTarget(requestCtx, target, true)
	if err != nil {
		return err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT remote_id,channel_id FROM managed_accounts WHERE target_id=$1 AND remote_id<>''`, targetID)
	if err != nil {
		return err
	}
	defer rows.Close()
	bindings := map[string]string{}
	for rows.Next() {
		var remoteID, channelID string
		if err := rows.Scan(&remoteID, &channelID); err != nil {
			return err
		}
		bindings[remoteID] = channelID
	}
	to := time.Now().UTC()
	from := to.Add(-7 * time.Minute)
	buckets := map[string]*businessMetricBucket{}
	for remoteID, channelID := range bindings {
		path := fmt.Sprintf("/api/v1/admin/ops/requests?start_time=%s&end_time=%s&kind=all&sort=created_at_desc&account_id=%s", from.Format(time.RFC3339), to.Format(time.RFC3339), remoteID)
		items, err := a.fetchPaged(requestCtx, target.BaseURL, path, session)
		if err != nil {
			return err
		}
		for _, item := range items {
			accountNumber, ok := number(item["account_id"])
			if !ok || strconv.Itoa(int(accountNumber)) != remoteID {
				continue
			}
			created, err := time.Parse(time.RFC3339, text(item["created_at"], ""))
			if err != nil || created.Before(from) || created.After(to) {
				continue
			}
			window := created.UTC().Truncate(time.Minute)
			key := channelID + ":" + window.Format(time.RFC3339)
			bucket := buckets[key]
			if bucket == nil {
				bucket = &businessMetricBucket{ChannelID: channelID, Window: window}
				buckets[key] = bucket
			}
			bucket.Requests++
			statusCode, _ := number(item["status_code"])
			kind := strings.ToLower(text(item["kind"], ""))
			errorType := strings.ToLower(text(item["error_type"], ""))
			failed := kind == "error" || statusCode >= 400
			if failed {
				bucket.Errors++
			}
			if failed && (statusCode == 408 || statusCode == 504 || strings.Contains(errorType, "timeout")) {
				bucket.Timeouts++
			}
			if failed && statusCode == 429 {
				bucket.RateLimits++
			}
			if value, ok := number(item["duration_ms"]); ok && value >= 0 {
				bucket.Durations = append(bucket.Durations, int(value))
			}
			if value, ok := number(item["first_token_ms"]); ok && value >= 0 {
				bucket.FirstToken = append(bucket.FirstToken, int(value))
			}
		}
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, bucket := range buckets {
		_, err = tx.ExecContext(ctx, `INSERT INTO metric_buckets(channel_id,window_start,requests,errors,timeouts,rate_limited,p50_ms,p95_ms,first_token_p95_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(channel_id,window_start) DO UPDATE SET requests=excluded.requests,errors=excluded.errors,timeouts=excluded.timeouts,rate_limited=excluded.rate_limited,p50_ms=excluded.p50_ms,p95_ms=excluded.p95_ms,first_token_p95_ms=excluded.first_token_p95_ms`, bucket.ChannelID, bucket.Window, bucket.Requests, bucket.Errors, bucket.Timeouts, bucket.RateLimits, percentile(bucket.Durations, .5), percentile(bucket.Durations, .95), percentile(bucket.FirstToken, .95))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE targets SET last_metrics_at=now() WHERE id=$1`, targetID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func percentile(values []int, ratio float64) any {
	if len(values) == 0 {
		return nil
	}
	sort.Ints(values)
	index := int(float64(len(values))*ratio+.999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}

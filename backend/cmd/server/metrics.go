package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	recentBusinessLatencySamples = 50
	businessLatencyWindow        = 5 * time.Minute
	cacheMetricWindow            = 5 * time.Minute
)

type businessMetricBucket struct {
	ManagedID  string
	ChannelID  string
	Window     time.Time
	Requests   int
	Errors     int
	Timeouts   int
	RateLimits int
	Durations  []int
	FirstToken []int
}

func businessErrorConfirmed(requests, errors, minSamples, errorThreshold int) bool {
	return requests >= minSamples && requests > 0 && errors*100 >= requests*errorThreshold
}

func businessErrorConfirmedAcrossWindows(currentRequests, currentErrors, previousRequests, previousErrors, minSamples, errorThreshold int) bool {
	return businessErrorConfirmed(currentRequests, currentErrors, minSamples, errorThreshold) && businessErrorConfirmed(previousRequests, previousErrors, minSamples, errorThreshold)
}

type businessLatencySnapshot struct {
	FirstTokenP50Ms int
	FirstTokenP90Ms int
	Samples         int
	LatestAt        time.Time
	Model           string
}

type targetMetricBinding struct {
	ManagedID  string
	RemoteID   string
	ChannelID  string
	ProbeModel string
}

type cacheMetricBucket struct {
	ManagedID, Model, RequestType, Source string
	Window                                time.Time
	Requests, CacheHits                   int
	InputTokens                           int64
	CacheReadTokens                       int64
	CacheCreationTokens                   int64
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
	authCtx, cancel := timeoutContext(ctx)
	session, err := a.authenticateTarget(authCtx, target, true)
	cancel()
	if err != nil {
		return err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.remote_id,m.channel_id,COALESCE(min(v.config->>'probeModel'),'')
		FROM managed_accounts m
		LEFT JOIN managed_account_groups mg ON mg.managed_account_id=m.id
		LEFT JOIN policies p ON p.scope_type='TARGET_GROUP' AND p.scope_id=mg.target_group_id AND p.status='ACTIVE'
		LEFT JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version
		WHERE m.target_id=$1 AND m.remote_id<>'' GROUP BY m.id`, targetID)
	if err != nil {
		return err
	}
	defer rows.Close()
	bindings := []targetMetricBinding{}
	for rows.Next() {
		var binding targetMetricBinding
		if err := rows.Scan(&binding.ManagedID, &binding.RemoteID, &binding.ChannelID, &binding.ProbeModel); err != nil {
			return err
		}
		bindings = append(bindings, binding)
	}
	to := time.Now().UTC()
	from := to.Add(-7 * time.Minute)
	cacheWindowEnd := to.Truncate(cacheMetricWindow)
	cacheFrom := cacheWindowEnd.Add(-cacheMetricWindow)
	buckets := map[string]*businessMetricBucket{}
	cacheBuckets := map[string]*cacheMetricBucket{}
	managedIDs := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		managedIDs = append(managedIDs, binding.ManagedID)
	}
	latencySnapshots := map[string]businessLatencySnapshot{}
	for _, binding := range bindings {
		usageCtx, usageCancel := timeoutContext(ctx)
		usageItems, usageErr := a.fetchRecentUsageRecords(usageCtx, target.BaseURL, binding.RemoteID, cacheFrom, to, session)
		usageCancel()
		if usageErr != nil {
			return usageErr
		}
		latencySnapshots[binding.ManagedID] = businessLatencyFromUsageItems(usageItems, binding.RemoteID, binding.ProbeModel, to)
		for _, item := range usageItems {
			created, err := parseRemoteTimestamp(text(item["created_at"], ""))
			if err != nil || created.Before(cacheFrom) || !created.Before(cacheWindowEnd) {
				continue
			}
			cache, ok := extractCacheUsage(item)
			if !ok {
				continue
			}
			model := strings.TrimSpace(text(item["model"], "UNKNOWN"))
			requestType := strings.ToLower(strings.TrimSpace(text(item["request_type"], "unknown")))
			window := created.UTC().Truncate(cacheMetricWindow)
			key := strings.Join([]string{binding.ManagedID, model, requestType, window.Format(time.RFC3339)}, ":")
			bucket := cacheBuckets[key]
			if bucket == nil {
				bucket = &cacheMetricBucket{ManagedID: binding.ManagedID, Model: model, RequestType: requestType, Source: "TARGET_USAGE", Window: window}
				cacheBuckets[key] = bucket
			}
			bucket.Requests++
			bucket.InputTokens += cache.InputTokens
			bucket.CacheReadTokens += cache.CacheReadTokens
			bucket.CacheCreationTokens += cache.CacheCreationTokens
			if cache.CacheReadTokens > 0 {
				bucket.CacheHits++
			}
		}

		path := fmt.Sprintf("/api/v1/admin/ops/requests?start_time=%s&end_time=%s&kind=all&sort=created_at_desc&account_id=%s", from.Format(time.RFC3339), to.Format(time.RFC3339), binding.RemoteID)
		requestCtx, requestCancel := timeoutContext(ctx)
		items, err := a.fetchPaged(requestCtx, target.BaseURL, path, session)
		requestCancel()
		if err != nil {
			return err
		}
		seenRequests := map[string]struct{}{}
		for _, item := range items {
			requestID := remoteRequestID(item["request_id"])
			if requestID == "" {
				requestID = remoteRequestID(item["requestId"])
			}
			if requestID == "" {
				requestID = remoteRequestID(item["id"])
			}
			if requestID != "" {
				if _, exists := seenRequests[requestID]; exists {
					continue
				}
				seenRequests[requestID] = struct{}{}
			}
			accountNumber, ok := number(item["account_id"])
			if !ok || strconv.Itoa(int(accountNumber)) != binding.RemoteID {
				continue
			}
			created, err := parseRemoteTimestamp(text(item["created_at"], ""))
			if err != nil || created.Before(from) || created.After(to) {
				continue
			}
			window := created.UTC().Truncate(time.Minute)
			key := binding.ManagedID + ":" + window.Format(time.RFC3339)
			bucket := buckets[key]
			if bucket == nil {
				bucket = &businessMetricBucket{ManagedID: binding.ManagedID, ChannelID: binding.ChannelID, Window: window}
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
	for managedID, snapshot := range latencySnapshots {
		if snapshot.Samples == 0 {
			_, err = tx.ExecContext(ctx, `UPDATE managed_accounts SET business_first_token_ms=NULL,business_first_token_p90_ms=NULL,business_latency_samples=0,business_latency_at=NULL,business_latency_model='' WHERE id=$1`, managedID)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE managed_accounts SET business_first_token_ms=$2,business_first_token_p90_ms=$3,business_latency_samples=$4,business_latency_at=$5,business_latency_model=$6 WHERE id=$1`, managedID, snapshot.FirstTokenP50Ms, snapshot.FirstTokenP90Ms, snapshot.Samples, snapshot.LatestAt, snapshot.Model)
		}
		if err != nil {
			return err
		}
	}
	for _, bucket := range buckets {
		firstTokenP95 := percentile(bucket.FirstToken, .95)
		_, err = tx.ExecContext(ctx, `INSERT INTO metric_buckets(managed_account_id,channel_id,window_start,requests,errors,timeouts,rate_limited,p50_ms,p95_ms,first_token_p95_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(managed_account_id,window_start) DO UPDATE SET channel_id=excluded.channel_id,requests=excluded.requests,errors=excluded.errors,timeouts=excluded.timeouts,rate_limited=excluded.rate_limited,p50_ms=excluded.p50_ms,p95_ms=excluded.p95_ms,first_token_p95_ms=excluded.first_token_p95_ms`, bucket.ManagedID, bucket.ChannelID, bucket.Window, bucket.Requests, bucket.Errors, bucket.Timeouts, bucket.RateLimits, percentile(bucket.Durations, .5), percentile(bucket.Durations, .95), firstTokenP95)
		if err != nil {
			return err
		}
	}
	for _, bucket := range cacheBuckets {
		_, err = tx.ExecContext(ctx, `INSERT INTO managed_account_cache_metrics(managed_account_id,model,request_type,window_start,observed_requests,cache_hit_requests,input_tokens,cache_read_tokens,cache_creation_tokens,metric_source)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT(managed_account_id,model,request_type,window_start) DO UPDATE SET observed_requests=excluded.observed_requests,cache_hit_requests=excluded.cache_hit_requests,input_tokens=excluded.input_tokens,cache_read_tokens=excluded.cache_read_tokens,cache_creation_tokens=excluded.cache_creation_tokens,metric_source=excluded.metric_source`, bucket.ManagedID, bucket.Model, bucket.RequestType, bucket.Window, bucket.Requests, bucket.CacheHits, bucket.InputTokens, bucket.CacheReadTokens, bucket.CacheCreationTokens, bucket.Source)
		if err != nil {
			return err
		}
	}
	if err = a.updateManagedAccountCacheSnapshots(ctx, tx, cacheBuckets, managedIDs, cacheWindowEnd); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM managed_account_cache_metrics WHERE window_start<now()-interval '7 days'`); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE targets SET last_metrics_at=now() WHERE id=$1`, targetID)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *App) updateManagedAccountCacheSnapshots(ctx context.Context, tx *sql.Tx, buckets map[string]*cacheMetricBucket, managedIDs []string, evaluatedAt time.Time) error {
	selected := map[string]*cacheMetricBucket{}
	for _, bucket := range buckets {
		current := selected[bucket.ManagedID]
		bucketTokens := bucket.InputTokens + bucket.CacheCreationTokens + bucket.CacheReadTokens
		currentTokens := int64(-1)
		if current != nil {
			currentTokens = current.InputTokens + current.CacheCreationTokens + current.CacheReadTokens
		}
		if current == nil || bucketTokens > currentTokens || (bucketTokens == currentTokens && bucket.Model+":"+bucket.RequestType < current.Model+":"+current.RequestType) {
			selected[bucket.ManagedID] = bucket
		}
	}
	for _, managedID := range managedIDs {
		item := selected[managedID]
		if item == nil {
			continue
		}
		score, totalInput, ok := cacheReadRatio(item.InputTokens, item.CacheCreationTokens, item.CacheReadTokens)
		if !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE managed_accounts SET
			cache_bad_snapshots=CASE WHEN cache_metric_model<>$7 OR cache_metric_request_type<>$8 THEN 0 ELSE cache_bad_snapshots END,
			cache_good_snapshots=CASE WHEN cache_metric_model<>$7 OR cache_metric_request_type<>$8 THEN 0 ELSE cache_good_snapshots END,
			cache_evaluated_at=CASE WHEN cache_metric_model<>$7 OR cache_metric_request_type<>$8 THEN NULL ELSE cache_evaluated_at END,
			cache_score=$2,cache_samples=$3,cache_input_tokens=$4,cache_read_tokens=$5,cache_metric_source='TARGET_USAGE',cache_metric_at=$6,cache_metric_model=$7,cache_metric_request_type=$8,updated_at=now()
			WHERE id=$1`, managedID, score, item.Requests, totalInput, item.CacheReadTokens, evaluatedAt, item.Model, item.RequestType); err != nil {
			return err
		}
	}
	return nil
}

func cacheReadRatio(input, created, read int64) (float64, int64, bool) {
	total := input + created + read
	if input < 0 || created < 0 || read < 0 || total <= 0 {
		return 0, total, false
	}
	return math.Max(0, math.Min(1, float64(read)/float64(total))), total, true
}

type cacheUsage struct {
	InputTokens, CacheReadTokens, CacheCreationTokens int64
}

func extractCacheUsage(item map[string]any) (cacheUsage, bool) {
	input, inputOK := integerValue(item["input_tokens"])
	read, readOK := integerValue(item["cache_read_tokens"])
	created, createdOK := integerValue(item["cache_creation_tokens"])
	if !inputOK || !readOK || !createdOK {
		return cacheUsage{}, false
	}
	return cacheUsage{InputTokens: input, CacheReadTokens: read, CacheCreationTokens: created}, true
}

func integerValue(value any) (int64, bool) {
	numberValue, ok := number(value)
	if !ok || numberValue < 0 || math.Trunc(numberValue) != numberValue {
		return 0, false
	}
	return int64(numberValue), true
}

func (a *App) fetchRecentUsageRecords(ctx context.Context, baseURL, remoteID string, from, to time.Time, session remoteSession) ([]map[string]any, error) {
	const pageSize = 100
	basePath := "/api/v1/admin/usage?account_id=" + url.QueryEscape(remoteID) +
		"&sort_by=created_at&sort_order=desc&timezone=UTC&start_date=" + from.UTC().Format("2006-01-02") +
		"&end_date=" + to.UTC().Format("2006-01-02")
	result := []map[string]any{}
	for page := 1; page <= 100; page++ {
		path := basePath + "&page=" + strconv.Itoa(page) + "&page_size=" + strconv.Itoa(pageSize)
		raw, _, err := a.remoteJSON(ctx, baseURL, http.MethodGet, path, session, nil)
		if err != nil {
			return nil, err
		}
		value, err := unwrapEnvelope(raw, "SUB2API")
		if err != nil {
			return nil, err
		}
		record, ok := value.(map[string]any)
		if !ok {
			return nil, &apiError{502, "SCHEMA_CHANGED", "目标节点用量分页格式不兼容"}
		}
		items, ok := record["items"].([]any)
		if !ok {
			return nil, &apiError{502, "SCHEMA_CHANGED", "目标节点用量列表格式不兼容"}
		}
		reachedCutoff := false
		for _, rawItem := range items {
			item, ok := rawItem.(map[string]any)
			if !ok {
				continue
			}
			created, parseErr := parseRemoteTimestamp(text(item["created_at"], ""))
			if parseErr != nil {
				continue
			}
			if created.Before(from) {
				reachedCutoff = true
				continue
			}
			if created.After(to) {
				continue
			}
			result = append(result, item)
		}
		pages, _ := number(record["pages"])
		if reachedCutoff || len(items) == 0 || page >= int(pages) {
			break
		}
	}
	return result, nil
}

func (a *App) fetchRecentBusinessLatency(ctx context.Context, baseURL, remoteID, probeModel string, session remoteSession) (businessLatencySnapshot, error) {
	path := "/api/v1/admin/usage?account_id=" + url.QueryEscape(remoteID) +
		"&stream=true&sort_by=created_at&sort_order=desc&page=1&page_size=" + strconv.Itoa(recentBusinessLatencySamples)
	raw, _, err := a.remoteJSON(ctx, baseURL, http.MethodGet, path, session, nil)
	if err != nil {
		return businessLatencySnapshot{}, err
	}
	value, err := unwrapEnvelope(raw, "SUB2API")
	if err != nil {
		return businessLatencySnapshot{}, err
	}
	record, ok := value.(map[string]any)
	if !ok {
		return businessLatencySnapshot{}, &apiError{502, "SCHEMA_CHANGED", "目标节点用量分页格式不兼容"}
	}
	items, ok := record["items"].([]any)
	if !ok {
		return businessLatencySnapshot{}, &apiError{502, "SCHEMA_CHANGED", "目标节点用量列表格式不兼容"}
	}
	return businessLatencyFromUsageItems(itemsAsMaps(items), remoteID, probeModel, time.Now()), nil
}

func itemsAsMaps(items []any) []map[string]any {
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if typed, ok := item.(map[string]any); ok {
			result = append(result, typed)
		}
	}
	return result
}

func businessLatencyFromUsageItems(items []map[string]any, remoteID, probeModel string, now time.Time) businessLatencySnapshot {
	values := make([]int, 0, recentBusinessLatencySamples)
	modelValues := make([]int, 0, recentBusinessLatencySamples)
	latest := time.Time{}
	modelLatest := time.Time{}
	cutoff := now.Add(-businessLatencyWindow)
	for _, item := range items {
		accountNumber, ok := number(item["account_id"])
		if !ok || strconv.Itoa(int(accountNumber)) != remoteID {
			continue
		}
		firstToken, ok := number(item["first_token_ms"])
		if !ok || firstToken < 0 {
			continue
		}
		created, parseErr := parseRemoteTimestamp(text(item["created_at"], ""))
		if parseErr != nil || created.Before(cutoff) {
			continue
		}
		values = append(values, int(firstToken))
		if created.After(latest) {
			latest = created
		}
		if probeModel != "" && text(item["model"], "") == probeModel {
			modelValues = append(modelValues, int(firstToken))
			if created.After(modelLatest) {
				modelLatest = created
			}
		}
	}
	if len(values) == 0 {
		return businessLatencySnapshot{}
	}
	model := "ALL"
	if len(modelValues) >= businessLatencyMinSamples {
		values = modelValues
		latest = modelLatest
		model = probeModel
	}
	return businessLatencySnapshot{FirstTokenP50Ms: medianInt(values), FirstTokenP90Ms: percentileInt(values, .90), Samples: len(values), LatestAt: latest, Model: model}
}

func parseRemoteTimestamp(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339, value)
}

func medianInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return sorted[middle-1] + (sorted[middle]-sorted[middle-1])/2
}

func remoteRequestID(value any) string {
	if id := text(value, ""); id != "" {
		return id
	}
	if numberValue, ok := number(value); ok {
		return strconv.FormatInt(int64(numberValue), 10)
	}
	return ""
}

func percentileInt(values []int, ratio float64) int {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	index := int(float64(len(sorted))*ratio+.999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func (a *App) disableSlowChannelAccounts(ctx context.Context, channelID, reason string) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM managed_accounts WHERE channel_id=$1 AND schedulable=true`, channelID)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		a.enqueueManagedAction(ctx, id, "SET_SCHEDULABLE", map[string]bool{"schedulable": true}, map[string]bool{"schedulable": false}, reason)
	}
	return nil
}

func slowFirstTokenReason(firstTokenMs int) string {
	return fmt.Sprintf("单次真实业务首 Token %.2f 秒超过 60 秒上限，已自动禁用", float64(firstTokenMs)/1000)
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

package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"
)

const (
	sourceStabilityInsufficient = "INSUFFICIENT_DATA"
	sourceStabilityStable       = "STABLE"
	sourceStabilityDegraded     = "DEGRADED"
	sourceStabilityUnstable     = "UNSTABLE"
)

type sourceQualityInput struct {
	CreatedAt            time.Time
	ProbeSamples         int
	ProbeSuccessRate     sql.NullFloat64
	BusinessRequests     int
	BusinessSuccessRate  sql.NullFloat64
	FirstTokenP95Ms      sql.NullFloat64
	ProbeFirstTokenP95Ms sql.NullFloat64
	ScanIncidents7d      int
}

func (a *App) applySourceStabilityAssessments(ctx context.Context, sources []Source) error {
	if len(sources) == 0 {
		return nil
	}
	rows, err := a.db.QueryContext(ctx, `SELECT s.id,s.created_at,
		(SELECT count(*) FROM probe_runs p JOIN channels c ON c.id=p.channel_id WHERE c.source_id=s.id AND p.started_at>now()-interval '7 days'),
		(SELECT avg(CASE WHEN p.success THEN 100.0 ELSE 0 END) FROM probe_runs p JOIN channels c ON c.id=p.channel_id WHERE c.source_id=s.id AND p.started_at>now()-interval '7 days'),
		(SELECT COALESCE(sum(b.requests),0) FROM metric_buckets b JOIN channels c ON c.id=b.channel_id WHERE c.source_id=s.id AND b.window_start>now()-interval '7 days'),
		(SELECT CASE WHEN COALESCE(sum(b.requests),0)=0 THEN NULL ELSE 100.0*(sum(b.requests)-sum(b.errors))/sum(b.requests) END FROM metric_buckets b JOIN channels c ON c.id=b.channel_id WHERE c.source_id=s.id AND b.window_start>now()-interval '7 days'),
		(SELECT avg(b.first_token_p95_ms) FROM metric_buckets b JOIN channels c ON c.id=b.channel_id WHERE c.source_id=s.id AND b.first_token_p95_ms IS NOT NULL AND b.window_start>now()-interval '7 days'),
		(SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY p.first_token_ms) FROM probe_runs p JOIN channels c ON c.id=p.channel_id WHERE c.source_id=s.id AND p.first_token_ms IS NOT NULL AND p.started_at>now()-interval '7 days'),
		(SELECT count(*) FROM events e WHERE e.dedupe_key='source-scan:'||s.id::text AND e.created_at>now()-interval '7 days')
		FROM sources s`)
	if err != nil {
		return err
	}
	defer rows.Close()
	assessments := make(map[string]struct {
		value, confidence string
		reasons           []string
		input             sourceQualityInput
	}, len(sources))
	for rows.Next() {
		var id string
		var input sourceQualityInput
		if err := rows.Scan(&id, &input.CreatedAt, &input.ProbeSamples, &input.ProbeSuccessRate, &input.BusinessRequests, &input.BusinessSuccessRate, &input.FirstTokenP95Ms, &input.ProbeFirstTokenP95Ms, &input.ScanIncidents7d); err != nil {
			return err
		}
		value, confidence, reasons := assessSourceStability(input, time.Now())
		assessments[id] = struct {
			value, confidence string
			reasons           []string
			input             sourceQualityInput
		}{value, confidence, reasons, input}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for index := range sources {
		assessment := assessments[sources[index].ID]
		sources[index].StabilityStatus = assessment.value
		sources[index].StabilityConfidence = assessment.confidence
		sources[index].StabilityReasons = assessment.reasons
		sources[index].BusinessRequests7d = assessment.input.BusinessRequests
		sources[index].ProbeSamples7d = assessment.input.ProbeSamples
		sources[index].ScanIncidents7d = assessment.input.ScanIncidents7d
		if assessment.input.BusinessSuccessRate.Valid {
			value := assessment.input.BusinessSuccessRate.Float64
			sources[index].BusinessSuccessRate7d = &value
		}
		if assessment.input.ProbeSuccessRate.Valid {
			value := assessment.input.ProbeSuccessRate.Float64
			sources[index].ProbeSuccessRate7d = &value
		}
		if firstToken, source := sourceStabilityFirstToken(assessment.input); firstToken.Valid {
			value := firstToken.Float64
			sources[index].FirstTokenP95Ms7d = &value
			sources[index].FirstTokenSource = source
		}
	}
	return nil
}

func assessSourceStability(input sourceQualityInput, now time.Time) (string, string, []string) {
	age := now.Sub(input.CreatedAt)
	confidence := "LOW"
	if age >= 7*24*time.Hour && input.BusinessRequests >= 1000 {
		confidence = "HIGH"
	} else if age >= 48*time.Hour && (input.BusinessRequests >= 100 || input.ProbeSamples >= 50) {
		confidence = "MEDIUM"
	}
	if age < 48*time.Hour || (input.BusinessRequests < 100 && input.ProbeSamples < 20) {
		reasons := []string{}
		if age < 48*time.Hour {
			reasons = append(reasons, fmt.Sprintf("已观察 %.0f 小时，需要至少 48 小时", math.Max(age.Hours(), 0)))
		}
		if input.BusinessRequests < 100 && input.ProbeSamples < 20 {
			reasons = append(reasons, fmt.Sprintf("真实业务 %d 个请求，主动探测 %d 个样本", input.BusinessRequests, input.ProbeSamples))
		}
		return sourceStabilityInsufficient, "LOW", reasons
	}

	unstableReasons := []string{}
	degradedReasons := []string{}
	strongBusinessEvidence := input.BusinessRequests >= 100 && input.BusinessSuccessRate.Valid
	if strongBusinessEvidence {
		rate := input.BusinessSuccessRate.Float64
		if rate < 90 {
			unstableReasons = append(unstableReasons, fmt.Sprintf("7 天真实业务成功率 %.1f%%，低于 90%%", rate))
		} else if rate < 98 {
			degradedReasons = append(degradedReasons, fmt.Sprintf("7 天真实业务成功率 %.1f%%，低于 98%%", rate))
		}
	}
	if input.ProbeSuccessRate.Valid && input.ProbeSamples >= 20 {
		rate := input.ProbeSuccessRate.Float64
		if !strongBusinessEvidence && rate < 50 {
			unstableReasons = append(unstableReasons, fmt.Sprintf("主动探测成功率仅 %.1f%%", rate))
		} else if !strongBusinessEvidence && rate < 90 {
			degradedReasons = append(degradedReasons, fmt.Sprintf("主动探测成功率为 %.1f%%", rate))
		}
	}
	firstToken, firstTokenSource := sourceStabilityFirstToken(input)
	if firstToken.Valid {
		latency := firstToken.Float64
		label := "真实首响"
		if firstTokenSource == "PROBE" {
			label = "探测首响"
		}
		if latency >= 10_000 {
			unstableReasons = append(unstableReasons, fmt.Sprintf("7 天%s P95 为 %.1f 秒", label, latency/1000))
		} else if latency >= 5_000 {
			degradedReasons = append(degradedReasons, fmt.Sprintf("7 天%s P95 为 %.1f 秒", label, latency/1000))
		}
	}
	if input.ScanIncidents7d >= 3 {
		unstableReasons = append(unstableReasons, fmt.Sprintf("7 天内发生 %d 次扫描中断", input.ScanIncidents7d))
	} else if input.ScanIncidents7d > 0 {
		degradedReasons = append(degradedReasons, fmt.Sprintf("7 天内发生 %d 次扫描中断", input.ScanIncidents7d))
	}
	if len(unstableReasons) > 0 {
		return sourceStabilityUnstable, confidence, firstReasons(append(unstableReasons, degradedReasons...), 3)
	}
	if len(degradedReasons) > 0 {
		return sourceStabilityDegraded, confidence, firstReasons(degradedReasons, 3)
	}
	reasons := []string{}
	if strongBusinessEvidence {
		reasons = append(reasons, fmt.Sprintf("7 天真实业务成功率 %.1f%%", input.BusinessSuccessRate.Float64))
	} else if input.ProbeSuccessRate.Valid {
		reasons = append(reasons, fmt.Sprintf("7 天主动探测成功率 %.1f%%", input.ProbeSuccessRate.Float64))
	}
	if firstToken.Valid {
		label := "真实首响"
		if firstTokenSource == "PROBE" {
			label = "探测首响"
		}
		reasons = append(reasons, fmt.Sprintf("7 天%s P95 为 %.1f 秒", label, firstToken.Float64/1000))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "现有可靠性指标未发现明显风险")
	}
	return sourceStabilityStable, confidence, firstReasons(reasons, 3)
}

func sourceStabilityFirstToken(input sourceQualityInput) (sql.NullFloat64, string) {
	if input.FirstTokenP95Ms.Valid {
		return input.FirstTokenP95Ms, "BUSINESS"
	}
	if input.ProbeSamples >= 20 && input.ProbeFirstTokenP95Ms.Valid {
		return input.ProbeFirstTokenP95Ms, "PROBE"
	}
	return sql.NullFloat64{}, ""
}

func firstReasons(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

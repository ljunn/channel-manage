package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"
)

const (
	sourceRecommendationInsufficient = "INSUFFICIENT_DATA"
	sourceRecommendationUse          = "RECOMMEND_USE"
	sourceRecommendationObserve      = "OBSERVE"
	sourceRecommendationStop         = "STOP_RECHARGE"
)

type sourceQualityInput struct {
	CreatedAt           time.Time
	ProbeSamples        int
	ProbeSuccessRate    sql.NullFloat64
	BusinessRequests    int
	BusinessSuccessRate sql.NullFloat64
	FirstTokenP95Ms     sql.NullFloat64
	ScanIncidents7d     int
	Mappings            int
	QualifiedMappings   int
}

func (a *App) applySourceQualityRecommendations(ctx context.Context, sources []Source) error {
	if len(sources) == 0 {
		return nil
	}
	rows, err := a.db.QueryContext(ctx, `SELECT s.id,s.created_at,
		(SELECT count(*) FROM probe_runs p JOIN channels c ON c.id=p.channel_id WHERE c.source_id=s.id AND p.started_at>now()-interval '7 days'),
		(SELECT avg(CASE WHEN p.success THEN 100.0 ELSE 0 END) FROM probe_runs p JOIN channels c ON c.id=p.channel_id WHERE c.source_id=s.id AND p.started_at>now()-interval '7 days'),
		(SELECT COALESCE(sum(b.requests),0) FROM metric_buckets b JOIN channels c ON c.id=b.channel_id WHERE c.source_id=s.id AND b.window_start>now()-interval '7 days'),
		(SELECT CASE WHEN COALESCE(sum(b.requests),0)=0 THEN NULL ELSE 100.0*(sum(b.requests)-sum(b.errors))/sum(b.requests) END FROM metric_buckets b JOIN channels c ON c.id=b.channel_id WHERE c.source_id=s.id AND b.window_start>now()-interval '7 days'),
		(SELECT avg(b.first_token_p95_ms) FROM metric_buckets b JOIN channels c ON c.id=b.channel_id WHERE c.source_id=s.id AND b.first_token_p95_ms IS NOT NULL AND b.window_start>now()-interval '7 days'),
		(SELECT count(*) FROM events e WHERE e.dedupe_key='source-scan:'||s.id::text AND e.created_at>now()-interval '7 days'),
		(SELECT count(*) FROM managed_account_groups mag JOIN managed_accounts m ON m.id=mag.managed_account_id JOIN channels c ON c.id=m.channel_id JOIN source_groups sg ON sg.id=c.source_group_id JOIN target_groups tg ON tg.id=mag.target_group_id WHERE c.source_id=s.id),
		(SELECT count(*) FROM managed_account_groups mag JOIN managed_accounts m ON m.id=mag.managed_account_id JOIN channels c ON c.id=m.channel_id JOIN source_groups sg ON sg.id=c.source_group_id JOIN target_groups tg ON tg.id=mag.target_group_id WHERE c.source_id=s.id AND sg.multiplier IS NOT NULL AND tg.multiplier IS NOT NULL AND sg.multiplier<tg.multiplier)
		FROM sources s`)
	if err != nil {
		return err
	}
	defer rows.Close()
	recommendations := make(map[string]struct {
		value, confidence string
		reasons           []string
	}, len(sources))
	for rows.Next() {
		var id string
		var input sourceQualityInput
		if err := rows.Scan(&id, &input.CreatedAt, &input.ProbeSamples, &input.ProbeSuccessRate, &input.BusinessRequests, &input.BusinessSuccessRate, &input.FirstTokenP95Ms, &input.ScanIncidents7d, &input.Mappings, &input.QualifiedMappings); err != nil {
			return err
		}
		value, confidence, reasons := recommendSourceQuality(input, time.Now())
		recommendations[id] = struct {
			value, confidence string
			reasons           []string
		}{value, confidence, reasons}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for index := range sources {
		recommendation := recommendations[sources[index].ID]
		sources[index].SystemRecommendation = recommendation.value
		sources[index].RecommendationConfidence = recommendation.confidence
		sources[index].RecommendationReasons = recommendation.reasons
	}
	return nil
}

func (a *App) sourceQualityReference(ctx context.Context, sourceID string) string {
	items := []Source{{ID: sourceID}}
	if a.applySourceQualityRecommendations(ctx, items) != nil || len(items) == 0 || items[0].SystemRecommendation != sourceRecommendationStop || len(items[0].RecommendationReasons) == 0 {
		return ""
	}
	return "建议停止充值，" + items[0].RecommendationReasons[0]
}

func recommendSourceQuality(input sourceQualityInput, now time.Time) (string, string, []string) {
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
		return sourceRecommendationInsufficient, "LOW", reasons
	}

	stopReasons := []string{}
	observeReasons := []string{}
	strongBusinessEvidence := input.BusinessRequests >= 100 && input.BusinessSuccessRate.Valid
	if strongBusinessEvidence {
		rate := input.BusinessSuccessRate.Float64
		if rate < 90 {
			stopReasons = append(stopReasons, fmt.Sprintf("7 天真实业务成功率 %.1f%%，低于 90%%", rate))
		} else if rate < 97 {
			observeReasons = append(observeReasons, fmt.Sprintf("7 天真实业务成功率 %.1f%%，低于 97%%", rate))
		}
	}
	if input.ProbeSuccessRate.Valid && input.ProbeSamples >= 20 {
		rate := input.ProbeSuccessRate.Float64
		if strongBusinessEvidence {
			if input.BusinessSuccessRate.Float64 >= 97 && rate < 50 {
				observeReasons = append(observeReasons, fmt.Sprintf("主动探测成功率 %.1f%% 与真实业务表现不一致，请检查测试模型", rate))
			}
		} else if rate < 50 {
			stopReasons = append(stopReasons, fmt.Sprintf("缺少足够真实业务时，主动探测成功率仅 %.1f%%", rate))
		} else if rate < 90 {
			observeReasons = append(observeReasons, fmt.Sprintf("缺少足够真实业务时，主动探测成功率为 %.1f%%", rate))
		}
	}
	if input.FirstTokenP95Ms.Valid {
		latency := input.FirstTokenP95Ms.Float64
		if latency >= 10_000 {
			stopReasons = append(stopReasons, fmt.Sprintf("7 天首 Token P95 约 %.1f 秒", latency/1000))
		} else if latency >= 5_000 {
			observeReasons = append(observeReasons, fmt.Sprintf("7 天首 Token P95 约 %.1f 秒", latency/1000))
		}
	}
	if input.ScanIncidents7d >= 3 {
		stopReasons = append(stopReasons, fmt.Sprintf("7 天内发生 %d 次扫描中断", input.ScanIncidents7d))
	} else if input.ScanIncidents7d > 0 {
		observeReasons = append(observeReasons, fmt.Sprintf("7 天内发生 %d 次扫描中断", input.ScanIncidents7d))
	}
	if input.Mappings > 0 && input.QualifiedMappings == 0 {
		stopReasons = append(stopReasons, "当前绑定没有正倍率空间")
	} else if input.Mappings > 0 && input.QualifiedMappings < input.Mappings {
		observeReasons = append(observeReasons, fmt.Sprintf("仅 %d/%d 个绑定有正倍率空间", input.QualifiedMappings, input.Mappings))
	}
	if len(stopReasons) > 0 {
		return sourceRecommendationStop, confidence, firstReasons(append(stopReasons, observeReasons...), 3)
	}
	if len(observeReasons) > 0 {
		return sourceRecommendationObserve, confidence, firstReasons(observeReasons, 3)
	}
	reasons := []string{}
	if strongBusinessEvidence {
		reasons = append(reasons, fmt.Sprintf("7 天真实业务成功率 %.1f%%", input.BusinessSuccessRate.Float64))
	} else if input.ProbeSuccessRate.Valid {
		reasons = append(reasons, fmt.Sprintf("7 天主动探测成功率 %.1f%%", input.ProbeSuccessRate.Float64))
	}
	if input.FirstTokenP95Ms.Valid {
		reasons = append(reasons, fmt.Sprintf("7 天首 Token P95 约 %.1f 秒", input.FirstTokenP95Ms.Float64/1000))
	}
	if input.Mappings > 0 {
		reasons = append(reasons, fmt.Sprintf("%d/%d 个绑定有正倍率空间", input.QualifiedMappings, input.Mappings))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "现有可靠性指标未发现明显风险")
	}
	return sourceRecommendationUse, confidence, firstReasons(reasons, 3)
}

func firstReasons(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

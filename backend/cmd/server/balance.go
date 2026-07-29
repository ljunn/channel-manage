package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"time"
)

type balanceSample struct {
	Balance    float64
	CapturedAt time.Time
}

type balanceForecast struct {
	BurnRate  float64
	EtaHours  float64
	Samples   int
	Known     bool
	Recharged bool
}

func calculateBalanceForecast(samples []balanceSample) balanceForecast {
	if len(samples) < 2 {
		return balanceForecast{}
	}
	sorted := append([]balanceSample(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CapturedAt.Before(sorted[j].CapturedAt) })
	latest := sorted[len(sorted)-1]
	previous := sorted[len(sorted)-2]
	rechargeThreshold := math.Max(0.01, math.Abs(previous.Balance)*0.01)
	result := balanceForecast{Recharged: latest.Balance-previous.Balance >= rechargeThreshold}
	baselineIndex := 0
	for index := 1; index < len(sorted); index++ {
		threshold := math.Max(0.01, math.Abs(sorted[index-1].Balance)*0.01)
		if sorted[index].Balance-sorted[index-1].Balance >= threshold {
			baselineIndex = index
		}
	}

	type ratePoint struct {
		rate float64
		at   time.Time
	}
	rates := []ratePoint{}
	for index := baselineIndex + 1; index < len(sorted); index++ {
		duration := sorted[index].CapturedAt.Sub(sorted[index-1].CapturedAt).Hours()
		if duration < 5.0/60.0 || duration > 48 {
			continue
		}
		decrease := sorted[index-1].Balance - sorted[index].Balance
		minimumDecrease := math.Max(0.000001, math.Abs(sorted[index-1].Balance)*0.000001)
		if decrease < minimumDecrease {
			continue
		}
		rates = append(rates, ratePoint{rate: decrease / duration, at: sorted[index].CapturedAt})
	}
	if len(rates) < 3 {
		return result
	}
	recent := []float64{}
	for _, point := range rates {
		if !point.at.Before(latest.CapturedAt.Add(-24 * time.Hour)) {
			recent = append(recent, point.rate)
		}
	}
	if len(recent) < 3 {
		recent = recent[:0]
		for _, point := range rates {
			recent = append(recent, point.rate)
		}
	}
	sort.Float64s(recent)
	median := recent[len(recent)/2]
	if len(recent)%2 == 0 {
		median = (recent[len(recent)/2-1] + median) / 2
	}
	if median <= 0 || math.IsNaN(median) || math.IsInf(median, 0) {
		return result
	}
	result.BurnRate = median
	result.EtaHours = math.Max(0, latest.Balance) / median
	result.Samples = len(recent)
	result.Known = true
	return result
}

func balanceAlertLead(now time.Time, workHours, nightHours, weekendHours int) (int, string) {
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		return weekendHours, "周末"
	}
	if now.Hour() < 9 || now.Hour() >= 19 {
		return nightHours, "夜间"
	}
	return workHours, "工作时段"
}

func (a *App) sourceBalanceForecast(ctx context.Context, sourceID string) (balanceForecast, error) {
	samples, err := a.sourceBalanceSamples(ctx, sourceID)
	if err != nil {
		return balanceForecast{}, err
	}
	return calculateBalanceForecast(samples), nil
}

func (a *App) sourceBalanceSamples(ctx context.Context, sourceID string) ([]balanceSample, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT balance,captured_at FROM source_balance_samples WHERE source_id=$1 AND captured_at>=now()-interval '7 days' ORDER BY captured_at`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := []balanceSample{}
	for rows.Next() {
		var sample balanceSample
		if err = rows.Scan(&sample.Balance, &sample.CapturedAt); err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return samples, nil
}

func consecutiveBalanceForecasts(samples []balanceSample, count int, predicate func(balanceForecast) bool) bool {
	if count < 1 || len(samples) < count+1 {
		return false
	}
	for offset := 0; offset < count; offset++ {
		forecast := calculateBalanceForecast(samples[:len(samples)-offset])
		if !forecast.Known || forecast.Recharged || !predicate(forecast) {
			return false
		}
	}
	return true
}

func recommendedRecharge(balance, burnRate, targetHours float64) float64 {
	needed := burnRate*targetHours - balance
	if needed <= 0 || math.IsNaN(needed) || math.IsInf(needed, 0) {
		return 0
	}
	return math.Ceil(needed/10) * 10
}

func (a *App) evaluateSourceBalance(ctx context.Context, sourceID string) {
	var name, baseURL, accountHint, currency string
	var balance sql.NullFloat64
	if err := a.db.QueryRowContext(ctx, `SELECT name,base_url,username_hint,balance,balance_currency FROM sources WHERE id=$1`, sourceID).Scan(&name, &baseURL, &accountHint, &balance, &currency); err != nil || !balance.Valid {
		return
	}
	dedupeKey := "source-balance:" + sourceID
	if balance.Float64 <= 0 {
		detail := fmt.Sprintf("数据源：%s\n源站地址：%s\n充值账号：%s\n当前余额：%.2f %s\n判定原因：账户已经没有可用余额", name, baseURL, fallbackText(accountHint, "请登录源站查看"), balance.Float64, currency)
		a.openEvent(ctx, "P0", "SOURCE_BALANCE", "账户可用余额已耗尽", detail, dedupeKey)
		return
	}
	var activeTitle string
	_ = a.db.QueryRowContext(ctx, `SELECT title FROM events WHERE dedupe_key=$1 AND status<>'RESOLVED' ORDER BY created_at DESC LIMIT 1`, dedupeKey).Scan(&activeTitle)
	explicitExhaustion := activeTitle == "源站账户余额不足"
	samples, err := a.sourceBalanceSamples(ctx, sourceID)
	if err != nil {
		return
	}
	forecast := calculateBalanceForecast(samples)
	if forecast.Recharged {
		a.resolveEvent(ctx, dedupeKey)
		return
	}
	if !forecast.Known {
		if explicitExhaustion {
			a.resolveEvent(ctx, dedupeKey)
		}
		return
	}
	location, locationErr := time.LoadLocation("Asia/Shanghai")
	if locationErr != nil {
		location = time.FixedZone("CST", 8*60*60)
	}
	workHours := max(a.settingInt(ctx, "balance_alert_work_hours", 4), 1)
	nightHours := max(a.settingInt(ctx, "balance_alert_night_hours", 12), 1)
	weekendHours := max(a.settingInt(ctx, "balance_alert_weekend_hours", 36), 1)
	leadHours, period := balanceAlertLead(time.Now().In(location), workHours, nightHours, weekendHours)
	exhaustsAt := time.Now().In(location).Add(time.Duration(forecast.EtaHours * float64(time.Hour)))
	recharge := recommendedRecharge(balance.Float64, forecast.BurnRate, float64(leadHours+2))
	detail := fmt.Sprintf("数据源：%s\n源站地址：%s\n充值账号：%s\n当前余额：%.2f %s\n实际消耗速度：%.2f %s / 小时（中位数）\n预计剩余：%.1f 小时\n预计耗尽时间：%s\n当前预警提前量：%d 小时（%s）\n建议最低充值：%.2f %s\n判定依据：连续 2 次扫描均低于预警线", name, baseURL, fallbackText(accountHint, "请登录源站查看"), balance.Float64, currency, forecast.BurnRate, currency, forecast.EtaHours, exhaustsAt.Format("2006-01-02 15:04"), leadHours, period, recharge, currency)
	if forecast.EtaHours <= 1 {
		if consecutiveBalanceForecasts(samples, 2, func(item balanceForecast) bool { return item.EtaHours <= 1 }) {
			a.openEvent(ctx, "P0", "SOURCE_BALANCE", "账户可用余额预计 1 小时内耗尽", detail, dedupeKey)
		}
		return
	}
	if forecast.EtaHours <= float64(leadHours) {
		if consecutiveBalanceForecasts(samples, 2, func(item balanceForecast) bool { return item.EtaHours <= float64(leadHours) }) {
			a.openEvent(ctx, "P1", "SOURCE_BALANCE", fmt.Sprintf("账户可用余额预计 %.1f 小时后耗尽", forecast.EtaHours), detail, dedupeKey)
		}
		return
	}
	stableRecovery := consecutiveBalanceForecasts(samples, 2, func(item balanceForecast) bool { return item.EtaHours >= float64(leadHours)*1.5 })
	if explicitExhaustion || stableRecovery {
		a.resolveEvent(ctx, dedupeKey)
	}
}

func fallbackText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

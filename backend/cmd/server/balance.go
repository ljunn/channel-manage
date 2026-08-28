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

func balanceBelowAlertThreshold(balance, threshold float64) bool {
	return threshold > 0 && !math.IsNaN(balance) && !math.IsInf(balance, 0) && balance < threshold
}

func (a *App) evaluateSourceBalance(ctx context.Context, sourceID string) {
	var name, baseURL, rechargeURL, accountHint, currency string
	var manuallyUntrusted bool
	var balance sql.NullFloat64
	if err := a.db.QueryRowContext(ctx, `SELECT name,base_url,recharge_url,username_hint,balance,balance_currency,manually_untrusted FROM sources WHERE id=$1`, sourceID).Scan(&name, &baseURL, &rechargeURL, &accountHint, &balance, &currency, &manuallyUntrusted); err != nil || !balance.Valid || manuallyUntrusted {
		return
	}
	if rechargeURL == "" {
		rechargeURL = baseURL
	}
	dedupeKey := "source-balance:" + sourceID
	threshold := a.settingFloat(ctx, "balance_alert_threshold", 10)
	if threshold <= 0 {
		threshold = 10
	}
	if balanceBelowAlertThreshold(balance.Float64, threshold) {
		detail := fmt.Sprintf("数据源：%s\n充值地址：%s\n充值账号：%s\n当前余额：%.2f %s\n提醒阈值：%.2f %s\n判定原因：当前余额低于指定阈值", name, rechargeURL, fallbackText(accountHint, "请登录源站查看"), balance.Float64, currency, threshold, currency)
		a.openEvent(ctx, "P1", "SOURCE_BALANCE", "数据源余额低于提醒阈值", detail, dedupeKey)
		return
	}
	a.resolveEvent(ctx, dedupeKey)
}

func fallbackText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

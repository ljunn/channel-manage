package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func targetGroupProbeModels(record map[string]any, platform string) []string {
	config, _ := record["models_list_config"].(map[string]any)
	raw, _ := config["models"].([]any)
	models := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, item := range raw {
		model, _ := item.(string)
		model = strings.TrimSpace(model)
		if model != "" && !seen[model] && probeModelMatchesPlatform(platform, model) {
			seen[model] = true
			models = append(models, model)
		}
	}
	return models
}

func probeModelMatchesPlatform(platform, model string) bool {
	value := strings.ToLower(strings.TrimSpace(model))
	if value == "" {
		return false
	}
	for _, marker := range []string{"auto-review", "embedding", "rerank", "moderation", "whisper", "audio", "realtime", "tts", "image", "dall-e", "video"} {
		if strings.Contains(value, marker) {
			return false
		}
	}
	switch managedPlatform(platform) {
	case "openai":
		return strings.HasPrefix(value, "gpt-")
	case "anthropic":
		return strings.HasPrefix(value, "claude-")
	case "gemini":
		return strings.HasPrefix(value, "gemini-")
	case "grok":
		return strings.HasPrefix(value, "grok-")
	default:
		return true
	}
}

func decodeModels(raw string) []string {
	models := []string{}
	_ = json.Unmarshal([]byte(raw), &models)
	return models
}

func intersectModels(left, right []string) []string {
	available := make(map[string]bool, len(right))
	for _, model := range right {
		available[model] = true
	}
	result := make([]string, 0, len(left))
	for _, model := range left {
		if available[model] {
			result = append(result, model)
		}
	}
	return result
}

func preferredProbeModel(platform string, models []string) string {
	preferences := map[string][]string{
		"openai":    {"gpt-5.5", "gpt-5.4", "gpt-5.4-mini"},
		"anthropic": {"claude-sonnet-4-6", "claude-sonnet-4-5-20250929"},
		"gemini":    {"gemini-2.5-pro", "gemini-2.5-flash"},
		"grok":      {"grok-4.3"},
	}
	for _, preferred := range preferences[managedPlatform(platform)] {
		for _, model := range models {
			if model == preferred {
				return model
			}
		}
	}
	if len(models) > 0 {
		return models[0]
	}
	return ""
}

func (a *App) ensureTargetProbeModels(ctx context.Context, targetID string) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id,platform,models FROM target_groups WHERE target_id=$1 AND probe_model='' ORDER BY name`, targetID)
	if err != nil {
		return err
	}
	type group struct{ id, platform, models string }
	groups := []group{}
	for rows.Next() {
		var item group
		if err = rows.Scan(&item.id, &item.platform, &item.models); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, item)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, item := range groups {
		common := decodeModels(item.models)
		keyRows, queryErr := a.db.QueryContext(ctx, `SELECT DISTINCT k.models FROM managed_account_groups mg JOIN managed_accounts m ON m.id=mg.managed_account_id JOIN channels c ON c.id=m.channel_id JOIN source_keys k ON k.id=c.source_key_id WHERE mg.target_group_id=$1`, item.id)
		if queryErr != nil {
			return queryErr
		}
		for keyRows.Next() {
			var modelsJSON string
			if err = keyRows.Scan(&modelsJSON); err != nil {
				keyRows.Close()
				return err
			}
			common = intersectModels(common, decodeModels(modelsJSON))
		}
		if err = keyRows.Close(); err != nil {
			return err
		}
		model := preferredProbeModel(item.platform, common)
		if model == "" {
			model = preferredProbeModel(item.platform, decodeModels(item.models))
		}
		if model != "" {
			if _, err = a.db.ExecContext(ctx, `UPDATE target_groups SET probe_model=$2,updated_at=now() WHERE id=$1 AND probe_model=''`, item.id, model); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) configuredChannelProbeModels(ctx context.Context, channelID string, sourceModels []string) ([]string, []string, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT DISTINCT tg.name,tg.probe_model FROM managed_accounts m JOIN managed_account_groups mg ON mg.managed_account_id=m.id JOIN target_groups tg ON tg.id=mg.target_group_id WHERE m.channel_id=$1 ORDER BY tg.name`, channelID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	available := map[string]bool{}
	for _, model := range sourceModels {
		available[model] = true
	}
	models := []string{}
	unavailable := []string{}
	seen := map[string]bool{}
	for rows.Next() {
		var groupName, model string
		if err = rows.Scan(&groupName, &model); err != nil {
			return nil, nil, err
		}
		if model == "" {
			return nil, nil, fmt.Errorf("目标分组 %s 尚未指定测试模型", groupName)
		}
		if !available[model] {
			unavailable = append(unavailable, fmt.Sprintf("%s：%s", groupName, model))
			continue
		}
		if !seen[model] {
			seen[model] = true
			models = append(models, model)
		}
	}
	if len(models) == 0 {
		if len(unavailable) > 0 {
			return models, unavailable, rows.Err()
		}
		return nil, nil, fmt.Errorf("渠道没有关联可测试的目标分组")
	}
	sort.Strings(models)
	sort.Strings(unavailable)
	return models, unavailable, rows.Err()
}

func (a *App) measureProbeModels(ctx context.Context, channelID, baseURL, key string, sourceModels []string) (int, []string, []string, error) {
	models, unavailable, err := a.configuredChannelProbeModels(ctx, channelID, sourceModels)
	if err != nil {
		return 0, nil, nil, err
	}
	maximum := 0
	for _, model := range models {
		firstTokenMs, sampleErr := a.measureFirstToken(ctx, baseURL, key, model)
		if firstTokenMs > maximum {
			maximum = firstTokenMs
		}
		if sampleErr != nil {
			return maximum, models, unavailable, fmt.Errorf("测试模型 %s：%w", model, sampleErr)
		}
		if firstTokenMs > maxFirstTokenMs {
			return maximum, models, unavailable, nil
		}
	}
	return maximum, models, unavailable, nil
}

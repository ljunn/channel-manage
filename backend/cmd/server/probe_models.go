package main

import (
	"context"
	"crypto/sha256"
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
	if !modelMatchesPlatform(platform, value) {
		return false
	}
	for _, marker := range []string{"auto-review", "embedding", "rerank", "moderation", "whisper", "audio", "realtime", "tts", "image", "dall-e", "video"} {
		if strings.Contains(value, marker) {
			return false
		}
	}
	return true
}

func modelMatchesPlatform(platform, model string) bool {
	value := strings.ToLower(strings.TrimSpace(model))
	if value == "" {
		return false
	}
	// Providers commonly prefix an upstream model with their own namespace
	// (for example openai/gpt-4o). Platform matching should inspect the model
	// family while preserving the original ID for the remote request.
	if slash := strings.LastIndexByte(value, '/'); slash >= 0 {
		value = value[slash+1:]
	}
	switch managedPlatform(platform) {
	case "openai":
		return strings.HasPrefix(value, "gpt-") || strings.HasPrefix(value, "o1") || strings.HasPrefix(value, "o3") || strings.HasPrefix(value, "o4") || strings.HasPrefix(value, "chatgpt-")
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

func modelMappingForPlatform(platform string, models []string) map[string]string {
	mapping := map[string]string{}
	for _, model := range models {
		model = strings.TrimSpace(model)
		if modelMatchesPlatform(platform, model) {
			mapping[model] = model
		}
	}
	return mapping
}

func normalizeModelNames(models []string) []string {
	result := make([]string, 0, len(models))
	seen := make(map[string]bool, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" || seen[model] {
			continue
		}
		seen[model] = true
		result = append(result, model)
	}
	sort.Strings(result)
	return result
}

func modelMappingForPolicy(platform string, models, disabledModels []string) map[string]string {
	disabled := make(map[string]bool, len(disabledModels))
	for _, model := range normalizeModelNames(disabledModels) {
		disabled[model] = true
	}
	mapping := map[string]string{}
	for model, upstream := range modelMappingForPlatform(platform, models) {
		if !disabled[model] {
			mapping[model] = upstream
		}
	}
	return mapping
}

func modelMappingHash(mapping map[string]string) string {
	keys := make([]string, 0, len(mapping))
	for model := range mapping {
		keys = append(keys, model)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(keys, "\n"))))
}

func managedAccountConfigHash(platform string, mapping map[string]string) string {
	hash := modelMappingHash(mapping)
	if normalized := managedPlatform(platform); normalized == "anthropic" || normalized == "gemini" {
		return "root-base-v1:" + hash
	}
	return hash
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
		"openai":    {"gpt-5.6-sol", "gpt-5.5", "gpt-5.4", "gpt-5.4-mini"},
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

func defaultProbeModelForPlatform(platform string) string {
	defaults := map[string]string{
		"openai":    "gpt-5.6-sol",
		"anthropic": "claude-3-5-haiku-latest",
		"gemini":    "gemini-2.5-flash",
		"grok":      "grok-3-mini",
	}
	if model := defaults[managedPlatform(platform)]; model != "" {
		return model
	}
	return "gpt-5.6-sol"
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
	rows, err := a.db.QueryContext(ctx, `SELECT DISTINCT tg.name,COALESCE(v.config->>'probeModel','') FROM managed_accounts m JOIN managed_account_groups mg ON mg.managed_account_id=m.id JOIN target_groups tg ON tg.id=mg.target_group_id JOIN policies p ON p.scope_type='TARGET_GROUP' AND p.scope_id=tg.id AND p.status='ACTIVE' JOIN policy_versions v ON v.policy_id=p.id AND v.version=p.active_version WHERE m.channel_id=$1 ORDER BY tg.name`, channelID)
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
			return nil, nil, fmt.Errorf("目标分组 %s 尚未指定业务测速模型", groupName)
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
		return models, []string{"未关联已启用策略"}, rows.Err()
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
			return maximum, models, unavailable, fmt.Errorf("业务测速模型 %s：%w", model, sampleErr)
		}
		if firstTokenMs > maxFirstTokenMs {
			return maximum, models, unavailable, nil
		}
	}
	return maximum, models, unavailable, nil
}

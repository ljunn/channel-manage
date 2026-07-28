package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

func migrate(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS operators (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '运营管理员',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_login_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), operator_id UUID NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS sources (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, platform TEXT NOT NULL,
			base_url TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'ACTIVE',
			credential_cipher BYTEA, username_hint TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
			capabilities JSONB NOT NULL DEFAULT '{}'::jsonb, scan_interval_seconds INT NOT NULL DEFAULT 900,
			scan_status TEXT NOT NULL DEFAULT 'IDLE', last_scan_at TIMESTAMPTZ, last_error TEXT NOT NULL DEFAULT '',
			balance NUMERIC(18,6), balance_currency TEXT NOT NULL DEFAULT 'USD', value_divisor NUMERIC(18,8) NOT NULL DEFAULT 1, expires_at TIMESTAMPTZ,
			tags JSONB NOT NULL DEFAULT '[]'::jsonb, risk_note TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE sources ADD COLUMN IF NOT EXISTS value_divisor NUMERIC(18,8) NOT NULL DEFAULT 1`,
		`ALTER TABLE sources DROP COLUMN IF EXISTS asset_mode`,
		`CREATE TABLE IF NOT EXISTS source_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			name TEXT NOT NULL, key_cipher BYTEA NOT NULL, key_hint TEXT NOT NULL, production_authorized BOOLEAN NOT NULL DEFAULT false,
			status TEXT NOT NULL DEFAULT 'ACTIVE', models JSONB NOT NULL DEFAULT '[]'::jsonb, concurrency INT NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS source_groups (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			remote_id TEXT NOT NULL, name TEXT NOT NULL, multiplier NUMERIC(14,6), group_type TEXT NOT NULL DEFAULT 'default',
			models JSONB NOT NULL DEFAULT '[]'::jsonb, raw_hash TEXT NOT NULL DEFAULT '', captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(source_id, remote_id)
		)`,
		`ALTER TABLE source_groups ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE source_keys ADD COLUMN IF NOT EXISTS remote_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE source_keys ADD COLUMN IF NOT EXISTS auto_generated BOOLEAN NOT NULL DEFAULT false`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_source_keys_remote_id ON source_keys(source_id,remote_id) WHERE remote_id<>''`,
		`CREATE TABLE IF NOT EXISTS group_samples (
			id BIGSERIAL PRIMARY KEY, source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			group_id UUID NOT NULL REFERENCES source_groups(id) ON DELETE CASCADE, multiplier NUMERIC(14,6),
			balance NUMERIC(18,6), captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_group_samples_group_time ON group_samples(group_id, captured_at DESC)`,
		`CREATE TABLE IF NOT EXISTS targets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, base_url TEXT NOT NULL UNIQUE,
			api_key_cipher BYTEA NOT NULL, key_hint TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'UNKNOWN', version TEXT NOT NULL DEFAULT '',
			write_enabled BOOLEAN NOT NULL DEFAULT false, last_sync_at TIMESTAMPTZ, last_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_metrics_at TIMESTAMPTZ`,
		`CREATE TABLE IF NOT EXISTS target_groups (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
			remote_id TEXT NOT NULL, name TEXT NOT NULL, protected_best_priority INT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(target_id, remote_id)
		)`,
		`CREATE TABLE IF NOT EXISTS protected_accounts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
			remote_id TEXT NOT NULL, name TEXT NOT NULL, platform TEXT NOT NULL DEFAULT '', group_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
			schedulable BOOLEAN NOT NULL DEFAULT false, priority INT, concurrency INT, captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(target_id, remote_id)
		)`,
		`CREATE TABLE IF NOT EXISTS channels (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			source_key_id UUID NOT NULL REFERENCES source_keys(id) ON DELETE CASCADE, source_group_id UUID REFERENCES source_groups(id) ON DELETE SET NULL,
			lifecycle_state TEXT NOT NULL DEFAULT 'DISCOVERED', state_reason TEXT NOT NULL DEFAULT '', score NUMERIC(8,3),
			priority_tier TEXT NOT NULL DEFAULT 'STANDARD', consecutive_failures INT NOT NULL DEFAULT 0,
			last_probe_at TIMESTAMPTZ, state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(source_key_id, source_group_id)
		)`,
		`CREATE TABLE IF NOT EXISTS probe_runs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
			kind TEXT NOT NULL, success BOOLEAN NOT NULL, status_code INT, latency_ms INT, first_token_ms INT,
			error_type TEXT NOT NULL DEFAULT '', response_summary TEXT NOT NULL DEFAULT '', cost_usd NUMERIC(14,6) NOT NULL DEFAULT 0,
			started_at TIMESTAMPTZ NOT NULL DEFAULT now(), finished_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_probe_channel_time ON probe_runs(channel_id, started_at DESC)`,
		`CREATE TABLE IF NOT EXISTS metric_buckets (
			id BIGSERIAL PRIMARY KEY, channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
			window_start TIMESTAMPTZ NOT NULL, requests INT NOT NULL, errors INT NOT NULL, timeouts INT NOT NULL,
			rate_limited INT NOT NULL, p50_ms INT, p95_ms INT, first_token_p95_ms INT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(channel_id, window_start)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_metric_channel_time ON metric_buckets(channel_id, window_start DESC)`,
		`CREATE TABLE IF NOT EXISTS managed_accounts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_id UUID NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
			channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE RESTRICT, remote_id TEXT NOT NULL DEFAULT '', remote_name TEXT NOT NULL,
			priority INT NOT NULL DEFAULT 20, concurrency INT NOT NULL DEFAULT 1, schedulable BOOLEAN NOT NULL DEFAULT false,
			ownership_marker TEXT NOT NULL, sync_status TEXT NOT NULL DEFAULT 'PENDING', last_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(target_id, channel_id)
		)`,
		`CREATE TABLE IF NOT EXISTS managed_account_groups (
			managed_account_id UUID NOT NULL REFERENCES managed_accounts(id) ON DELETE CASCADE,
			target_group_id UUID NOT NULL REFERENCES target_groups(id) ON DELETE RESTRICT,
			PRIMARY KEY(managed_account_id, target_group_id)
		)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, scope_type TEXT NOT NULL DEFAULT 'GLOBAL', scope_id UUID,
			status TEXT NOT NULL DEFAULT 'DRAFT', active_version INT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS policy_versions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
			version INT NOT NULL, config JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(policy_id, version)
		)`,
		`CREATE TABLE IF NOT EXISTS action_intents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), managed_account_id UUID REFERENCES managed_accounts(id) ON DELETE SET NULL,
			action_type TEXT NOT NULL, before_state JSONB NOT NULL DEFAULT '{}'::jsonb, after_state JSONB NOT NULL DEFAULT '{}'::jsonb,
			reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', idempotency_key TEXT NOT NULL UNIQUE,
			approved_at TIMESTAMPTZ, executed_at TIMESTAMPTZ, error TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), severity TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'OPEN', dedupe_key TEXT NOT NULL,
			acknowledged_at TIMESTAMPTZ, resolved_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS notification_channels (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'EMAIL',
			config_cipher BYTEA NOT NULL, recipient_hint TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE',
			last_test_at TIMESTAMPTZ, last_error TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS notification_deliveries (
			id BIGSERIAL PRIMARY KEY, event_id UUID REFERENCES events(id) ON DELETE SET NULL, channel_id UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
			status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_events_status_time ON events(status, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGSERIAL PRIMARY KEY, operator_id UUID, action TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL,
			detail JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
	}
	for index, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migration %d: %w", index+1, err)
		}
	}
	defaults := map[string]string{
		"shadow_mode": "true", "emergency_freeze": "false", "auto_approve": "false",
		"probe_interval_seconds": "900", "scan_interval_seconds": "900", "max_daily_probe_cost_usd": "1",
		"min_healthy_channels": "1", "confirmation_failures": "3", "metric_window_minutes": "5",
		"min_error_samples": "5", "error_rate_threshold": "20",
	}
	for key, value := range defaults {
		if _, err := db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES($1,$2::jsonb) ON CONFLICT(key) DO NOTHING`, key, value); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) audit(ctx context.Context, action, objectType, objectID string, detail any) {
	operatorID := any(nil)
	if user, ok := ctx.Value(userContextKey).(Operator); ok {
		operatorID = user.ID
	}
	_, err := a.db.ExecContext(ctx, `INSERT INTO audit_logs(operator_id,action,object_type,object_id,detail) VALUES($1,$2,$3,$4,$5)`, operatorID, action, objectType, objectID, jsonValue(detail))
	if err != nil {
		logDatabaseError("写入审计", err)
	}
}

func jsonValue(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func logDatabaseError(action string, err error) {
	if err != nil {
		fmt.Printf("%s失败: %v\n", action, err)
	}
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

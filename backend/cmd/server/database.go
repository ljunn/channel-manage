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
			recharge_url TEXT NOT NULL DEFAULT '', manually_untrusted BOOLEAN NOT NULL DEFAULT false, manually_untrusted_at TIMESTAMPTZ,
			credential_cipher BYTEA, username_hint TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
			capabilities JSONB NOT NULL DEFAULT '{}'::jsonb, scan_interval_seconds INT NOT NULL DEFAULT 900,
			scan_status TEXT NOT NULL DEFAULT 'IDLE', last_scan_at TIMESTAMPTZ, last_error TEXT NOT NULL DEFAULT '',
			balance NUMERIC(18,6), balance_currency TEXT NOT NULL DEFAULT 'USD', value_divisor NUMERIC(18,8) NOT NULL DEFAULT 1, expires_at TIMESTAMPTZ,
			tags JSONB NOT NULL DEFAULT '[]'::jsonb, risk_note TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE sources ADD COLUMN IF NOT EXISTS recharge_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sources ADD COLUMN IF NOT EXISTS manually_untrusted BOOLEAN NOT NULL DEFAULT false`,
		`ALTER TABLE sources ADD COLUMN IF NOT EXISTS manually_untrusted_at TIMESTAMPTZ`,
		`ALTER TABLE sources ADD COLUMN IF NOT EXISTS value_divisor NUMERIC(18,8) NOT NULL DEFAULT 1`,
		`ALTER TABLE sources DROP COLUMN IF EXISTS asset_mode`,
		`UPDATE sources SET scan_status='IDLE',last_error='',updated_at=now() WHERE scan_status='RUNNING'`,
		`CREATE TABLE IF NOT EXISTS source_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			name TEXT NOT NULL, key_cipher BYTEA NOT NULL, key_hint TEXT NOT NULL, production_authorized BOOLEAN NOT NULL DEFAULT false,
			status TEXT NOT NULL DEFAULT 'ACTIVE', models JSONB NOT NULL DEFAULT '[]'::jsonb, concurrency INT NOT NULL DEFAULT 1000,
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
		`ALTER TABLE source_keys ALTER COLUMN concurrency SET DEFAULT 1000`,
		`UPDATE source_keys SET concurrency=1000 WHERE auto_generated=true AND concurrency=1`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_source_keys_remote_id ON source_keys(source_id,remote_id) WHERE remote_id<>''`,
		`CREATE TABLE IF NOT EXISTS group_samples (
			id BIGSERIAL PRIMARY KEY, source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			group_id UUID NOT NULL REFERENCES source_groups(id) ON DELETE CASCADE, multiplier NUMERIC(14,6),
			balance NUMERIC(18,6), captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_group_samples_group_time ON group_samples(group_id, captured_at DESC)`,
		`CREATE TABLE IF NOT EXISTS source_balance_samples (
			id BIGSERIAL PRIMARY KEY, source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			balance NUMERIC(18,6) NOT NULL, value_divisor NUMERIC(18,8) NOT NULL DEFAULT 1,
			captured_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(source_id,captured_at)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_source_balance_time ON source_balance_samples(source_id,captured_at DESC)`,
		`INSERT INTO source_balance_samples(source_id,balance,value_divisor,captured_at)
		SELECT gs.source_id,max(gs.balance),s.value_divisor,min(gs.captured_at)
		FROM group_samples gs JOIN sources s ON s.id=gs.source_id WHERE gs.balance IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM source_balance_samples LIMIT 1)
		GROUP BY gs.source_id,s.value_divisor,date_trunc('minute',gs.captured_at) ON CONFLICT DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS targets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, base_url TEXT NOT NULL UNIQUE,
			api_key_cipher BYTEA NOT NULL, key_hint TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'UNKNOWN', version TEXT NOT NULL DEFAULT '',
			write_enabled BOOLEAN NOT NULL DEFAULT false, last_sync_at TIMESTAMPTZ, last_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_metrics_at TIMESTAMPTZ`,
		`CREATE TABLE IF NOT EXISTS target_groups (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
			remote_id TEXT NOT NULL, name TEXT NOT NULL, multiplier NUMERIC(14,6), multiplier_captured_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(target_id, remote_id)
		)`,
		`ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS multiplier NUMERIC(14,6)`,
		`ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS multiplier_captured_at TIMESTAMPTZ`,
		`ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'openai'`,
		`ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS models JSONB NOT NULL DEFAULT '[]'::jsonb`,
		`ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS probe_model TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE target_groups DROP COLUMN IF EXISTS protected_best_priority`,
		`DROP TABLE IF EXISTS protected_accounts`,
		`CREATE TABLE IF NOT EXISTS channels (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			source_key_id UUID NOT NULL REFERENCES source_keys(id) ON DELETE CASCADE, source_group_id UUID REFERENCES source_groups(id) ON DELETE SET NULL,
			lifecycle_state TEXT NOT NULL DEFAULT 'DISCOVERED', state_reason TEXT NOT NULL DEFAULT '', score NUMERIC(8,3),
			priority_tier TEXT NOT NULL DEFAULT 'STANDARD', consecutive_failures INT NOT NULL DEFAULT 0,
			last_probe_at TIMESTAMPTZ, last_slow_sample_at TIMESTAMPTZ, state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(source_key_id, source_group_id)
		)`,
		`ALTER TABLE channels ADD COLUMN IF NOT EXISTS last_slow_sample_at TIMESTAMPTZ`,
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
			priority INT NOT NULL DEFAULT 1000, concurrency INT NOT NULL DEFAULT 1000, schedulable BOOLEAN NOT NULL DEFAULT false,
			ownership_marker TEXT NOT NULL, sync_status TEXT NOT NULL DEFAULT 'PENDING', last_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(target_id, channel_id)
		)`,
		`ALTER TABLE managed_accounts ALTER COLUMN priority SET DEFAULT 1000`,
		`ALTER TABLE managed_accounts ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'openai'`,
		`ALTER TABLE managed_accounts ADD COLUMN IF NOT EXISTS model_mapping_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE managed_accounts ADD COLUMN IF NOT EXISTS business_first_token_ms INT`,
		`ALTER TABLE managed_accounts ADD COLUMN IF NOT EXISTS business_latency_samples INT NOT NULL DEFAULT 0`,
		`ALTER TABLE managed_accounts ADD COLUMN IF NOT EXISTS business_latency_at TIMESTAMPTZ`,
		`ALTER TABLE managed_accounts ALTER COLUMN concurrency SET DEFAULT 1000`,
		`ALTER TABLE managed_accounts DROP CONSTRAINT IF EXISTS managed_accounts_target_id_channel_id_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_accounts_target_remote ON managed_accounts(target_id,remote_id) WHERE remote_id<>''`,
		`DELETE FROM channels c USING source_keys k,source_groups g WHERE c.source_key_id=k.id AND c.source_group_id=g.id AND k.auto_generated=true AND (SELECT count(*) FROM channels siblings WHERE siblings.source_key_id=k.id)>1 AND strpos(k.name,g.name)=0 AND NOT EXISTS(SELECT 1 FROM managed_accounts m WHERE m.channel_id=c.id)`,
		`CREATE TABLE IF NOT EXISTS managed_account_groups (
			managed_account_id UUID NOT NULL REFERENCES managed_accounts(id) ON DELETE CASCADE,
			target_group_id UUID NOT NULL REFERENCES target_groups(id) ON DELETE RESTRICT,
			PRIMARY KEY(managed_account_id, target_group_id)
		)`,
		`CREATE TABLE IF NOT EXISTS deployment_jobs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), source_id UUID NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
			target_id UUID NOT NULL REFERENCES targets(id) ON DELETE RESTRICT, request JSONB NOT NULL,
			status TEXT NOT NULL DEFAULT 'QUEUED', progress_done INT NOT NULL DEFAULT 0, progress_total INT NOT NULL DEFAULT 0,
			result JSONB NOT NULL DEFAULT '{}'::jsonb, error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(), started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ
		)`,
		`UPDATE deployment_jobs SET status='FAILED',error='服务重启中断了后台创建，请重新提交',finished_at=now()
		WHERE status IN ('QUEUED','RUNNING')`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_deployment_jobs_active_source ON deployment_jobs(source_id)
		WHERE status IN ('QUEUED','RUNNING')`,
		`CREATE INDEX IF NOT EXISTS idx_deployment_jobs_source_time ON deployment_jobs(source_id,created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, scope_type TEXT NOT NULL DEFAULT 'GLOBAL', scope_id UUID,
			status TEXT NOT NULL DEFAULT 'DRAFT', active_version INT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`UPDATE policies p SET scope_type='TARGET_GROUP',scope_id=tg.id,updated_at=now() FROM target_groups tg WHERE p.scope_type='GLOBAL' AND p.scope_id IS NULL AND p.name=tg.name AND (SELECT count(*) FROM target_groups matches WHERE matches.name=p.name)=1`,
		`UPDATE policies SET status='DRAFT',active_version=NULL,updated_at=now() WHERE scope_type<>'TARGET_GROUP' OR scope_id IS NULL`,
		`CREATE TABLE IF NOT EXISTS policy_versions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
			version INT NOT NULL, config JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(policy_id, version)
		)`,
		`UPDATE policy_versions v
		SET config=jsonb_set(v.config,'{probeModel}',to_jsonb(tg.probe_model),true)
		FROM policies p JOIN target_groups tg ON tg.id=p.scope_id
		WHERE v.policy_id=p.id AND COALESCE(v.config->>'probeModel','')=''`,
		`CREATE TABLE IF NOT EXISTS action_intents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), managed_account_id UUID REFERENCES managed_accounts(id) ON DELETE SET NULL,
			action_type TEXT NOT NULL, before_state JSONB NOT NULL DEFAULT '{}'::jsonb, after_state JSONB NOT NULL DEFAULT '{}'::jsonb,
			reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', idempotency_key TEXT NOT NULL UNIQUE,
			approved_at TIMESTAMPTZ, executed_at TIMESTAMPTZ, error TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE action_intents DROP CONSTRAINT IF EXISTS action_intents_idempotency_key_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_action_intents_pending_key ON action_intents(idempotency_key) WHERE status IN ('PENDING','APPROVED')`,
		`UPDATE action_intents SET status='REJECTED',error='已由自动策略执行替代',executed_at=now() WHERE status='PENDING'`,
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
		`UPDATE events SET status='RESOLVED',resolved_at=COALESCE(resolved_at,now()) WHERE status<>'RESOLVED' AND category='CHANNEL_PROBE'`,
		`UPDATE channels SET state_reason='源站账户余额不足' WHERE upper(state_reason) LIKE '%INSUFFICIENT_BALANCE%' OR upper(state_reason) LIKE '%INSUFFICIENT ACCOUNT BALANCE%' OR upper(state_reason) LIKE '%BALANCE NOT ENOUGH%' OR upper(state_reason) LIKE '%QUOTA EXHAUSTED%' OR state_reason LIKE '%余额不足%'`,
		`UPDATE probe_runs SET error_type='BALANCE_EXHAUSTED',response_summary='源站账户余额不足' WHERE upper(error_type) LIKE '%INSUFFICIENT_BALANCE%' OR upper(error_type) LIKE '%INSUFFICIENT ACCOUNT BALANCE%' OR upper(error_type) LIKE '%BALANCE NOT ENOUGH%' OR upper(error_type) LIKE '%QUOTA EXHAUSTED%' OR error_type LIKE '%余额不足%'`,
		`UPDATE events SET status='RESOLVED',resolved_at=COALESCE(resolved_at,now()) WHERE status='ACKNOWLEDGED'`,
		`UPDATE events e SET status='RESOLVED',resolved_at=COALESCE(e.resolved_at,now())
		WHERE e.status<>'RESOLVED' AND (e.dedupe_key LIKE 'target-sync:%' OR e.dedupe_key LIKE 'target-rate-limit:%')
		AND NOT EXISTS (
			SELECT 1 FROM targets t
			WHERE t.id::text=split_part(e.dedupe_key,':',2) AND t.status<>'ONLINE'
		)`,
		`WITH ranked AS (
			SELECT id,row_number() OVER (PARTITION BY dedupe_key ORDER BY created_at DESC) AS position
			FROM events WHERE status<>'RESOLVED'
		) UPDATE events SET status='RESOLVED',resolved_at=COALESCE(resolved_at,now())
		WHERE id IN (SELECT id FROM ranked WHERE position>1)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_events_active_dedupe ON events(dedupe_key) WHERE status<>'RESOLVED'`,
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
		"balance_alert_work_hours": "4", "balance_alert_night_hours": "12", "balance_alert_weekend_hours": "36",
		"email_alert_source_balance": "true", "email_alert_source_scan": "true", "email_alert_target_sync": "true",
		"email_alert_group_availability": "true", "email_alert_action_execution": "true", "email_alert_platform_sync": "true",
		"email_alert_recovery": "false",
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

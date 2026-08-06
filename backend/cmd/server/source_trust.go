package main

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
)

func (a *App) updateSourceTrust(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		ManuallyUntrusted bool `json:"manuallyUntrusted"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var name string
	var current bool
	if err = tx.QueryRowContext(r.Context(), `SELECT name,manually_untrusted FROM sources WHERE id=$1 FOR UPDATE`, id).Scan(&name, &current); err != nil {
		if err == sql.ErrNoRows {
			return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
		}
		return err
	}
	if current == input.ManuallyUntrusted {
		_ = tx.Rollback()
		writeData(w, map[string]any{"id": id, "manuallyUntrusted": current})
		return nil
	}
	if input.ManuallyUntrusted {
		var activeJobs int
		if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM deployment_jobs WHERE source_id=$1 AND status IN ('QUEUED','RUNNING')`, id).Scan(&activeJobs); err != nil {
			return err
		}
		if activeJobs > 0 {
			return &apiError{409, "SOURCE_DEPLOYMENT_RUNNING", "该数据源仍有后台创建任务，请等待完成后再标记为不可信"}
		}
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE sources SET manually_untrusted=$2,manually_untrusted_at=CASE WHEN $2 THEN now() ELSE NULL END,updated_at=now() WHERE id=$1`, id, input.ManuallyUntrusted); err != nil {
		return err
	}
	if input.ManuallyUntrusted {
		if _, err = tx.ExecContext(r.Context(), `UPDATE channels SET lifecycle_state='MANUAL_HOLD',state_reason='人工标记数据源不可信',score=0,state_changed_at=now() WHERE source_id=$1`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE action_intents SET status='REJECTED',error='数据源已被人工标记为不可信',executed_at=now()
			WHERE managed_account_id IN (SELECT m.id FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1)
			AND status IN ('PENDING','APPROVED') AND after_state @> '{"schedulable":true}'::jsonb`, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE events SET status='RESOLVED',resolved_at=now()
			WHERE status<>'RESOLVED' AND dedupe_key IN ('source-scan:'||$1,'source-balance:'||$1)`, id); err != nil {
			return err
		}
	} else {
		if _, err = tx.ExecContext(r.Context(), `UPDATE channels SET lifecycle_state='DISCOVERED',state_reason='已取消不可信标记，等待重新验证',score=NULL,consecutive_failures=0,last_probe_at=NULL,state_changed_at=now() WHERE source_id=$1`, id); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.audit(r.Context(), "SET_SOURCE_TRUST", "source", id, map[string]any{"name": name, "manually_untrusted": input.ManuallyUntrusted})
	if input.ManuallyUntrusted {
		rows, queryErr := a.db.QueryContext(r.Context(), `SELECT m.id,m.schedulable FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1`, id)
		if queryErr == nil {
			for rows.Next() {
				var managedID string
				var schedulable bool
				if rows.Scan(&managedID, &schedulable) == nil && schedulable {
					a.enqueueManagedAction(context.Background(), managedID, "SET_SCHEDULABLE", map[string]bool{"schedulable": true}, map[string]bool{"schedulable": false}, "人工标记数据源不可信")
				}
			}
			_ = rows.Close()
		}
	} else {
		go a.runRecovery(context.Background())
	}
	writeData(w, map[string]any{"id": id, "manuallyUntrusted": input.ManuallyUntrusted})
	return nil
}

func (a *App) updateSourceScheduling(w http.ResponseWriter, r *http.Request, id string) error {
	var input struct {
		Paused bool `json:"paused"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var name string
	var current, manuallyUntrusted bool
	if err = tx.QueryRowContext(r.Context(), `SELECT name,scheduling_paused,manually_untrusted FROM sources WHERE id=$1 FOR UPDATE`, id).Scan(&name, &current, &manuallyUntrusted); err != nil {
		if err == sql.ErrNoRows {
			return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
		}
		return err
	}
	if !input.Paused && manuallyUntrusted {
		return &apiError{409, "SOURCE_UNTRUSTED", "该数据源已被标记为不可信，取消不可信标记后才能恢复调度"}
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE sources SET scheduling_paused=$2,scheduling_paused_at=CASE WHEN $2 THEN COALESCE(scheduling_paused_at,now()) ELSE NULL END,updated_at=now() WHERE id=$1`, id, input.Paused); err != nil {
		return err
	}
	if input.Paused {
		if _, err = tx.ExecContext(r.Context(), `UPDATE action_intents SET status='REJECTED',error='数据源已暂停调度',executed_at=now()
			WHERE managed_account_id IN (SELECT m.id FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1)
			AND status IN ('PENDING','APPROVED') AND after_state @> '{"schedulable":true}'::jsonb`, id); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if current != input.Paused {
		a.audit(r.Context(), "SET_SOURCE_SCHEDULING", "source", id, map[string]any{"name": name, "paused": input.Paused})
	}
	if input.Paused {
		rows, queryErr := a.db.QueryContext(r.Context(), `SELECT m.id,m.schedulable FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1`, id)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var managedID string
			var schedulable bool
			if err = rows.Scan(&managedID, &schedulable); err != nil {
				return err
			}
			a.enqueueManagedAction(context.Background(), managedID, "SET_SCHEDULABLE", map[string]bool{"schedulable": schedulable}, map[string]bool{"schedulable": false}, "数据源已人工暂停调度")
		}
		if err = rows.Err(); err != nil {
			return err
		}
	} else {
		go a.runRecovery(context.Background())
		go a.runPolicyEvaluation(context.Background())
	}
	writeData(w, map[string]any{"id": id, "schedulingPaused": input.Paused})
	return nil
}

func sourceIDFromEvent(category, dedupeKey string) string {
	prefix := ""
	switch category {
	case "SOURCE_BALANCE":
		prefix = "source-balance:"
	case "SOURCE_SCAN":
		prefix = "source-scan:"
	default:
		return ""
	}
	if !strings.HasPrefix(dedupeKey, prefix) {
		return ""
	}
	return strings.TrimPrefix(dedupeKey, prefix)
}

func (a *App) sourceIsManuallyUntrusted(ctx context.Context, id string) bool {
	var untrusted bool
	return a.db.QueryRowContext(ctx, `SELECT manually_untrusted FROM sources WHERE id=$1`, id).Scan(&untrusted) == nil && untrusted
}

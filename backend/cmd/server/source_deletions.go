package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type sourceDeletionAccount struct {
	ID, TargetID, RemoteID, OwnershipMarker, BaseURL string
	WriteEnabled                                     bool
}

// deleteSource only records the intent. Remote account deletion can take long
// enough to exceed an HTTP request, so the source is removed by the job worker
// after every owned remote account has been deleted successfully.
func (a *App) deleteSource(w http.ResponseWriter, r *http.Request, sourceID string) error {
	// Serialize against an in-flight mapping update so it cannot create a new
	// remote account after this deletion intent is committed.
	a.mappingMu.Lock()
	defer a.mappingMu.Unlock()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var sourceName, sourceStatus string
	if err = tx.QueryRowContext(r.Context(), `SELECT name,status FROM sources WHERE id=$1 FOR UPDATE`, sourceID).Scan(&sourceName, &sourceStatus); err == sql.ErrNoRows {
		return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
	} else if err != nil {
		return err
	}

	if sourceStatus == "DELETING" {
		var jobID, jobStatus string
		err = tx.QueryRowContext(r.Context(), `SELECT id,status FROM source_deletion_jobs WHERE source_id=$1 AND status IN ('QUEUED','RUNNING') ORDER BY created_at DESC LIMIT 1`, sourceID).Scan(&jobID, &jobStatus)
		if err == nil {
			_ = tx.Rollback()
			writeJSON(w, http.StatusAccepted, map[string]any{"data": map[string]any{"jobId": jobID, "status": jobStatus}})
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}
	} else if sourceStatus != "ACTIVE" {
		return &apiError{409, "SOURCE_DELETE_UNAVAILABLE", "数据源当前不能删除"}
	}

	var activeDeployments int
	if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM deployment_jobs WHERE source_id=$1 AND status IN ('QUEUED','RUNNING')`, sourceID).Scan(&activeDeployments); err != nil {
		return err
	}
	if activeDeployments > 0 {
		return &apiError{409, "SOURCE_DEPLOYMENT_RUNNING", "该数据源仍有后台创建任务，请等待完成后再删除"}
	}

	var accountCount int
	if err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1`, sourceID).Scan(&accountCount); err != nil {
		return err
	}
	jobID := uuid.NewString()
	if _, err = tx.ExecContext(r.Context(), `UPDATE sources SET status='DELETING',scheduling_paused=true,scheduling_paused_at=COALESCE(scheduling_paused_at,now()),updated_at=now() WHERE id=$1`, sourceID); err != nil {
		return err
	}
	// Prevent already queued policy actions from racing the deletion worker.
	if _, err = tx.ExecContext(r.Context(), `UPDATE action_intents SET status='REJECTED',error='数据源正在删除',executed_at=now()
		WHERE managed_account_id IN (SELECT m.id FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1)
		AND status IN ('PENDING','APPROVED')`, sourceID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE managed_accounts m SET schedulable=false,updated_at=now()
		FROM channels c WHERE m.channel_id=c.id AND c.source_id=$1`, sourceID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO source_deletion_jobs(id,source_id,source_name,progress_total) VALUES($1,$2,$3,$4)`, jobID, sourceID, sourceName, accountCount); err != nil {
		if strings.Contains(err.Error(), "idx_source_deletion_jobs_active_source") || strings.Contains(err.Error(), "duplicate key") {
			return &apiError{409, "SOURCE_DELETION_RUNNING", "该数据源已有后台删除任务，请等待完成"}
		}
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}

	operator, _ := r.Context().Value(userContextKey).(Operator)
	go a.runSourceDeletion(jobID, sourceID, operator)
	a.audit(r.Context(), "DELETE_REQUESTED", "source_deletion_job", jobID, map[string]any{"source_id": sourceID, "account_count": accountCount})
	writeJSON(w, http.StatusAccepted, map[string]any{"data": map[string]any{"jobId": jobID, "status": "QUEUED", "progressDone": 0, "progressTotal": accountCount}})
	return nil
}

func (a *App) listSourceDeletionJobs(w http.ResponseWriter, r *http.Request, sourceID string) error {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,status,progress_done,progress_total,result,error,created_at,started_at,finished_at
		FROM source_deletion_jobs WHERE source_id=$1 ORDER BY created_at DESC LIMIT 20`, sourceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, status, result, jobError string
		var done, total int
		var created time.Time
		var started, finished sql.NullTime
		if err = rows.Scan(&id, &status, &done, &total, &result, &jobError, &created, &started, &finished); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "status": status, "progressDone": done, "progressTotal": total, "result": json.RawMessage(result), "error": jobError, "createdAt": created, "startedAt": nullableTime(started), "finishedAt": nullableTime(finished)})
	}
	writeData(w, items)
	return rows.Err()
}

func (a *App) runSourceDeletion(jobID, sourceID string, operator Operator) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if operator.ID != "" {
		ctx = context.WithValue(ctx, userContextKey, operator)
	}
	if _, err := a.db.ExecContext(ctx, `UPDATE source_deletion_jobs SET status='RUNNING',started_at=now() WHERE id=$1 AND status='QUEUED'`, jobID); err != nil {
		a.failSourceDeletion(jobID, sourceID, err)
		return
	}

	rows, err := a.db.QueryContext(ctx, `SELECT m.id,m.target_id,m.remote_id,m.ownership_marker,t.base_url,t.write_enabled
		FROM managed_accounts m JOIN channels c ON c.id=m.channel_id JOIN targets t ON t.id=m.target_id
		WHERE c.source_id=$1 ORDER BY m.created_at`, sourceID)
	if err != nil {
		a.failSourceDeletion(jobID, sourceID, err)
		return
	}
	accounts := []sourceDeletionAccount{}
	for rows.Next() {
		var account sourceDeletionAccount
		if err = rows.Scan(&account.ID, &account.TargetID, &account.RemoteID, &account.OwnershipMarker, &account.BaseURL, &account.WriteEnabled); err != nil {
			_ = rows.Close()
			a.failSourceDeletion(jobID, sourceID, err)
			return
		}
		accounts = append(accounts, account)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		a.failSourceDeletion(jobID, sourceID, err)
		return
	}
	_ = rows.Close()

	sessions := map[string]remoteSession{}
	for index, account := range accounts {
		if account.OwnershipMarker != "" && !strings.HasPrefix(account.OwnershipMarker, "channel-manage:") {
			a.failSourceDeletion(jobID, sourceID, fmt.Errorf("托管账号 %s 所有权标记无效", account.ID))
			return
		}
		if account.RemoteID != "" {
			session, ok := sessions[account.TargetID]
			if !ok {
				target, _, credentialErr := a.targetCredentials(ctx, account.TargetID)
				if credentialErr != nil {
					a.failSourceDeletion(jobID, sourceID, credentialErr)
					return
				}
				if !target.WriteEnabled || !account.WriteEnabled {
					a.failSourceDeletion(jobID, sourceID, fmt.Errorf("目标节点未开启托管写入"))
					return
				}
				authCtx, authCancel := context.WithTimeout(ctx, 2*time.Minute)
				session, err = a.authenticateTarget(authCtx, target, true)
				authCancel()
				if err != nil {
					a.failSourceDeletion(jobID, sourceID, err)
					return
				}
				sessions[account.TargetID] = session
			}
			deleteCtx, deleteCancel := context.WithTimeout(ctx, 2*time.Minute)
			err = a.deleteRemoteManagedAccountChecked(deleteCtx, account.BaseURL, session, account.RemoteID)
			deleteCancel()
			if err != nil {
				a.failSourceDeletion(jobID, sourceID, fmt.Errorf("删除远端托管账号 %s 失败: %w", account.RemoteID, err))
				return
			}
		}
		if err = a.removeSourceManagedAccount(ctx, sourceID, account.ID); err != nil {
			a.failSourceDeletion(jobID, sourceID, err)
			return
		}
		_, _ = a.db.ExecContext(context.Background(), `UPDATE source_deletion_jobs SET progress_done=$2 WHERE id=$1`, jobID, index+1)
	}

	if err = a.finishSourceDeletion(ctx, jobID, sourceID, len(accounts)); err != nil {
		a.failSourceDeletion(jobID, sourceID, err)
		return
	}
	a.resolveEvent(context.Background(), "source-scan:"+sourceID)
	a.resolveEvent(context.Background(), "source-balance:"+sourceID)
	a.audit(ctx, "DELETE", "source", sourceID, map[string]any{"job_id": jobID, "managed_accounts": len(accounts)})
}

func (a *App) removeSourceManagedAccount(ctx context.Context, sourceID, managedID string) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE action_intents SET status='REJECTED',error='托管账号随数据源删除',executed_at=now() WHERE managed_account_id=$1 AND status IN ('PENDING','APPROVED')`, managedID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM managed_accounts m USING channels c WHERE m.id=$1 AND m.channel_id=c.id AND c.source_id=$2`, managedID, sourceID)
	if err != nil {
		return err
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
		return affectedErr
	} else if affected == 0 {
		// A previous attempt may have removed this local row after the remote
		// deletion succeeded. Treat that as an idempotent success.
	}
	return tx.Commit()
}

func (a *App) finishSourceDeletion(ctx context.Context, jobID, sourceID string, deletedCount int) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sourceStatus string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM sources WHERE id=$1 FOR UPDATE`, sourceID).Scan(&sourceStatus); err == sql.ErrNoRows {
		_, updateErr := tx.ExecContext(ctx, `UPDATE source_deletion_jobs SET status='COMPLETED',progress_done=progress_total,result=$2,finished_at=now(),error='' WHERE id=$1 AND status IN ('QUEUED','RUNNING')`, jobID, jsonValue(map[string]any{"deleted": true}))
		if updateErr != nil {
			return updateErr
		}
		return tx.Commit()
	} else if err != nil {
		return err
	}
	if sourceStatus != "DELETING" {
		return fmt.Errorf("数据源状态已变化，无法完成删除")
	}
	var remaining int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1`, sourceID).Scan(&remaining); err != nil {
		return err
	}
	if remaining > 0 {
		return fmt.Errorf("仍有 %d 个托管账号未清理", remaining)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sources WHERE id=$1 AND status='DELETING'`, sourceID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE source_deletion_jobs SET status='COMPLETED',progress_done=progress_total,result=$2,finished_at=now(),error='' WHERE id=$1`, jobID, jsonValue(map[string]any{"deleted": true, "managedAccounts": deletedCount})); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *App) failSourceDeletion(jobID, sourceID string, err error) {
	message := "后台删除失败"
	if err != nil {
		message = truncate(userErrorMessage(err), 500)
	}
	_, _ = a.db.ExecContext(context.Background(), `UPDATE source_deletion_jobs SET status='FAILED',error=$2,finished_at=now() WHERE id=$1 AND status IN ('QUEUED','RUNNING')`, jobID, message)
	auditCtx := context.Background()
	a.audit(auditCtx, "DELETE_FAILED", "source_deletion_job", jobID, map[string]any{"source_id": sourceID, "error": message})
	log.Printf("数据源 %s 删除任务 %s 失败: %s", sourceID, jobID, message)
}

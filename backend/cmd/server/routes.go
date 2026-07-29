package main

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
)

func (a *App) routeAPI(w http.ResponseWriter, r *http.Request, path string) error {
	method := r.Method
	if method == http.MethodPost && path == "/auth/logout" {
		return a.logout(w, r)
	}
	if method == http.MethodGet && path == "/auth/me" {
		writeData(w, r.Context().Value(userContextKey))
		return nil
	}
	if method == http.MethodPatch && path == "/auth/account" {
		return a.updateAccount(w, r)
	}
	if method == http.MethodGet && path == "/dashboard/summary" {
		value, err := a.dashboard(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/dashboard/trends" {
		value, err := a.marketHistory(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/market/groups" {
		value, err := a.marketGroups(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/market/dashboard" {
		value, err := a.marketDashboard(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && (path == "/market/price-history" || path == "/market/managed-price-history") {
		value, err := a.marketHistory(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/sources" {
		value, err := a.listSources(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodPost && path == "/sources" {
		return a.createSource(w, r)
	}
	if method == http.MethodGet && path == "/targets" {
		value, err := a.listTargets(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodPost && path == "/targets" {
		return a.createTarget(w, r)
	}
	if method == http.MethodGet && path == "/channels" {
		value, err := a.listChannels(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/managed-accounts" {
		value, err := a.listManagedAccounts(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodPost && path == "/managed-accounts" {
		return a.createManagedAccount(w, r)
	}
	if method == http.MethodGet && path == "/policies" {
		value, err := a.listPolicies(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodPost && path == "/policies" {
		return a.createPolicy(w, r)
	}
	if method == http.MethodGet && (path == "/action-intents" || path == "/scheduling-current") {
		value, err := a.listActions(r.Context(), path == "/scheduling-current")
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/events" {
		value, err := a.listEvents(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/audit-logs" {
		value, err := a.listAudit(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodGet && path == "/notification-channels" {
		value, err := a.listNotificationChannels(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodPost && path == "/notification-channels" {
		return a.createNotificationChannel(w, r)
	}
	if method == http.MethodGet && path == "/settings" {
		value, err := a.getSettings(r.Context())
		if err != nil {
			return err
		}
		writeData(w, value)
		return nil
	}
	if method == http.MethodPatch && path == "/settings" {
		return a.saveSettings(w, r)
	}
	if method == http.MethodGet && path == "/automation/status" {
		writeData(w, map[string]any{"running": false, "scheduler": "active"})
		return nil
	}
	if method == http.MethodPost && strings.HasPrefix(path, "/automation/") {
		go a.runAutomation(context.Background())
		writeData(w, map[string]string{"status": "ACCEPTED"})
		return nil
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "sources" {
		id := parts[1]
		if len(parts) == 2 && method == http.MethodGet {
			return a.sourceDetail(w, r, id)
		}
		if len(parts) == 2 && method == http.MethodPatch {
			return a.updateSource(w, r, id)
		}
		if len(parts) == 2 && method == http.MethodDelete {
			return a.deleteSource(w, r, id)
		}
		if len(parts) == 3 && parts[2] == "keys" && method == http.MethodPost {
			return a.addSourceKey(w, r, id)
		}
		if len(parts) == 3 && parts[2] == "deploy" && method == http.MethodPost {
			return a.deploySourceGroups(w, r, id)
		}
		if len(parts) == 3 && (parts[2] == "scan" || parts[2] == "test-connection") && method == http.MethodPost {
			go a.scanSource(context.Background(), id)
			writeData(w, map[string]string{"id": id, "status": "ACCEPTED"})
			return nil
		}
		if len(parts) == 4 && parts[2] == "keys" && method == http.MethodDelete {
			return a.deleteSourceKey(w, r, id, parts[3])
		}
	}
	if len(parts) >= 2 && parts[0] == "targets" {
		id := parts[1]
		if len(parts) == 2 && method == http.MethodPatch {
			return a.updateTarget(w, r, id)
		}
		if len(parts) == 2 && method == http.MethodDelete {
			return a.deleteTarget(w, r, id)
		}
		if len(parts) == 3 && parts[2] == "test-connection" && method == http.MethodPost {
			if err := a.syncTarget(r.Context(), id); err != nil {
				return err
			}
			writeData(w, map[string]string{"id": id, "status": "ONLINE"})
			return nil
		}
		if len(parts) == 3 && method == http.MethodGet && (parts[2] == "groups" || parts[2] == "managed-accounts") {
			return a.targetStatus(w, r, id, parts[2])
		}
	}
	if len(parts) == 3 && parts[0] == "channels" && method == http.MethodPost {
		return a.updateChannelState(w, r, parts[1], parts[2])
	}
	if len(parts) == 3 && parts[0] == "events" && method == http.MethodPost {
		return a.updateEvent(w, r, parts[1], parts[2])
	}
	if len(parts) == 3 && parts[0] == "notification-channels" && parts[2] == "test" && method == http.MethodPost {
		return a.testNotification(w, r, parts[1])
	}
	if len(parts) == 3 && parts[0] == "action-intents" && method == http.MethodPost {
		return a.decideAction(w, r, parts[1], parts[2])
	}
	if len(parts) == 3 && parts[0] == "managed-accounts" && parts[2] == "priority" && method == http.MethodPatch {
		return a.updateManagedAccountPriority(w, r, parts[1])
	}
	if len(parts) == 3 && parts[0] == "managed-accounts" && parts[2] == "concurrency" && method == http.MethodPatch {
		return a.updateManagedAccountConcurrency(w, r, parts[1])
	}
	if len(parts) == 3 && parts[0] == "policies" && parts[2] == "versions" && method == http.MethodPost {
		return a.createPolicyVersion(w, r, parts[1])
	}
	if len(parts) == 3 && parts[0] == "policies" && parts[2] == "simulate" && method == http.MethodPost {
		return a.simulatePolicy(w, r, parts[1])
	}
	if len(parts) == 3 && parts[0] == "policies" && parts[2] == "activate-version" && method == http.MethodPost {
		return a.activatePolicy(w, r, parts[1])
	}
	return &apiError{Status: 404, Code: "NOT_FOUND", Message: "接口不存在"}
}

func (a *App) deleteSource(w http.ResponseWriter, r *http.Request, id string) error {
	var count int
	if err := a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_id=$1`, id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return &apiError{409, "SOURCE_IN_USE", "数据源仍有关联托管账号"}
	}
	result, err := a.db.ExecContext(r.Context(), `DELETE FROM sources WHERE id=$1`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "SOURCE_NOT_FOUND", "数据源不存在"}
	}
	a.audit(r.Context(), "DELETE", "source", id, nil)
	writeData(w, map[string]bool{"deleted": true})
	return nil
}

func (a *App) deleteSourceKey(w http.ResponseWriter, r *http.Request, sourceID, keyID string) error {
	var count int
	if err := a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM managed_accounts m JOIN channels c ON c.id=m.channel_id WHERE c.source_key_id=$1`, keyID).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return &apiError{409, "UPSTREAM_KEY_IN_USE", "该 Key 已有关联托管账号"}
	}
	result, err := a.db.ExecContext(r.Context(), `DELETE FROM source_keys WHERE id=$1 AND source_id=$2`, keyID, sourceID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "UPSTREAM_KEY_NOT_FOUND", "Key 不存在"}
	}
	a.audit(r.Context(), "DELETE", "source_key", keyID, nil)
	writeData(w, map[string]bool{"deleted": true})
	return nil
}

func (a *App) deleteTarget(w http.ResponseWriter, r *http.Request, id string) error {
	var count int
	if err := a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM managed_accounts WHERE target_id=$1`, id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return &apiError{409, "TARGET_IN_USE", "目标节点仍有关联托管账号"}
	}
	result, err := a.db.ExecContext(r.Context(), `DELETE FROM targets WHERE id=$1`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return &apiError{404, "TARGET_NOT_FOUND", "目标节点不存在"}
	}
	a.audit(r.Context(), "DELETE", "target", id, nil)
	writeData(w, map[string]bool{"deleted": true})
	return nil
}

var _ = sql.ErrNoRows

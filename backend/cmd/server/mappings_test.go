package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSourceGroupMappingLocksAllowDifferentGroups(t *testing.T) {
	app := &App{}
	firstRelease := make(chan struct{})
	firstAcquired := make(chan struct{})
	go func() {
		unlock := app.lockSourceGroupMapping("source", "group-a")
		close(firstAcquired)
		<-firstRelease
		unlock()
	}()
	<-firstAcquired

	differentAcquired := make(chan struct{})
	go func() {
		unlock := app.lockSourceGroupMapping("source", "group-b")
		close(differentAcquired)
		unlock()
	}()
	select {
	case <-differentAcquired:
	case <-time.After(time.Second):
		t.Fatal("different source groups were serialized")
	}

	sameAcquired := make(chan struct{})
	go func() {
		unlock := app.lockSourceGroupMapping("source", "group-a")
		close(sameAcquired)
		unlock()
	}()
	select {
	case <-sameAcquired:
		t.Fatal("same source group was not serialized")
	case <-time.After(20 * time.Millisecond):
	}
	close(firstRelease)
	select {
	case <-sameAcquired:
	case <-time.After(time.Second):
		t.Fatal("same source group did not resume after release")
	}
}

func TestMappingDifference(t *testing.T) {
	current := []existingMappingAccount{
		{ID: "account-a", TargetGroup: deploymentTargetGroup{ID: "group-a"}},
		{ID: "account-b", TargetGroup: deploymentTargetGroup{ID: "group-b"}},
	}
	desired := []deploymentTargetGroup{{ID: "group-b"}, {ID: "group-c"}}

	kept, removed, added := mappingDifference(current, desired)
	if len(kept) != 1 || kept[0].ID != "account-b" {
		t.Fatalf("unexpected kept mappings: %#v", kept)
	}
	if len(removed) != 1 || removed[0].ID != "account-a" {
		t.Fatalf("unexpected removed mappings: %#v", removed)
	}
	if len(added) != 1 || added[0].ID != "group-c" {
		t.Fatalf("unexpected added mappings: %#v", added)
	}
}

func TestDeleteRemoteManagedAccountCheckedAcceptsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/admin/accounts/42" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	if err := app.deleteRemoteManagedAccountChecked(context.Background(), server.URL, remoteSession{}, "42"); err != nil {
		t.Fatalf("not found should be treated as deleted: %v", err)
	}
}

func TestDeleteRemoteManagedAccountCheckedReturnsRemoteError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"busy"}`, http.StatusConflict)
	}))
	defer server.Close()

	app := &App{httpClient: server.Client()}
	err := app.deleteRemoteManagedAccountChecked(context.Background(), server.URL, remoteSession{}, "42")
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.Code != "REMOTE_REJECTED" {
		t.Fatalf("expected remote conflict, got %v", err)
	}
}

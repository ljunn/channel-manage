package main

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestAccessTokenExpiryReadsJWTSeconds(t *testing.T) {
	expiresAt := time.Unix(1_800_000_000, 0).UTC()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, expiresAt.Unix())))
	got, ok := accessTokenExpiry("header." + payload + ".signature")
	if !ok || !got.Equal(expiresAt) {
		t.Fatalf("accessTokenExpiry()=%v,%v, want %v,true", got, ok, expiresAt)
	}
}

func TestAccessTokenExpiryRejectsOpaqueToken(t *testing.T) {
	if _, ok := accessTokenExpiry("opaque-access-token"); ok {
		t.Fatal("opaque token unexpectedly had an expiry")
	}
}

func TestNextTokenRefreshAtUsesExpiryLead(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if got, want := nextTokenRefreshAt(now.Add(time.Hour), now), now.Add(50*time.Minute); !got.Equal(want) {
		t.Fatalf("nextTokenRefreshAt()=%v, want %v", got, want)
	}
	if got, want := nextTokenRefreshAt(now.Add(5*time.Minute), now), now.Add(4*time.Minute); !got.Equal(want) {
		t.Fatalf("short token nextTokenRefreshAt()=%v, want %v", got, want)
	}
}

func TestTokenRefreshBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 0, want: time.Minute},
		{failures: 1, want: time.Minute},
		{failures: 2, want: 5 * time.Minute},
		{failures: 3, want: 15 * time.Minute},
		{failures: 4, want: time.Hour},
		{failures: 5, want: 6 * time.Hour},
	}
	for _, test := range tests {
		if got := tokenRefreshBackoff(test.failures); got != test.want {
			t.Errorf("tokenRefreshBackoff(%d)=%v, want %v", test.failures, got, test.want)
		}
	}
}

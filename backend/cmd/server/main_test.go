package main

import (
	"net"
	"os"
	"reflect"
	"testing"
)

func TestCredentialEncryptionRoundTrip(t *testing.T) {
	app := &App{cryptoKey: deriveCryptoKey("this-is-a-long-test-secret")}
	plain := []byte(`{"username":"ops@example.com","password":"secret"}`)
	encrypted, err := app.encryptSecret(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(encrypted) == string(plain) {
		t.Fatal("secret was stored as plaintext")
	}
	decrypted, err := app.decryptSecret(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decrypted, plain) {
		t.Fatalf("round trip mismatch: %q", decrypted)
	}
}

func TestCredentialEncryptionRejectsWrongKey(t *testing.T) {
	first := &App{cryptoKey: deriveCryptoKey("first-secret")}
	second := &App{cryptoKey: deriveCryptoKey("second-secret")}
	encrypted, err := first.encryptSecret([]byte("credential"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.decryptSecret(encrypted); err == nil {
		t.Fatal("wrong key decrypted credential")
	}
}

func TestValidateRemoteURLRejectsUnsafeTargets(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_UPSTREAMS", "false")
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "false")
	for _, value := range []string{"http://example.com", "https://127.0.0.1", "https://10.0.0.2", "file:///etc/passwd"} {
		if _, err := validateRemoteURL(value); err == nil {
			t.Errorf("expected %q to be rejected", value)
		}
	}
}

func TestValidateRemoteURLNormalizesOrigin(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("requires external DNS")
	}
	value, err := validateRemoteURL("https://example.com/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if value != "https://example.com" {
		t.Fatalf("got %q", value)
	}
}

func TestUnwrapEnvelope(t *testing.T) {
	value, err := unwrapEnvelope(map[string]any{"code": float64(0), "message": "ok", "data": map[string]any{"id": float64(1)}}, "SUB2API")
	if err != nil {
		t.Fatal(err)
	}
	if value.(map[string]any)["id"] != float64(1) {
		t.Fatalf("unexpected value: %#v", value)
	}
	if _, err := unwrapEnvelope(map[string]any{"success": false}, "NEW_API"); err == nil {
		t.Fatal("failed response was accepted")
	}
}

func TestStableKey(t *testing.T) {
	first := stableKey("account", "SET_SCHEDULABLE", "true")
	if first != stableKey("account", "SET_SCHEDULABLE", "true") {
		t.Fatal("key is not stable")
	}
	if first == stableKey("account", "SET_SCHEDULABLE", "false") {
		t.Fatal("different actions shared a key")
	}
}

func TestUnsafeRemoteIP(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "::1"} {
		if !unsafeRemoteIP(net.ParseIP(value)) {
			t.Errorf("expected %s to be unsafe", value)
		}
	}
	if unsafeRemoteIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public IP was blocked")
	}
}

func TestPercentile(t *testing.T) {
	if got := percentile([]int{40, 10, 30, 20}, .95); got != 40 {
		t.Fatalf("p95=%v", got)
	}
	if got := percentile(nil, .5); got != nil {
		t.Fatalf("empty percentile=%v", got)
	}
}

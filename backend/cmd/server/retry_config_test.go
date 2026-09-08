package main

import (
	"reflect"
	"testing"
)

func TestParsePoolModeRetryStatusCodesDefaultsAndValidates(t *testing.T) {
	codes, err := parsePoolModeRetryStatusCodes("")
	if err != nil || !reflect.DeepEqual(codes, []int{401, 403, 429}) {
		t.Fatalf("empty setting codes=%v err=%v, want [401 403 429]", codes, err)
	}
	codes, err = parsePoolModeRetryStatusCodes(" 401, 429,401, 500 ")
	if err != nil || !reflect.DeepEqual(codes, []int{401, 429, 500}) {
		t.Fatalf("normalized setting codes=%v err=%v", codes, err)
	}
	for _, value := range []string{"99", "600", "401,,429", "abc", "503, 700"} {
		if _, err = parsePoolModeRetryStatusCodes(value); err == nil {
			t.Errorf("invalid setting %q was accepted", value)
		}
	}
}

func TestFormatPoolModeRetryStatusCodes(t *testing.T) {
	if formatted := formatPoolModeRetryStatusCodes([]int{401, 403, 429}); formatted != "401,403,429" {
		t.Fatalf("formatted=%q", formatted)
	}
}

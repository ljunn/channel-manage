package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func qualityTaskResults(allPassed bool) []modelQualityTaskResult {
	results := make([]modelQualityTaskResult, 0, len(modelQualityTasks("QC-TEST")))
	for _, task := range modelQualityTasks("QC-TEST") {
		results = append(results, modelQualityTaskResult{
			ID: task.ID, Passed: allPassed, Weight: task.Weight, Critical: task.Critical, Reason: "测试结果",
		})
	}
	return results
}

func TestModelQualityVerdictUsesWeightedCriticalGate(t *testing.T) {
	status, score, _ := modelQualityVerdict(qualityTaskResults(true), nil)
	if status != modelCheckPassed || score == nil || *score != 100 {
		t.Fatalf("all-pass verdict=%s score=%v", status, score)
	}

	results := qualityTaskResults(true)
	results[4].Passed = false // non-critical code task, 15 points
	status, score, _ = modelQualityVerdict(results, nil)
	if status != modelCheckPassed || score == nil || *score != 85 {
		t.Fatalf("single non-critical failure verdict=%s score=%v", status, score)
	}

	results = qualityTaskResults(true)
	results[1].Passed = false // one critical failure remains an indeterminate result
	status, score, _ = modelQualityVerdict(results, nil)
	if status != modelCheckUnknown || score == nil || *score != 80 {
		t.Fatalf("single critical failure verdict=%s score=%v", status, score)
	}

	results = qualityTaskResults(true)
	results[0].Passed = false
	results[1].Passed = false
	status, score, _ = modelQualityVerdict(results, nil)
	if status != modelCheckFailed || score == nil || *score != 65 {
		t.Fatalf("two critical failures verdict=%s score=%v", status, score)
	}

	results = qualityTaskResults(true)
	results[0].Technical = true
	status, score, _ = modelQualityVerdict(results, nil)
	if status != modelCheckUnknown || score != nil {
		t.Fatalf("technical failure verdict=%s score=%v", status, score)
	}
	status, score, _ = modelQualityVerdict(nil, errors.New("network down"))
	if status != modelCheckUnknown || score != nil {
		t.Fatalf("technical error verdict=%s score=%v", status, score)
	}
}

func TestModelQualityValidatorsRejectNearMisses(t *testing.T) {
	if ok, _ := validateQualityJSON(`{"answer":27,"valid":true,"items":["red","blue"]}`); !ok {
		t.Fatal("valid JSON probe was rejected")
	}
	for _, output := range []string{
		`{"answer":"27","valid":true,"items":["red","blue"]}`,
		`{"answer":27.0,"valid":true,"items":["red","blue"]}`,
		`{"answer":27,"valid":null,"items":["red","blue"]}`,
		`{"answer":27,"valid":true,"items":["red","blue"]} {"extra":1}`,
		`{"answer":27,"answer":27,"valid":true,"items":["red","blue"]}`,
		`{"answer":27,"valid":true,"items":["red","blue"],"extra":1}`,
		"```json\n{\"answer\":27,\"valid\":true,\"items\":[\"red\",\"blue\"]}\n```",
	} {
		if ok, _ := validateQualityJSON(output); ok {
			t.Errorf("near-miss JSON was accepted: %q", output)
		}
	}
	if ok, _ := validateQualityCodeExpression("items[::-1]"); !ok {
		t.Fatal("valid code expression was rejected")
	}
	if ok, _ := validateQualityCodeExpression("items.reverse()"); ok {
		t.Fatal("mutating code expression was accepted")
	}
}

func TestModelQualityProbeValuesVaryAndGeneratedAnswersValidate(t *testing.T) {
	first := modelQualityProbeValuesFor("QC-ALPHA")
	second := modelQualityProbeValuesFor("QC-BRAVO")
	if first.ArithmeticPrompt == second.ArithmeticPrompt || first.LogicPrompt == second.LogicPrompt || first.JSONPrompt == second.JSONPrompt || first.CodePrompt == second.CodePrompt || first.HallucinationPrompt == second.HallucinationPrompt {
		t.Fatal("probe values did not vary with the challenge")
	}
	if ok, reason := modelQualityTasks("QC-ALPHA")[1].Validate(first.ArithmeticAnswer); !ok {
		t.Fatalf("generated arithmetic answer was rejected: %s", reason)
	}
	if ok, reason := modelQualityTasks("QC-ALPHA")[2].Validate(first.LogicAnswer); !ok {
		t.Fatalf("generated logic answer was rejected: %s", reason)
	}
	encodedItems, err := json.Marshal(first.JSONItems)
	if err != nil {
		t.Fatalf("marshal generated JSON items: %v", err)
	}
	jsonOutput := fmt.Sprintf(`{"answer":%d,"valid":%t,"items":%s}`, first.JSONAnswer, first.JSONValid, encodedItems)
	if ok, reason := first.JSONValidator(jsonOutput); !ok {
		t.Fatalf("generated JSON answer was rejected: %s", reason)
	}
	if ok, reason := modelQualityTasks("QC-ALPHA")[4].Validate(first.CodeAnswer); !ok {
		t.Fatalf("generated code answer was rejected: %s", reason)
	}
}

func TestModelQualityLogicConstraintsRemainUnique(t *testing.T) {
	permutations := func(values []string) [][]string {
		var build func([]string) [][]string
		build = func(remaining []string) [][]string {
			if len(remaining) == 0 {
				return [][]string{{}}
			}
			result := make([][]string, 0)
			for index, value := range remaining {
				next := append([]string(nil), remaining[:index]...)
				next = append(next, remaining[index+1:]...)
				for _, suffix := range build(next) {
					result = append(result, append([]string{value}, suffix...))
				}
			}
			return result
		}
		return build(values)
	}

	for _, challenge := range []string{"QC-ALPHA", "QC-BRAVO", "QC-DELTA", "QC-OMEGA"} {
		seed := sha256.Sum256([]byte(challenge))
		names := []string{"A", "B", "C", "D", "E"}
		for index := len(names) - 1; index > 0; index-- {
			swap := int(seed[5+index] % byte(index+1))
			names[index], names[swap] = names[swap], names[index]
		}
		solutions := 0
		for _, order := range permutations(names) {
			positions := map[string]int{}
			for index, name := range order {
				positions[name] = index
			}
			if positions[names[1]] != positions[names[0]]+1 ||
				positions[names[3]] != positions[names[2]]+1 ||
				positions[names[1]] >= positions[names[2]] ||
				absQualityInt(positions[names[4]]-positions[names[0]]) == 1 ||
				positions[names[3]] == 4 {
				continue
			}
			solutions++
		}
		if solutions != 1 {
			t.Fatalf("challenge %s produced %d logic solutions", challenge, solutions)
		}
	}
}

func absQualityInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func TestModelQualityResponseParsing(t *testing.T) {
	content, usage, err := parseModelQualityResponse(map[string]any{
		"choices": []any{map[string]any{
			"finish_reason": "stop",
			"message":       map[string]any{"content": " ANSWER=50 "},
		}},
		"usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 4},
	})
	if err != nil || content != " ANSWER=50 " || usage.TotalTokens != 16 {
		t.Fatalf("parsed content=%q usage=%+v err=%v", content, usage, err)
	}

	content, _, err = parseModelQualityResponse(map[string]any{
		"choices": []any{map[string]any{
			"message": map[string]any{"content": []any{
				map[string]any{"type": "text", "text": "SYSTEM-"},
				map[string]any{"type": "text", "text": "OK"},
			}},
		}},
	})
	if err != nil || content != "SYSTEM-OK" {
		t.Fatalf("content parts=%q err=%v", content, err)
	}
	content, usage, err = parseModelQualityResponse(map[string]any{
		"usage": map[string]any{"prompt_tokens": 9, "completion_tokens": 3},
		"data": map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"content": []any{
				map[string]any{"type": "reasoning", "text": "hidden"},
				map[string]any{"type": "output_text", "text": "FINAL"},
			}},
		}}},
	})
	if err != nil || content != "FINAL" || usage.TotalTokens != 12 {
		t.Fatalf("reasoning content parts=%q usage=%+v err=%v", content, usage, err)
	}
	for _, value := range []any{
		map[string]any{"choices": []any{map[string]any{"finish_reason": "length", "message": map[string]any{"content": "x"}}}},
		map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": ""}}}},
		map[string]any{"choices": []any{}},
	} {
		if _, _, err := parseModelQualityResponse(value); err == nil {
			t.Errorf("invalid response was accepted: %#v", value)
		}
	}
	content, usage, err = parseModelQualityResponse(map[string]any{
		"data": map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{"content": []any{map[string]any{"type": "output_text", "text": "OK"}}},
			}},
			"usage": map[string]any{"input_tokens": 8, "output_tokens": 2, "total_tokens": 10},
		},
	})
	if err != nil || content != "OK" || usage.TotalTokens != 10 {
		t.Fatalf("wrapped response content=%q usage=%+v err=%v", content, usage, err)
	}
	for _, value := range []any{
		map[string]any{"choices": []any{map[string]any{"message": map[string]any{"refusal": "不能完成"}}}},
		map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": []any{map[string]any{"type": "refusal", "refusal": "不能完成"}}}}}},
	} {
		if _, _, err := parseModelQualityResponse(value); err == nil {
			t.Errorf("explicit refusal was accepted: %#v", value)
		}
	}
}

func TestModelQualityPayload(t *testing.T) {
	regular := modelQualityPayload("gpt-4.1-mini", modelQualityTasks("QC-TEST")[0])
	if regular["max_tokens"] != modelQualityMaxOutputTokens || regular["temperature"] != 0 {
		t.Fatalf("regular payload=%#v", regular)
	}
	reasoning := modelQualityPayload("gpt-5", modelQualityTasks("QC-TEST")[0])
	if reasoning["max_completion_tokens"] != modelQualityReasoningOutputTokens {
		t.Fatalf("reasoning payload=%#v", reasoning)
	}
	aliasedReasoning := modelQualityPayload("openai/gpt-5", modelQualityTasks("QC-TEST")[0])
	if aliasedReasoning["max_completion_tokens"] != modelQualityReasoningOutputTokens || aliasedReasoning["temperature"] != nil {
		t.Fatalf("aliased reasoning payload=%#v", aliasedReasoning)
	}
}

func TestModelQualityUsesGlobalProbeModel(t *testing.T) {
	model, err := resolveModelQualityProbeModel("")
	if err != nil || model != defaultModelQualityProbeModel {
		t.Fatalf("default global quality model=%q err=%v", model, err)
	}
	model, err = resolveModelQualityProbeModel("  custom-quality-model  ")
	if err != nil || model != "custom-quality-model" {
		t.Fatalf("configured global quality model=%q err=%v", model, err)
	}
	// A configured model is intentionally accepted even when it is absent from
	// the cached /models response; the global setting must be sent as-is rather
	// than silently switching to another model.
	model, err = resolveModelQualityProbeModel("gpt-5.6-sol")
	if err != nil || model != "gpt-5.6-sol" {
		t.Fatalf("unlisted global quality model=%q err=%v", model, err)
	}
	if _, err = resolveModelQualityProbeModel("bad\nmodel"); err == nil {
		t.Fatal("control characters in global quality model were accepted")
	}
}

func TestModelQualitySchedulingGateMatrix(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		required bool
		override bool
		blocked  bool
	}{
		{"legacy", modelCheckLegacy, false, false, false},
		{"legacy-empty", "", false, false, false},
		{"existing-pending", modelCheckPending, false, false, false},
		{"existing-running", modelCheckRunning, false, false, false},
		{"existing-unknown", modelCheckUnknown, false, false, false},
		{"existing-failed", modelCheckFailed, false, false, true},
		{"new-pending", modelCheckPending, true, false, true},
		{"new-running", modelCheckRunning, true, false, true},
		{"new-unknown", modelCheckUnknown, true, false, true},
		{"new-failed", modelCheckFailed, true, false, true},
		{"new-unknown-value", "UNEXPECTED", true, false, true},
		{"forced", modelCheckFailed, true, true, false},
		{"passed", modelCheckPassed, true, false, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := modelQualityBlocksSchedulingFor(test.status, test.required, test.override); got != test.blocked {
				t.Fatalf("blocked=%v, want %v", got, test.blocked)
			}
		})
	}
}

func TestModelQualityPassClearsOnlyTheInitialRequiredGate(t *testing.T) {
	cases := []struct {
		name     string
		required bool
		status   string
		want     bool
	}{
		{"new-pass", true, modelCheckPassed, false},
		{"new-technical-unknown", true, modelCheckUnknown, true},
		{"new-capability-failure", true, modelCheckFailed, true},
		{"existing-pass", false, modelCheckPassed, false},
		{"existing-technical-unknown", false, modelCheckUnknown, false},
		{"existing-capability-failure", false, modelCheckFailed, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := modelQualityRequiredAfterResult(test.required, test.status); got != test.want {
				t.Fatalf("required=%v, want %v", got, test.want)
			}
		})
	}
}

func TestModelQualityLifecycleHeldOnlyForQualityGate(t *testing.T) {
	cases := []struct {
		name, state, reason string
		want                bool
	}{
		{"new-quality-gate", "DISCOVERED", "等待模型能力检测", true},
		{"quality-running", "VALIDATING", "模型能力检测进行中", true},
		{"quality-failure", "QUARANTINED", "模型能力检测不通过：能力分过低", true},
		{"ordinary-first-probe", "DISCOVERED", "等待首次探测", false},
		{"ordinary-revalidation", "VALIDATING", "等待重新验证", false},
		{"ordinary-quarantine", "QUARANTINED", "REMOTE_UNAVAILABLE", false},
		{"manual-hold", "MANUAL_HOLD", "等待模型能力检测", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := modelQualityLifecycleHeld(test.state, test.reason); got != test.want {
				t.Fatalf("held=%v, want %v", got, test.want)
			}
		})
	}
}

func TestModelQualityOwnsHealthLifecycle(t *testing.T) {
	if !modelQualityOwnsHealthLifecycle(modelCheckPending, true, false, "HEALTHY", "最近流式抽样成功") {
		t.Fatal("required pending channel released to health probe")
	}
	if !modelQualityOwnsHealthLifecycle(modelCheckFailed, false, false, "HEALTHY", "") {
		t.Fatal("failed quality result did not retain lifecycle ownership")
	}
	if modelQualityOwnsHealthLifecycle(modelCheckUnknown, false, false, "HEALTHY", "最近流式抽样成功") {
		t.Fatal("legacy technical unknown took over lifecycle")
	}
	if modelQualityOwnsHealthLifecycle(modelCheckFailed, true, true, "QUARANTINED", "模型能力检测不通过") {
		t.Fatal("override did not release quality lifecycle ownership")
	}
	if !modelQualityOwnsHealthLifecycle(modelCheckRunning, false, false, "QUARANTINED", "模型能力检测不通过：能力失败") {
		t.Fatal("quality quarantine was released during a rerun")
	}
	if modelQualityOwnsHealthLifecycle(modelCheckRunning, false, false, "HEALTHY", "模型能力检测通过") {
		t.Fatal("ordinary healthy lifecycle was claimed by a technical rerun")
	}
}

func TestRestoreModelQualityLifecycleDoesNotOverwriteOrdinaryHealthState(t *testing.T) {
	nextState, nextReason, score, changed := restoreModelQualityLifecycle("HEALTHY", "最近流式抽样成功", modelCheckPassed, "gpt-test", "通过", sql.NullFloat64{Float64: 100, Valid: true}, false)
	if changed || nextState != "HEALTHY" || nextReason != "最近流式抽样成功" || score != nil {
		t.Fatalf("ordinary health state was overwritten: %q %q %v %v", nextState, nextReason, score, changed)
	}
	nextState, nextReason, score, changed = restoreModelQualityLifecycle("HEALTHY", "人工强制通过模型能力检测", modelCheckFailed, "gpt-test", "1/7 项任务通过", sql.NullFloat64{Float64: 14, Valid: true}, true)
	if !changed || nextState != "QUARANTINED" || score != 0 || !strings.Contains(nextReason, "1/7") {
		t.Fatalf("failed quality result was not restored: %q %q %v %v", nextState, nextReason, score, changed)
	}
	nextState, nextReason, score, changed = restoreModelQualityLifecycle("VALIDATING", "人工强制通过模型能力检测，等待健康验证", modelCheckPassed, "gpt-test", "7/7 项任务通过", sql.NullFloat64{Float64: 100, Valid: true}, false)
	if !changed || nextState != "VALIDATING" || score != nil || !strings.Contains(nextReason, "等待健康验证") {
		t.Fatalf("quality pass bypassed health validation: %q %q %v %v", nextState, nextReason, score, changed)
	}
	nextState, nextReason, score, changed = restoreModelQualityLifecycle("HEALTHY", "最近流式抽样成功", modelCheckUnknown, "gpt-test", "技术请求失败", sql.NullFloat64{}, true)
	if !changed || nextState != "DISCOVERED" || score != nil || !strings.Contains(nextReason, "等待模型能力检测") {
		t.Fatalf("required unknown result was not restored to the quality gate: %q %q %v %v", nextState, nextReason, score, changed)
	}
}

func TestModelQualityTasksHaveStableWeightsAndCriticalCoverage(t *testing.T) {
	tasks := modelQualityTasks("QC-TEST")
	if len(tasks) != 7 {
		t.Fatalf("task count=%d", len(tasks))
	}
	total := 0
	critical := 0
	for _, task := range tasks {
		total += task.Weight
		if task.Critical {
			critical++
		}
	}
	if total != 100 || critical < 4 {
		t.Fatalf("weights=%d critical=%d", total, critical)
	}
	if !reflect.DeepEqual(modelQualityTasks("QC-TEST")[0].ID, "instruction_exact") {
		t.Fatal("first task changed unexpectedly")
	}
}

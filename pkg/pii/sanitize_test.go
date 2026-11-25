package pii

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSkipPII(t *testing.T) {
	tests := []struct {
		given string
		want  bool
	}{
		{"customer.email_address", true},
		{"payment.CVV", true},
		{"billing.postal-code", true},
		{"profile.dateOfBirth", true},
		{"raw_api_key", true},
		{"account", true},
		{"confusable-сvv", true},
		{"display_mode", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_checking_Then_skip_is_"+fmt.Sprint(tt.want), func(t *testing.T) {
			if got := SkipPII(tt.given); got != tt.want {
				t.Fatalf("SkipPII() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestSanitizeForAgentDropAndRedact(t *testing.T) {
	input := map[string]any{
		"status":    "ready",
		"full_name": "Synthetic Person",
		"details": map[string]any{
			"email": "person@example.test",
			"note":  "Reach person@example.test after the appointment",
		},
		"items": []any{"ordinary text", "Account 1234567890123456"},
	}

	dropped, err := SanitizeForAgent(input, Options{})
	if err != nil {
		t.Fatalf("SanitizeForAgent(drop) error = %v", err)
	}
	root := dropped.(map[string]any)
	if root["status"] != "ready" {
		t.Fatalf("safe field was changed: %#v", root["status"])
	}
	if _, ok := root["full_name"]; ok {
		t.Fatal("sensitive name field was not dropped")
	}
	details := root["details"].(map[string]any)
	if _, ok := details["email"]; ok {
		t.Fatal("sensitive email field was not dropped")
	}
	if _, ok := details["note"]; ok {
		t.Fatal("free-text PII field was not dropped")
	}
	items := root["items"].([]any)
	if len(items) != 1 || items[0] != "ordinary text" {
		t.Fatalf("sensitive slice element was not dropped: %#v", items)
	}

	redacted, err := SanitizeForAgent(input, Options{Mode: ModeRedact})
	if err != nil {
		t.Fatalf("SanitizeForAgent(redact) error = %v", err)
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, secret := range []string{"Synthetic Person", "person@example.test", "1234567890123456"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("sanitized output contains sensitive value %q", secret)
		}
	}
	if !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("sanitized output does not contain a redaction marker: %s", encoded)
	}
}

func TestSanitizeNestedStructsAndJSON(t *testing.T) {
	type profile struct {
		Email string `json:"email"`
		State string `json:"state"`
	}
	type payload struct {
		Profile profile `json:"profile"`
		CVV     string  `json:"cvv"`
	}
	value, err := SanitizeForAgent(payload{
		Profile: profile{Email: "person@example.test", State: "active"},
		CVV:     "123",
	}, Options{Mode: ModeRedact})
	if err != nil {
		t.Fatalf("SanitizeForAgent(struct) error = %v", err)
	}
	structOutput := fmt.Sprint(value)
	for _, secret := range []string{"person@example.test", "123"} {
		if strings.Contains(structOutput, secret) {
			t.Fatalf("sanitized struct contains sensitive value %q", secret)
		}
	}
	if !strings.Contains(structOutput, "active") {
		t.Fatalf("safe struct field was removed: %s", structOutput)
	}

	for _, raw := range []json.RawMessage{
		[]byte(`{"email":"person@example.test","safe":"ok"}`),
		[]byte(`{"email":`),
	} {
		out, err := SanitizeForAgent(raw, Options{Mode: ModeRedact})
		if err != nil {
			t.Fatalf("SanitizeForAgent(JSON) error = %v", err)
		}
		if strings.Contains(fmt.Sprint(out), "person@example.test") {
			t.Fatalf("sanitized JSON contains email: %v", out)
		}
	}
}

func TestSanitizeFreeTextAndUnicodeDigits(t *testing.T) {
	input := "Call 212-555-0100; DOB: 04/12/1990; email person@example.test."
	output, err := SanitizeForAgent(input, Options{Mode: ModeRedact})
	if err != nil {
		t.Fatalf("SanitizeForAgent() error = %v", err)
	}
	safe := output.(string)
	for _, secret := range []string{"212-555-0100", "04/12/1990", "person@example.test"} {
		if strings.Contains(safe, secret) {
			t.Fatalf("free-text sanitizer exposed %q: %s", secret, safe)
		}
	}
	fullWidthPAN := "４１１１１１１１１１１１１１１１"
	output, err = SanitizeForAgent("Card "+fullWidthPAN, Options{Mode: ModeRedact})
	if err != nil {
		t.Fatalf("SanitizeForAgent(Unicode digits) error = %v", err)
	}
	if strings.Contains(output.(string), fullWidthPAN) {
		t.Fatal("Unicode digit lookalike value was not redacted")
	}
	confusableEmail := "persоn＠example．test"
	output, err = SanitizeForAgent(confusableEmail, Options{Mode: ModeRedact})
	if err != nil {
		t.Fatalf("SanitizeForAgent(Unicode email) error = %v", err)
	}
	if strings.Contains(output.(string), confusableEmail) {
		t.Fatal("Unicode email lookalike was not redacted")
	}
	shortCVV, err := SanitizeForAgent("123", Options{Mode: ModeRedact})
	if err != nil || shortCVV != "[REDACTED]" {
		t.Fatalf("SanitizeForAgent(short CVV) = %v, %v", shortCVV, err)
	}
	floatPAN, err := SanitizeForAgent(float64(4111111111111111), Options{Mode: ModeRedact})
	if err != nil || floatPAN != "[REDACTED]" {
		t.Fatalf("SanitizeForAgent(numeric PAN) = %v, %v", floatPAN, err)
	}
}

func TestSanitizePartialModesNeverExposeHighRisk(t *testing.T) {
	tests := []struct {
		mode Mode
	}{
		{ModeChar},
		{ModeLast4},
		{ModePrefix},
		{ModeToken},
	}
	for _, tt := range tests {
		t.Run("Given_high_risk_fields_When_"+string(tt.mode)+"_Then_fully_redact", func(t *testing.T) {
			value, err := SanitizeForAgent(map[string]any{
				"cvv":      "123",
				"card_pan": "4111111111111111",
				"api_key":  "synthetic-credential",
				"email":    "person@example.test",
			}, Options{Mode: tt.mode, TokenKey: []byte(strings.Repeat("k", 32))})
			if err != nil {
				t.Fatalf("SanitizeForAgent() error = %v", err)
			}
			output := fmt.Sprint(value)
			for _, secret := range []string{"123", "4111111111111111", "synthetic-credential"} {
				if strings.Contains(output, secret) {
					t.Fatalf("mode %q exposed high-risk value %q: %s", tt.mode, secret, output)
				}
			}
		})
	}
	last4, err := SanitizeForAgent(map[string]any{"email": "person@example.test"}, Options{Mode: ModeLast4})
	if err != nil {
		t.Fatalf("SanitizeForAgent(last4) error = %v", err)
	}
	if strings.Contains(fmt.Sprint(last4), "person@example.test") {
		t.Fatalf("last4 output retained the full email: %v", last4)
	}
	for _, value := range []any{"123", []int{1, 2, 3}, [16]byte{'4', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'}} {
		output, err := SanitizeForAgent(value, Options{Mode: ModeLast4})
		if err != nil {
			t.Fatalf("SanitizeForAgent(high-risk scalar) error = %v", err)
		}
		if fmt.Sprint(output) != "[REDACTED]" {
			t.Fatalf("high-risk numeric representation was partially exposed: %v", output)
		}
	}
	mixedRisk, err := SanitizeForAgent(map[string]any{
		"email.account": "synthetic-account",
	}, Options{Mode: ModeLast4})
	if err != nil {
		t.Fatalf("SanitizeForAgent(mixed-risk field) error = %v", err)
	}
	if got := mixedRisk.(map[string]any)["email.account"]; got != "[REDACTED]" {
		t.Fatalf("mixed-risk field was not fully redacted: %v", got)
	}
}

func TestSanitizeTokenAndAllowlist(t *testing.T) {
	input := map[string]any{
		"status":  "approved",
		"email":   "person@example.test",
		"api_key": "synthetic-credential",
	}
	options := Options{Mode: ModeToken, TokenKey: []byte(strings.Repeat("s", 32))}
	first, err := SanitizeForAgent(input, options)
	if err != nil {
		t.Fatalf("SanitizeForAgent(token) error = %v", err)
	}
	second, err := SanitizeForAgent(input, options)
	if err != nil {
		t.Fatalf("SanitizeForAgent(token) error = %v", err)
	}
	if fmt.Sprint(first) != fmt.Sprint(second) || strings.Contains(fmt.Sprint(first), "person@example.test") {
		t.Fatalf("tokenization was not deterministic and private: %v, %v", first, second)
	}

	allowed, err := SanitizeForAgent(input, Options{
		Mode: ModeAllowlist, Allowlist: []string{"status", "email"},
	})
	if err != nil {
		t.Fatalf("SanitizeForAgent(allowlist) error = %v", err)
	}
	result := allowed.(map[string]any)
	if result["status"] != "approved" || result["email"] != "[REDACTED]" {
		t.Fatalf("allowlist result = %#v", result)
	}
	if _, ok := result["api_key"]; ok {
		t.Fatal("unknown field was not dropped by allowlist")
	}
	nested, err := SanitizeForAgent(map[string]any{
		"profile": map[string]any{"safe": "kept", "email": "person@example.test"},
	}, Options{Mode: ModeAllowlist, Allowlist: []string{"profile.safe"}})
	if err != nil {
		t.Fatalf("SanitizeForAgent(nested allowlist) error = %v", err)
	}
	profile := nested.(map[string]any)["profile"].(map[string]any)
	if profile["safe"] != "kept" || len(profile) != 1 {
		t.Fatalf("nested allowlist result = %#v", profile)
	}
}

func TestSanitizeForAgentSafeDegradation(t *testing.T) {
	tests := []struct {
		given string
		input any
		opts  Options
	}{
		{"nil input", nil, Options{}},
		{"empty map", map[string]any{}, Options{}},
		{"empty slice", []any{}, Options{}},
		{"unsupported channel", make(chan int), Options{}},
		{"oversized string", "123456789012345678901", Options{MaxInputBytes: 20}},
		{"malformed JSON", `{"email":`, Options{}},
		{"invalid UTF-8", string([]byte{0xff}), Options{}},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_sanitizing_Then_no_error", func(t *testing.T) {
			if _, err := SanitizeForAgent(tt.input, tt.opts); err != nil {
				t.Fatalf("SanitizeForAgent() error = %v", err)
			}
		})
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if _, err := SanitizeForAgent(cycle, Options{MaxDepth: 8}); err != nil {
		t.Fatalf("SanitizeForAgent(cycle) error = %v", err)
	}
	largeList := make([]int, 100)
	out, err := SanitizeForAgent(largeList, Options{MaxNodes: 10})
	if err != nil {
		t.Fatalf("SanitizeForAgent(limited nodes) error = %v", err)
	}
	if len(out.([]any)) >= len(largeList) {
		t.Fatalf("node limit did not truncate input: len=%d", len(out.([]any)))
	}
}

func TestSanitizeOptionsFailClosed(t *testing.T) {
	for _, options := range []Options{
		{Mode: "invalid"},
		{Mode: ModeToken},
		{Mode: ModeAllowlist, Allowlist: []string{"!!!"}},
		{MaxDepth: 129},
	} {
		_, err := SanitizeForAgent("sensitive", options)
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("SanitizeForAgent(%+v) error = %v, want invalid configuration", options, err)
		}
	}
}

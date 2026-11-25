package payment

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestValidatePAN(t *testing.T) {
	tests := []struct {
		given   string
		value   string
		options PANOptions
		want    Reason
		scheme  Scheme
	}{
		{"synthetic valid Visa", "4111111111111111", PANOptions{DetectScheme: true}, ReasonValid, SchemeVisa},
		{"valid with configured separators", "4111-1111 1111-1111", PANOptions{StripSeparators: true}, ReasonValid, SchemeUnknown},
		{"checksum failure", "4111111111111112", PANOptions{}, ReasonChecksumMismatch, SchemeUnknown},
		{"12 digit boundary", "411111111111", PANOptions{}, ReasonInvalidLength, SchemeUnknown},
		{"13 digit boundary", "4222222222222", PANOptions{}, ReasonValid, SchemeUnknown},
		{"19 digit boundary", "4000000000000000006", PANOptions{}, ReasonValid, SchemeUnknown},
		{"20 digit boundary", "40000000000000000006", PANOptions{}, ReasonInvalidLength, SchemeUnknown},
		{"separator disabled by default", "4111-1111 1111-1111", PANOptions{}, ReasonInvalidCharacter, SchemeUnknown},
		{"unicode digits", "４11111111111111", PANOptions{}, ReasonInvalidCharacter, SchemeUnknown},
		{"whitespace after configured normalization", "   ", PANOptions{StripSeparators: true}, ReasonEmpty, SchemeUnknown},
		{"empty input", "", PANOptions{}, ReasonEmpty, SchemeUnknown},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := ValidatePAN(tt.value, tt.options)
			if err != nil {
				t.Fatalf("ValidatePAN() error = %v", err)
			}
			if got.Reason != tt.want || got.Scheme != tt.scheme || got.Type != TypePAN || got.Valid != (tt.want == ReasonValid) {
				t.Fatalf("ValidatePAN() = %+v, want reason %q and scheme %q", got, tt.want, tt.scheme)
			}
		})
	}
}

func TestValidateCVV(t *testing.T) {
	tests := []struct {
		given          string
		value          string
		expectedLength int
		want           Reason
	}{
		{"three digits", "123", 0, ReasonValid},
		{"four digits", "9876", 4, ReasonValid},
		{"wrong expected length", "123", 4, ReasonInvalidLength},
		{"letters", "12a", 0, ReasonInvalidCharacter},
		{"empty", "", 0, ReasonEmpty},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := ValidateCVV(tt.value, tt.expectedLength)
			if err != nil || got.Reason != tt.want {
				t.Fatalf("ValidateCVV() = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
	if _, err := ValidateCVV("123", 5); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ValidateCVV() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestValidateExpiration(t *testing.T) {
	reference := time.Date(2026, time.November, 24, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		given string
		value string
		want  Reason
	}{
		{"two digit future year", "12/29", ReasonValid},
		{"four digit current month", "11/2026", ReasonValid},
		{"expired month", "10/2026", ReasonExpired},
		{"month zero", "00/29", ReasonInvalidMonth},
		{"month thirteen", "13/29", ReasonInvalidMonth},
		{"invalid separator", "12-29", ReasonInvalidCharacter},
		{"empty", "", ReasonEmpty},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := ValidateExpiration(tt.value, reference)
			if err != nil || got.Reason != tt.want {
				t.Fatalf("ValidateExpiration() = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
}

func TestValidateIBAN(t *testing.T) {
	tests := []struct {
		given   string
		value   string
		options IBANOptions
		want    Reason
	}{
		{"synthetic valid IBAN", "GB82WEST12345698765432", IBANOptions{}, ReasonValid},
		{"lowercase and spaces", "gb82 west 1234 5698 7654 32", IBANOptions{}, ReasonValid},
		{"lowercase country rule", "GB82WEST12345698765432", IBANOptions{CountryLengths: map[string]int{"gb": 22}}, ReasonValid},
		{"checksum failure", "GB82WEST12345698765433", IBANOptions{}, ReasonChecksumMismatch},
		{"country length mismatch", "GB82WEST12345698765432", IBANOptions{CountryLengths: map[string]int{"GB": 21}}, ReasonInvalidLength},
		{"unicode lookalike", "ＧＢ82WEST12345698765432", IBANOptions{}, ReasonInvalidCharacter},
		{"whitespace only", "   ", IBANOptions{}, ReasonEmpty},
		{"empty", "", IBANOptions{}, ReasonEmpty},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := ValidateIBAN(tt.value, tt.options)
			if err != nil || got.Reason != tt.want {
				t.Fatalf("ValidateIBAN() = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
	if _, err := ValidateIBAN("GB82WEST12345698765432", IBANOptions{CountryLengths: map[string]int{"GB": 14}}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ValidateIBAN() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestValidateABARoutingNumber(t *testing.T) {
	tests := []struct {
		given string
		value string
		want  Reason
	}{
		{"synthetic valid routing number", "021000021", ReasonValid},
		{"checksum failure", "021000022", ReasonChecksumMismatch},
		{"eight digits", "02100002", ReasonInvalidLength},
		{"non-digit", "02100002a", ReasonInvalidCharacter},
		{"empty", "", ReasonEmpty},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := ValidateABARoutingNumber(tt.value)
			if err != nil || got.Reason != tt.want {
				t.Fatalf("ValidateABARoutingNumber() = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
}

func TestValidateBankAccount(t *testing.T) {
	options := BankAccountOptions{
		MinLength: 6,
		MaxLength: 12,
		Pattern:   regexp.MustCompile(`^[A-Z0-9]+$`),
	}
	tests := []struct {
		given string
		value string
		opts  BankAccountOptions
		want  Reason
	}{
		{"synthetic account", "000123456789", options, ReasonValid},
		{"below minimum", "12345", options, ReasonInvalidLength},
		{"pattern mismatch", "00012-56789", options, ReasonInvalidCharacter},
		{"empty", "", options, ReasonEmpty},
		{"regex alternate full match", "AB123", BankAccountOptions{Pattern: regexp.MustCompile(`AB|AB123`)}, ReasonValid},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := ValidateBankAccount(tt.value, tt.opts)
			if err != nil || got.Reason != tt.want {
				t.Fatalf("ValidateBankAccount() = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
	if _, err := ValidateBankAccount("123", BankAccountOptions{MinLength: 5, MaxLength: 2}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ValidateBankAccount() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestValidatePaymentToken(t *testing.T) {
	rules := []TokenRule{{
		Prefix:       "tok_",
		MinLength:    8,
		MaxLength:    32,
		Pattern:      regexp.MustCompile(`^tok_[A-Za-z0-9_-]+$`),
		AllowedChars: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
	}}
	tests := []struct {
		given string
		value string
		rules []TokenRule
		want  Reason
	}{
		{"synthetic token", "tok_test_123", rules, ReasonValid},
		{"unknown prefix", "pm_test_123", rules, ReasonRuleMismatch},
		{"bad character", "tok_test.123", rules, ReasonInvalidCharacter},
		{"empty", "", rules, ReasonEmpty},
		{"no configured rules", "tok_test_123", nil, ReasonRuleMismatch},
		{"overlapping prefixes", "tok_test_123", []TokenRule{
			{Prefix: "tok_", MinLength: 8, MaxLength: 8},
			{Prefix: "tok_test_", MinLength: 12, MaxLength: 32},
		}, ReasonValid},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := ValidatePaymentToken(tt.value, tt.rules)
			if err != nil || got.Reason != tt.want {
				t.Fatalf("ValidatePaymentToken() = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
	if _, err := ValidatePaymentToken("tok_test_123", []TokenRule{{Prefix: "tok_", MinLength: 1, MaxLength: 20}}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ValidatePaymentToken() error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestValidationDoesNotEchoInput(t *testing.T) {
	value := "4111111111111112"
	got, err := ValidatePAN(value, PANOptions{})
	if err != nil {
		t.Fatalf("ValidatePAN() error = %v", err)
	}
	if strings.Contains(string(got.Reason), value) {
		t.Fatalf("reason %q contains submitted value", got.Reason)
	}
}

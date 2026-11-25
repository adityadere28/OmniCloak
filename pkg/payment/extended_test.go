package payment

import (
	"errors"
	"fmt"
	"regexp"
	"testing"
)

func TestValidateCardMetadata(t *testing.T) {
	tests := []struct {
		given string
		run   func() (Result, error)
		want  Reason
	}{
		{"configured BIN range", func() (Result, error) {
			return ValidateCardBIN("4111111111111111", []BINRule{{Start: "411111", End: "411111", MinPANLength: 16, MaxPANLength: 16, Scheme: SchemeVisa}})
		}, ReasonValid},
		{"BIN outside range", func() (Result, error) {
			return ValidateCardBIN("4111111111111111", []BINRule{{Start: "511111", End: "511111", MinPANLength: 16, MaxPANLength: 16}})
		}, ReasonRuleMismatch},
		{"three-digit service code", func() (Result, error) { return ValidateCardServiceCode("201") }, ReasonValid},
		{"track one", func() (Result, error) {
			return ValidateMagneticStripe("%B4111111111111111^DOE/JOHN^2912201?")
		}, ReasonValid},
		{"track two", func() (Result, error) {
			return ValidateMagneticStripe(";4111111111111111=2912201?")
		}, ReasonValid},
		{"invalid track checksum", func() (Result, error) {
			return ValidateMagneticStripe(";4111111111111112=2912201?")
		}, ReasonInvalidFormat},
		{"cardholder with normalized whitespace", func() (Result, error) {
			return ValidateCardholderName("  José   Doe ", CardholderNameOptions{NormalizeWhitespace: true})
		}, ReasonValid},
		{"invalid cardholder control", func() (Result, error) {
			return ValidateCardholderName("Jane\nDoe", CardholderNameOptions{})
		}, ReasonInvalidCharacter},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := tt.run()
			if err != nil || got.Reason != tt.want {
				t.Fatalf("validation = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
}

func TestValidateClearingAndRegionalRails(t *testing.T) {
	tests := []struct {
		given string
		run   func() (Result, error)
		want  Reason
	}{
		{"BIC 8 characters", func() (Result, error) { return ValidateBIC("DEUTDEFF") }, ReasonValid},
		{"BIC 11 characters", func() (Result, error) { return ValidateBIC("DEUTDEFFXXX") }, ReasonValid},
		{"UK sort code", func() (Result, error) { return ValidateUKSortCode("12-34-56") }, ReasonValid},
		{"IFSC", func() (Result, error) { return ValidateIFSC("hdfc0001234") }, ReasonValid},
		{"Canadian clearing", func() (Result, error) { return ValidateCanadianClearingCode("0001-23456") }, ReasonValid},
		{"Australian BSB", func() (Result, error) { return ValidateAustralianBSB("123-456") }, ReasonValid},
		{"NZ weighted checksum", func() (Result, error) {
			return ValidateNZBankAccount("12345672", NZBankAccountOptions{
				Weights: []int{1, 1, 1, 1, 1, 1, 1}, Modulus: 10, CheckDigitIndex: 7,
			})
		}, ReasonValid},
		{"NZ checksum mismatch", func() (Result, error) {
			return ValidateNZBankAccount("12345673", NZBankAccountOptions{
				Weights: []int{1, 1, 1, 1, 1, 1, 1}, Modulus: 10, CheckDigitIndex: 7,
			})
		}, ReasonChecksumMismatch},
		{"UPI VPA", func() (Result, error) { return ValidateUPIVPA("alex@ybl") }, ReasonValid},
		{"ACH SEC code", func() (Result, error) { return ValidateACHSECCode("PPD") }, ReasonValid},
		{"SEPA creditor identifier", func() (Result, error) {
			return ValidateSEPACreditorID(testSEPACreditorID("DE", "ZZZ123456789"))
		}, ReasonValid},
		{"mandate reference", func() (Result, error) { return ValidateMandateReference("INV/2026-001") }, ReasonValid},
		{"wallet tag", func() (Result, error) {
			return ValidateWalletTag("wallet_demo_1", []TokenRule{{Prefix: "wallet_", MinLength: 9, MaxLength: 32}})
		}, ReasonValid},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := tt.run()
			if err != nil || got.Reason != tt.want {
				t.Fatalf("validation = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
	if _, err := ValidateNZBankAccount("", NZBankAccountOptions{}); err != nil {
		t.Fatalf("empty NZ account should be a validation result, got %v", err)
	}
}

func TestValidateTransactionMetadata(t *testing.T) {
	tests := []struct {
		given string
		run   func() (Result, error)
		want  Reason
	}{
		{"merchant ID", func() (Result, error) {
			return ValidateMerchantID("MERCHANT-01", IdentifierOptions{MinLength: 4, MaxLength: 16, Allowed: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"})
		}, ReasonValid},
		{"terminal ID", func() (Result, error) {
			return ValidateTerminalID("TERM01", IdentifierOptions{Pattern: regexp.MustCompile(`^TERM[0-9]+$`)})
		}, ReasonValid},
		{"currency code", func() (Result, error) { return ValidateCurrencyCode("usd") }, ReasonValid},
		{"unknown currency", func() (Result, error) { return ValidateCurrencyCode("ZZZ") }, ReasonRuleMismatch},
		{"amount at USD precision", func() (Result, error) { return ValidateUSDAmount("12.34") }, ReasonValid},
		{"amount beyond precision", func() (Result, error) { return ValidateUSDAmount("12.345") }, ReasonInvalidLength},
		{"zero-decimal currency amount", func() (Result, error) { return ValidateAmount("123", 0) }, ReasonValid},
		{"STAN", func() (Result, error) { return ValidateSTAN("123456") }, ReasonValid},
		{"RRN", func() (Result, error) { return ValidateRRN("123456789012") }, ReasonValid},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := tt.run()
			if err != nil || got.Reason != tt.want {
				t.Fatalf("validation = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
	if units, ok := CurrencyMinorUnits("JPY"); !ok || units != 0 {
		t.Fatalf("CurrencyMinorUnits(JPY) = %d, %t; want 0, true", units, ok)
	}
	if units, ok := CurrencyMinorUnits("USD"); !ok || units != 2 {
		t.Fatalf("CurrencyMinorUnits(USD) = %d, %t; want 2, true", units, ok)
	}
}

func TestCrossFieldAndPolicyValidation(t *testing.T) {
	tests := []struct {
		given string
		run   func() (Result, error)
		want  Reason
	}{
		{"Visa CVV alignment", func() (Result, error) {
			return ValidateCardDetails("4111111111111111", SchemeVisa, "123")
		}, ReasonValid},
		{"scheme mismatch", func() (Result, error) {
			return ValidateCardDetails("4111111111111111", SchemeMastercard, "123")
		}, ReasonRuleMismatch},
		{"Amex CVV alignment", func() (Result, error) {
			return ValidateCardPayment("378282246310005", "9876")
		}, ReasonValid},
		{"Amex wrong CVV length", func() (Result, error) {
			return ValidateCardPayment("378282246310005", "123")
		}, ReasonInvalidLength},
		{"forbidden field", func() (Result, error) {
			return ValidateForbiddenPaymentFields(map[string]string{"card_cvv": "123"}, nil)
		}, ReasonForbiddenField},
		{"custom forbidden field", func() (Result, error) {
			return ValidateForbiddenPaymentFields(map[string]string{"raw_pan": "synthetic"}, []string{"raw_pan"})
		}, ReasonForbiddenField},
	}
	for _, tt := range tests {
		t.Run("Given_"+tt.given+"_When_validating_Then_"+string(tt.want), func(t *testing.T) {
			got, err := tt.run()
			if err != nil || got.Reason != tt.want {
				t.Fatalf("validation = %+v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
	if got := ClassifyPANExposure("4111111111111111"); got != PANExposureRaw {
		t.Fatalf("ClassifyPANExposure(raw) = %q", got)
	}
	if got := ClassifyPANExposure("4111********1111"); got != PANExposureMasked {
		t.Fatalf("ClassifyPANExposure(masked) = %q", got)
	}
	if got := ClassifyPANExposure("4111********1111-"); got != PANExposureUnknown {
		t.Fatalf("ClassifyPANExposure(trailing separator) = %q", got)
	}
	if _, err := NormalizePaymentText("  spaced\ttext  "); err != nil {
		t.Fatalf("NormalizePaymentText() error = %v", err)
	}
	if _, err := NormalizePaymentText("bad\x00text"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NormalizePaymentText() error = %v, want ErrInvalidInput", err)
	}
	for _, check := range []func() (Result, error){
		func() (Result, error) { return ValidateCVV("123", 0) },
		func() (Result, error) { return ValidatePAN("4111111111111111", PANOptions{}) },
		func() (Result, error) { return ValidateMagneticStripe("") },
	} {
		got, err := check()
		if err != nil {
			t.Fatalf("validation error = %v", err)
		}
		if !got.NonLoggable {
			t.Errorf("%s result should mark its input non-loggable", got.Type)
		}
	}
}

func TestFieldAwareValidation(t *testing.T) {
	validatePAN := func(value string) (Result, error) {
		return ValidatePAN(value, PANOptions{})
	}
	results, err := ValidateFieldMap(
		map[string]string{"pan": "4111111111111111"},
		map[string]FieldValidator{"pan": validatePAN},
	)
	if err != nil || !results["pan"].Valid {
		t.Fatalf("ValidateFieldMap() = %v, %v", results, err)
	}
	type payload struct {
		Card string `payment:"pan"`
	}
	results, err = ValidateStructFields(payload{Card: "4111111111111111"}, map[string]FieldValidator{"pan": validatePAN})
	if err != nil || !results["pan"].Valid {
		t.Fatalf("ValidateStructFields() = %v, %v", results, err)
	}
	if _, err := ValidateStructFields(nil, map[string]FieldValidator{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ValidateStructFields(nil) error = %v", err)
	}
	if _, err := ValidateFieldMap(nil, map[string]FieldValidator{"pan": nil}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("ValidateFieldMap(nil validator) error = %v", err)
	}
}

func testSEPACreditorID(country, body string) string {
	checkInput := body + country + "00"
	remainder := 0
	for i := 0; i < len(checkInput); i++ {
		c := checkInput[i]
		if c >= 'A' && c <= 'Z' {
			remainder = (remainder*100 + int(c-'A'+10)) % 97
		} else {
			remainder = (remainder*10 + int(c-'0')) % 97
		}
	}
	checkDigits := 98 - remainder
	return country + fmt.Sprintf("%02d", checkDigits) + body
}

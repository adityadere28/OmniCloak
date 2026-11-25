// Package payment validates payment-related identifiers without network calls
// or exposing submitted values in validation results. Invalid values appear in
// Result; errors are reserved for invalid validator configuration.
package payment

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ErrInvalidConfiguration indicates invalid validator options or rules.
var ErrInvalidConfiguration = errors.New("invalid validation configuration")

// ErrInvalidInput indicates malformed input to a transformation helper.
var ErrInvalidInput = errors.New("invalid input")

// Type identifies the payment value validated by a Result.
type Type string

const (
	// TypePAN identifies a card primary account number.
	TypePAN Type = "pan"
	// TypeCVV identifies a card security code.
	TypeCVV Type = "cvv"
	// TypeExpiration identifies a card expiration date.
	TypeExpiration Type = "card_expiration"
	// TypeIBAN identifies an international bank account number.
	TypeIBAN Type = "iban"
	// TypeABARouting identifies a US ABA routing number.
	TypeABARouting Type = "aba_routing_number"
	// TypeBankAccount identifies a generic bank account number.
	TypeBankAccount Type = "bank_account"
	// TypePaymentToken identifies a payment token or wallet reference.
	TypePaymentToken Type = "payment_token"
	// TypeCardBIN identifies card BIN/IIN metadata.
	TypeCardBIN Type = "card_bin"
	// TypeCardServiceCode identifies a magnetic-stripe service code.
	TypeCardServiceCode Type = "card_service_code"
	// TypeMagStripe identifies magnetic-stripe track data.
	TypeMagStripe Type = "magnetic_stripe"
	// TypeCardholderName identifies a cardholder name.
	TypeCardholderName Type = "cardholder_name"
	// TypeBIC identifies a BIC/SWIFT code.
	TypeBIC Type = "bic"
	// TypeUKSortCode identifies a UK sort code.
	TypeUKSortCode Type = "uk_sort_code"
	// TypeIFSC identifies an Indian IFSC.
	TypeIFSC Type = "ifsc"
	// TypeCanadianClearing identifies a Canadian institution/transit number.
	TypeCanadianClearing Type = "canadian_clearing_code"
	// TypeAustralianBSB identifies an Australian BSB.
	TypeAustralianBSB Type = "australian_bsb"
	// TypeNZBankAccount identifies a New Zealand bank account.
	TypeNZBankAccount Type = "nz_bank_account"
	// TypeUPIVPA identifies a UPI virtual payment address.
	TypeUPIVPA Type = "upi_vpa"
	// TypeACHSEC identifies an ACH Standard Entry Class code.
	TypeACHSEC Type = "ach_sec_code"
	// TypeSEPACreditorID identifies a SEPA Creditor Identifier.
	TypeSEPACreditorID Type = "sepa_creditor_identifier"
	// TypeMandateReference identifies a SEPA mandate reference.
	TypeMandateReference Type = "mandate_reference"
	// TypeWalletTag identifies a wallet tag.
	TypeWalletTag Type = "wallet_tag"
	// TypeMerchantID identifies a merchant identifier.
	TypeMerchantID Type = "merchant_id"
	// TypeTerminalID identifies a terminal identifier.
	TypeTerminalID Type = "terminal_id"
	// TypeCurrency identifies an ISO 4217 currency code.
	TypeCurrency Type = "currency"
	// TypeAmount identifies a monetary amount.
	TypeAmount Type = "amount"
	// TypeSTAN identifies a System Trace Audit Number.
	TypeSTAN Type = "stan"
	// TypeRRN identifies a Retrieval Reference Number.
	TypeRRN Type = "rrn"
	// TypePANExposure identifies masked or raw PAN exposure.
	TypePANExposure Type = "pan_exposure"
	// TypeCardDetails identifies cross-field card validation.
	TypeCardDetails Type = "card_details"
	// TypePaymentPolicy identifies a payment payload policy check.
	TypePaymentPolicy Type = "payment_policy"
	// TypeAVS identifies AVS billing address data.
	TypeAVS Type = "avs"
	// TypeMICR identifies US check MICR components.
	TypeMICR Type = "us_micr"
	// TypeRoutingRail identifies ABA routing rail eligibility.
	TypeRoutingRail Type = "aba_routing_rail"
	// TypeACHCompanyID identifies an ACH Company ID.
	TypeACHCompanyID Type = "ach_company_id"
	// TypeACHTrace identifies an ACH trace number.
	TypeACHTrace Type = "ach_trace_number"
	// TypeACHCode identifies a NACHA return or NOC code.
	TypeACHCode Type = "ach_code"
	// TypeEIN identifies a US Employer Identification Number.
	TypeEIN Type = "us_ein"
	// TypeITIN identifies a US Individual Taxpayer Identification Number.
	TypeITIN Type = "us_itin"
	// TypeSSN identifies a US Social Security Number.
	TypeSSN Type = "us_ssn"
	// TypeUSZIP identifies a US ZIP code.
	TypeUSZIP Type = "us_zip"
	// TypeAccountType identifies a consumer or commercial account type.
	TypeAccountType Type = "account_type"
)

// Sensitivity classifies the sensitivity of the validated value.
type Sensitivity string

const (
	// SensitivityHigh marks sensitive financial identifiers.
	SensitivityHigh Sensitivity = "high"
	// SensitivityCritical marks values requiring especially strict handling.
	SensitivityCritical Sensitivity = "critical"
	// SensitivityMedium marks payment metadata with moderate sensitivity.
	SensitivityMedium Sensitivity = "medium"
)

// Reason is a non-sensitive validation outcome code.
type Reason string

const (
	// ReasonValid indicates that validation succeeded.
	ReasonValid Reason = "valid"
	// ReasonEmpty indicates that the input was empty.
	ReasonEmpty Reason = "empty"
	// ReasonInvalidFormat indicates that the input format was invalid.
	ReasonInvalidFormat Reason = "invalid_format"
	// ReasonInvalidLength indicates that the input length was invalid.
	ReasonInvalidLength Reason = "invalid_length"
	// ReasonInvalidCharacter indicates that the input contained disallowed characters.
	ReasonInvalidCharacter Reason = "invalid_character"
	// ReasonChecksumMismatch indicates that a checksum did not match.
	ReasonChecksumMismatch Reason = "checksum_mismatch"
	// ReasonInvalidMonth indicates that an expiration month was outside 01..12.
	ReasonInvalidMonth Reason = "invalid_month"
	// ReasonExpired indicates that an expiration date precedes the reference month.
	ReasonExpired Reason = "expired"
	// ReasonRuleMismatch indicates that configured validation rules did not match.
	ReasonRuleMismatch Reason = "rule_mismatch"
	// ReasonForbiddenField indicates that a prohibited field was present.
	ReasonForbiddenField Reason = "forbidden_field"
	// ReasonRawData indicates that unmasked sensitive data was found.
	ReasonRawData Reason = "raw_sensitive_data"
)

// Scheme identifies a detected card network.
type Scheme string

const (
	// SchemeUnknown indicates that the network was not detected.
	SchemeUnknown Scheme = ""
	// SchemeVisa identifies Visa.
	SchemeVisa Scheme = "visa"
	// SchemeMastercard identifies Mastercard.
	SchemeMastercard Scheme = "mastercard"
	// SchemeAmericanExpress identifies American Express.
	SchemeAmericanExpress Scheme = "american_express"
	// SchemeDiscover identifies Discover.
	SchemeDiscover Scheme = "discover"
)

// Result contains a non-sensitive validation outcome. It never includes input.
type Result struct {
	Valid       bool
	Type        Type
	Sensitivity Sensitivity
	// NonLoggable marks the submitted field as unsuitable for persistence or logs.
	NonLoggable bool
	Reason      Reason
	Scheme      Scheme
}

func result(t Type, sensitivity Sensitivity, reason Reason) Result {
	return Result{
		Type:        t,
		Sensitivity: sensitivity,
		NonLoggable: t == TypePAN || t == TypeCVV || t == TypeCardBIN ||
			t == TypeMagStripe || t == TypeCardDetails,
		Reason: reason,
		Valid:  reason == ReasonValid,
	}
}

// PANOptions controls optional PAN normalization and scheme detection.
type PANOptions struct {
	StripSeparators bool
	DetectScheme    bool
}

// ValidatePAN checks ASCII digits, the standard PAN length range, and Luhn.
func ValidatePAN(value string, options PANOptions) (Result, error) {
	const maxInputLength = 64
	r := result(TypePAN, SensitivityCritical, ReasonInvalidFormat)
	if len(value) == 0 {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(value) > maxInputLength {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if options.StripSeparators {
		value = strings.NewReplacer(" ", "", "-", "").Replace(value)
	}
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
		return r, nil
	}
	if len(value) < 13 || len(value) > 19 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if !luhnValid(value) {
		r.Reason = ReasonChecksumMismatch
		return r, nil
	}
	r = result(TypePAN, SensitivityCritical, ReasonValid)
	if options.DetectScheme {
		r.Scheme = detectScheme(value)
	}
	return r, nil
}

// ValidateCVV accepts three or four digits, or enforces expectedLength when set.
func ValidateCVV(value string, expectedLength int) (Result, error) {
	r := result(TypeCVV, SensitivityCritical, ReasonInvalidFormat)
	if expectedLength != 0 && expectedLength != 3 && expectedLength != 4 {
		return Result{}, fmt.Errorf("%w: CVV length must be 0, 3, or 4", ErrInvalidConfiguration)
	}
	if value == "" {
		r.Reason = ReasonEmpty
	} else if (expectedLength != 0 && len(value) != expectedLength) ||
		(expectedLength == 0 && len(value) != 3 && len(value) != 4) {
		r.Reason = ReasonInvalidLength
	} else if !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeCVV, SensitivityCritical, ReasonValid)
	}
	return r, nil
}

// ValidateExpiration accepts MM/YY or MM/YYYY. A zero reference time skips expiry checking.
func ValidateExpiration(value string, referenceTime time.Time) (Result, error) {
	r := result(TypeExpiration, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(value) != 5 && len(value) != 7 {
		r.Reason = ReasonInvalidFormat
		return r, nil
	}
	if value[2] != '/' || !asciiDigits(value[:2]) || !asciiDigits(value[3:]) {
		r.Reason = ReasonInvalidCharacter
		return r, nil
	}
	month := int(value[0]-'0')*10 + int(value[1]-'0')
	if month < 1 || month > 12 {
		r.Reason = ReasonInvalidMonth
		return r, nil
	}
	year := 0
	for i := 3; i < len(value); i++ {
		year = year*10 + int(value[i]-'0')
	}
	if len(value) == 5 {
		year += 2000
	}
	if !referenceTime.IsZero() && (year < referenceTime.Year() ||
		(year == referenceTime.Year() && time.Month(month) < referenceTime.Month())) {
		r.Reason = ReasonExpired
		return r, nil
	}
	return result(TypeExpiration, SensitivityHigh, ReasonValid), nil
}

// IBANOptions enables optional country-specific IBAN lengths.
type IBANOptions struct {
	// CountryLengths enables country-specific length checks when non-empty.
	CountryLengths map[string]int
}

// ValidateIBAN accepts ASCII IBANs with optional ASCII spaces and checks mod-97.
func ValidateIBAN(value string, options IBANOptions) (Result, error) {
	r := result(TypeIBAN, SensitivityHigh, ReasonInvalidFormat)
	for country, length := range options.CountryLengths {
		if len(country) != 2 || !asciiLetters(country) || length < 15 || length > 34 {
			return Result{}, fmt.Errorf("%w: invalid IBAN country length rule", ErrInvalidConfiguration)
		}
	}
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(value) > 128 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	var normalized strings.Builder
	normalized.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == ' ' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if !isASCIILetter(c) && (c < '0' || c > '9') {
			r.Reason = ReasonInvalidCharacter
			return r, nil
		}
		normalized.WriteByte(c)
	}
	iban := normalized.String()
	if iban == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(iban) < 15 || len(iban) > 34 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if !asciiLetters(iban[:2]) || !asciiDigits(iban[2:4]) {
		r.Reason = ReasonInvalidFormat
		return r, nil
	}
	if len(options.CountryLengths) != 0 {
		expected, ok := countryLength(options.CountryLengths, iban[:2])
		if !ok || len(iban) != expected {
			r.Reason = ReasonInvalidLength
			return r, nil
		}
	}
	if !ibanMod97Valid(iban) {
		r.Reason = ReasonChecksumMismatch
		return r, nil
	}
	return result(TypeIBAN, SensitivityHigh, ReasonValid), nil
}

// ValidateABARoutingNumber checks the nine-digit ABA checksum.
func ValidateABARoutingNumber(value string) (Result, error) {
	r := result(TypeABARouting, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 9 {
		r.Reason = ReasonInvalidLength
	} else if !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
	} else if !abaChecksumValid(value) {
		r.Reason = ReasonChecksumMismatch
	} else {
		r = result(TypeABARouting, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// BankAccountOptions configures generic bank account validation.
type BankAccountOptions struct {
	MinLength int
	MaxLength int
	Pattern   *regexp.Regexp
}

// ValidateBankAccount applies configurable structural bounds and an optional regex.
func ValidateBankAccount(value string, options BankAccountOptions) (Result, error) {
	min, max := options.MinLength, options.MaxLength
	if min == 0 {
		min = 1
	}
	if max == 0 {
		max = 34
	}
	if min < 1 || max < min {
		return Result{}, fmt.Errorf("%w: bank account length bounds must be positive and ordered", ErrInvalidConfiguration)
	}
	r := result(TypeBankAccount, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) < min || len(value) > max {
		r.Reason = ReasonInvalidLength
	} else if !asciiAlphaNumeric(value) {
		r.Reason = ReasonInvalidCharacter
	} else if options.Pattern != nil && !matchesWhole(options.Pattern, value) {
		r.Reason = ReasonRuleMismatch
	} else {
		r = result(TypeBankAccount, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// TokenRule describes an accepted payment token format.
type TokenRule struct {
	Prefix       string
	MinLength    int
	MaxLength    int
	Pattern      *regexp.Regexp
	AllowedChars string
}

// ValidatePaymentToken matches a configured token prefix, length, charset, and pattern.
func ValidatePaymentToken(value string, rules []TokenRule) (Result, error) {
	for _, rule := range rules {
		if rule.Prefix == "" || rule.MinLength < len(rule.Prefix) || rule.MaxLength < rule.MinLength ||
			!asciiTokenChars(rule.Prefix) || !asciiTokenChars(rule.AllowedChars) {
			return Result{}, fmt.Errorf("%w: invalid payment token rule", ErrInvalidConfiguration)
		}
	}
	r := result(TypePaymentToken, SensitivityHigh, ReasonRuleMismatch)
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	matchedPrefix := false
	for _, rule := range rules {
		if !strings.HasPrefix(value, rule.Prefix) {
			continue
		}
		matchedPrefix = true
		if len(value) < rule.MinLength || len(value) > rule.MaxLength {
			r.Reason = ReasonInvalidLength
			continue
		}
		if !asciiTokenChars(value) {
			r.Reason = ReasonInvalidCharacter
			continue
		}
		if rule.AllowedChars != "" && !containsOnly(value, rule.AllowedChars) {
			r.Reason = ReasonInvalidCharacter
			continue
		}
		if rule.Pattern != nil && !matchesWhole(rule.Pattern, value) {
			r.Reason = ReasonRuleMismatch
			continue
		}
		return result(TypePaymentToken, SensitivityHigh, ReasonValid), nil
	}
	if !matchedPrefix {
		r.Reason = ReasonRuleMismatch
	}
	return r, nil
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func asciiLetters(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !isASCIILetter(value[i]) {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func asciiAlphaNumeric(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

func asciiTokenChars(value string) bool {
	if value == "" {
		return true
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func containsOnly(value, allowed string) bool {
	for i := 0; i < len(value); i++ {
		if !strings.ContainsRune(allowed, rune(value[i])) {
			return false
		}
	}
	return true
}

func matchesWhole(pattern *regexp.Regexp, value string) bool {
	match := pattern.FindStringIndex(value)
	if match != nil && match[0] == 0 && match[1] == len(value) {
		return true
	}
	anchored, err := regexp.Compile(`\A(?:` + pattern.String() + `)\z`)
	return err == nil && anchored.MatchString(value)
}

func countryLength(lengths map[string]int, country string) (int, bool) {
	for code, length := range lengths {
		if strings.EqualFold(code, country) {
			return length, true
		}
	}
	return 0, false
}

func luhnValid(value string) bool {
	sum, double := 0, false
	for i := len(value) - 1; i >= 0; i-- {
		digit := int(value[i] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

func detectScheme(value string) Scheme {
	switch {
	case value[0] == '4':
		return SchemeVisa
	case strings.HasPrefix(value, "34") || strings.HasPrefix(value, "37"):
		return SchemeAmericanExpress
	case len(value) >= 2 && value[0] == '5' && value[1] >= '1' && value[1] <= '5':
		return SchemeMastercard
	case len(value) >= 4 && value[:4] >= "2221" && value[:4] <= "2720":
		return SchemeMastercard
	case strings.HasPrefix(value, "6011") || strings.HasPrefix(value, "65") ||
		(strings.HasPrefix(value, "64") && len(value) >= 3 && value[2] >= '4' && value[2] <= '9') ||
		(len(value) >= 6 && value[:6] >= "622126" && value[:6] <= "622925"):
		return SchemeDiscover
	default:
		return SchemeUnknown
	}
}

func ibanMod97Valid(value string) bool {
	remainder := 0
	for i := 4; i < len(value); i++ {
		remainder = ibanMod97Step(remainder, value[i])
	}
	for i := 0; i < 4; i++ {
		remainder = ibanMod97Step(remainder, value[i])
	}
	return remainder == 1
}

func ibanMod97Step(remainder int, c byte) int {
	if c >= '0' && c <= '9' {
		return (remainder*10 + int(c-'0')) % 97
	}
	return (remainder*100 + int(c-'A'+10)) % 97
}

func abaChecksumValid(value string) bool {
	d := make([]int, 9)
	for i := range value {
		d[i] = int(value[i] - '0')
	}
	return (3*(d[0]+d[3]+d[6])+7*(d[1]+d[4]+d[7])+d[2]+d[5]+d[8])%10 == 0
}

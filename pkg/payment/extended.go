package payment

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// BINRule describes an inclusive numeric IIN range and its accepted PAN lengths.
type BINRule struct {
	Start        string
	End          string
	MinPANLength int
	MaxPANLength int
	Scheme       Scheme
}

func uppercaseASCII(value string) (string, bool) {
	bytes := []byte(value)
	for i, c := range bytes {
		if c > 0x7f {
			return "", false
		}
		if c >= 'a' && c <= 'z' {
			bytes[i] = c - ('a' - 'A')
		}
	}
	return string(bytes), true
}

// ValidateCardBIN checks a PAN against configured IIN ranges and PAN lengths.
func ValidateCardBIN(pan string, rules []BINRule) (Result, error) {
	if len(rules) == 0 {
		return Result{}, fmt.Errorf("%w: at least one BIN rule is required", ErrInvalidConfiguration)
	}
	for _, rule := range rules {
		if !asciiDigits(rule.Start) || !asciiDigits(rule.End) || len(rule.Start) != len(rule.End) ||
			len(rule.Start) < 6 || len(rule.Start) > 8 || rule.Start > rule.End ||
			rule.MinPANLength < 13 || rule.MaxPANLength > 19 || rule.MaxPANLength < rule.MinPANLength {
			return Result{}, fmt.Errorf("%w: invalid BIN range", ErrInvalidConfiguration)
		}
	}
	r := result(TypeCardBIN, SensitivityHigh, ReasonRuleMismatch)
	if pan == "" {
		r.Reason = ReasonEmpty
	} else if !asciiDigits(pan) {
		r.Reason = ReasonInvalidCharacter
	} else if len(pan) < 13 || len(pan) > 19 {
		r.Reason = ReasonInvalidLength
	} else {
		for _, rule := range rules {
			prefix := pan[:len(rule.Start)]
			if len(pan) >= rule.MinPANLength && len(pan) <= rule.MaxPANLength &&
				prefix >= rule.Start && prefix <= rule.End {
				r = result(TypeCardBIN, SensitivityHigh, ReasonValid)
				r.Scheme = rule.Scheme
				return r, nil
			}
		}
	}
	return r, nil
}

// ValidateCardServiceCode requires the three numeric digits used on magnetic stripes.
func ValidateCardServiceCode(value string) (Result, error) {
	return validateExactDigits(value, TypeCardServiceCode, SensitivityCritical, 3)
}

// ValidateMagneticStripe validates Track 1 or Track 2 structure without returning track data.
func ValidateMagneticStripe(track string) (Result, error) {
	r := result(TypeMagStripe, SensitivityCritical, ReasonInvalidFormat)
	if track == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(track) > 79 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if !utf8.ValidString(track) {
		r.Reason = ReasonInvalidCharacter
		return r, nil
	}
	if strings.HasPrefix(track, "%B") {
		if len(track) > 79 || !strings.HasSuffix(track, "?") {
			r.Reason = ReasonInvalidLength
			return r, nil
		}
		parts := strings.Split(track[2:len(track)-1], "^")
		if len(parts) != 3 || !validTrackExpiryService(parts[2]) {
			return r, nil
		}
		if !asciiAlphaNumeric(parts[0]) || !validPANForTrack(parts[0]) {
			r.Reason = ReasonInvalidFormat
			return r, nil
		}
		nameResult, _ := ValidateCardholderName(parts[1], CardholderNameOptions{})
		if !nameResult.Valid {
			r.Reason = ReasonInvalidFormat
			return r, nil
		}
		return result(TypeMagStripe, SensitivityCritical, ReasonValid), nil
	}
	if strings.HasPrefix(track, ";") {
		if len(track) > 40 || !strings.HasSuffix(track, "?") {
			r.Reason = ReasonInvalidLength
			return r, nil
		}
		parts := strings.Split(track[1:len(track)-1], "=")
		if len(parts) != 2 || !validTrackExpiryService(parts[1]) {
			return r, nil
		}
		if !asciiDigits(parts[0]) || !validPANForTrack(parts[0]) {
			r.Reason = ReasonInvalidFormat
			return r, nil
		}
		return result(TypeMagStripe, SensitivityCritical, ReasonValid), nil
	}
	r.Reason = ReasonInvalidFormat
	return r, nil
}

func validPANForTrack(value string) bool {
	r, _ := ValidatePAN(value, PANOptions{})
	return r.Valid
}

func validTrackExpiryService(value string) bool {
	if len(value) < 7 || !asciiDigits(value[:7]) {
		return false
	}
	month, _ := strconv.Atoi(value[2:4])
	return month >= 1 && month <= 12 && (len(value) == 7 || asciiDigits(value[7:]))
}

// CardholderNameOptions controls whitespace handling for embossed names.
type CardholderNameOptions struct {
	NormalizeWhitespace bool
}

// ValidateCardholderName accepts letters, marks, spaces, apostrophes, hyphens, and periods.
func ValidateCardholderName(value string, options CardholderNameOptions) (Result, error) {
	r := result(TypeCardholderName, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(value) > 256 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if strings.TrimSpace(value) == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if !utf8.ValidString(value) {
		r.Reason = result(TypeCardholderName, SensitivityHigh, ReasonInvalidCharacter).Reason
		return r, nil
	}
	if options.NormalizeWhitespace {
		value = strings.Join(strings.Fields(value), " ")
	}
	count := utf8.RuneCountInString(value)
	if count < 1 || count > 26 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	previousSpace := false
	for _, char := range value {
		switch {
		case unicode.IsLetter(char) || unicode.IsMark(char):
			previousSpace = false
		case char == ' ' && !previousSpace:
			previousSpace = true
		case strings.ContainsRune("'-./", char):
			previousSpace = false
		default:
			r.Reason = ReasonInvalidCharacter
			return r, nil
		}
	}
	if previousSpace || strings.Contains(value, "  ") {
		r.Reason = ReasonInvalidFormat
		return r, nil
	}
	return result(TypeCardholderName, SensitivityHigh, ReasonValid), nil
}

// ValidateBIC checks the 8- or 11-character ISO 9362 structure.
func ValidateBIC(value string) (Result, error) {
	r := result(TypeBIC, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 8 && len(value) != 11 {
		r.Reason = ReasonInvalidLength
	} else if !asciiLetters(value[:4]) || !asciiLetters(value[4:6]) ||
		!asciiAlphaNumeric(value[6:]) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeBIC, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// ValidateUKSortCode accepts six digits with optional 2-2-2 hyphen grouping.
func ValidateUKSortCode(value string) (Result, error) {
	value, ok := normalizeDigitGroups(value, 2, 2, 2)
	if !ok {
		return result(TypeUKSortCode, SensitivityHigh, ReasonInvalidFormat), nil
	}
	r := result(TypeUKSortCode, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 6 {
		r.Reason = ReasonInvalidLength
	} else if !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeUKSortCode, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// ValidateIFSC checks the 11-character Indian IFSC structure.
func ValidateIFSC(value string) (Result, error) {
	if value == "" {
		return result(TypeIFSC, SensitivityHigh, ReasonEmpty), nil
	}
	if len(value) != 11 {
		return result(TypeIFSC, SensitivityHigh, ReasonInvalidLength), nil
	}
	var ok bool
	value, ok = uppercaseASCII(value)
	r := result(TypeIFSC, SensitivityHigh, ReasonInvalidFormat)
	if !ok {
		r.Reason = ReasonInvalidCharacter
	} else if !asciiLetters(value[:4]) || value[4] != '0' || !asciiAlphaNumeric(value[5:]) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeIFSC, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// ValidateCanadianClearingCode checks a nine-digit Canadian routing number (0 + institution + transit).
func ValidateCanadianClearingCode(value string) (Result, error) {
	value, ok := normalizeDigitGroups(value, 4, 5)
	if !ok {
		return result(TypeCanadianClearing, SensitivityHigh, ReasonInvalidFormat), nil
	}
	r := result(TypeCanadianClearing, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 9 {
		r.Reason = ReasonInvalidLength
	} else if value[0] != '0' || !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeCanadianClearing, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// ValidateAustralianBSB accepts six digits with optional 3-3 hyphen grouping.
func ValidateAustralianBSB(value string) (Result, error) {
	value, ok := normalizeDigitGroups(value, 3, 3)
	if !ok {
		return result(TypeAustralianBSB, SensitivityHigh, ReasonInvalidFormat), nil
	}
	r := result(TypeAustralianBSB, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 6 {
		r.Reason = ReasonInvalidLength
	} else if !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeAustralianBSB, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// NZBankAccountOptions specifies the institution-specific weighted checksum.
type NZBankAccountOptions struct {
	Weights         []int
	Modulus         int
	CheckDigitIndex int
}

// ValidateNZBankAccount checks digits and a configured weighted check digit.
func ValidateNZBankAccount(value string, options NZBankAccountOptions) (Result, error) {
	if value == "" {
		return result(TypeNZBankAccount, SensitivityHigh, ReasonEmpty), nil
	}
	if len(value) < 8 || len(value) > 16 {
		return result(TypeNZBankAccount, SensitivityHigh, ReasonInvalidLength), nil
	}
	if options.Modulus < 2 || options.Modulus > 1_000_000_000 || len(options.Weights) != len(value)-1 ||
		options.CheckDigitIndex < 0 || options.CheckDigitIndex >= len(value) {
		return Result{}, fmt.Errorf("%w: NZ account checksum rule must match account length", ErrInvalidConfiguration)
	}
	for _, weight := range options.Weights {
		if weight < 1 || weight > 1_000_000_000 {
			return Result{}, fmt.Errorf("%w: NZ account weights must be positive and bounded", ErrInvalidConfiguration)
		}
	}
	r := result(TypeNZBankAccount, SensitivityHigh, ReasonInvalidFormat)
	if !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		sum, weightIndex := int64(0), 0
		for i := 0; i < len(value); i++ {
			if i == options.CheckDigitIndex {
				continue
			}
			sum += int64(value[i]-'0') * int64(options.Weights[weightIndex])
			weightIndex++
		}
		expected := (int64(options.Modulus) - sum%int64(options.Modulus)) % int64(options.Modulus)
		if expected != int64(value[options.CheckDigitIndex]-'0') {
			r.Reason = ReasonChecksumMismatch
		} else {
			r = result(TypeNZBankAccount, SensitivityHigh, ReasonValid)
		}
	}
	return r, nil
}

// ValidateUPIVPA checks the local-part@handle structure of a UPI address.
func ValidateUPIVPA(value string) (Result, error) {
	r := result(TypeUPIVPA, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(value) > 128 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	parts := strings.Split(value, "@")
	if len(parts) != 2 || len(parts[0]) < 2 || len(parts[0]) > 64 ||
		len(parts[1]) < 2 || len(parts[1]) > 64 {
		r.Reason = ReasonInvalidFormat
		return r, nil
	}
	if !asciiUPIPart(parts[0], true) || !asciiUPIPart(parts[1], false) {
		r.Reason = ReasonInvalidCharacter
		return r, nil
	}
	return result(TypeUPIVPA, SensitivityHigh, ReasonValid), nil
}

func asciiUPIPart(value string, local bool) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if local && strings.ContainsRune("._-", rune(c)) || !local && strings.ContainsRune(".-", rune(c)) {
			continue
		}
		return false
	}
	return len(value) > 0 && isASCIILetterOrDigit(value[0]) && isASCIILetterOrDigit(value[len(value)-1])
}

func isASCIILetterOrDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// ValidateACHSECCode checks a NACHA Standard Entry Class code.
func ValidateACHSECCode(value string) (Result, error) {
	const codes = "ACK ADV ARC ATX BOC CAT CCD CIE COR CTX ENR ENT IAT MTE POP POS PPD RCK SHR TEL TRC TRX WEB XCK"
	r := result(TypeACHSEC, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	for _, code := range strings.Fields(codes) {
		if value == code {
			return result(TypeACHSEC, SensitivityHigh, ReasonValid), nil
		}
	}
	return r, nil
}

// ValidateSEPACreditorID checks structure and the ISO 7064 mod-97-10 checksum.
func ValidateSEPACreditorID(value string) (Result, error) {
	if value == "" {
		return result(TypeSEPACreditorID, SensitivityHigh, ReasonEmpty), nil
	}
	if len(value) > 128 {
		return result(TypeSEPACreditorID, SensitivityHigh, ReasonInvalidLength), nil
	}
	var ascii bool
	value, ascii = uppercaseASCII(strings.ReplaceAll(value, " ", ""))
	r := result(TypeSEPACreditorID, SensitivityHigh, ReasonInvalidFormat)
	if !ascii {
		r.Reason = ReasonInvalidCharacter
		return r, nil
	}
	if len(value) < 8 || len(value) > 35 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if !asciiLetters(value[:2]) || !asciiDigits(value[2:4]) || !asciiAlphaNumeric(value[4:]) {
		r.Reason = ReasonInvalidCharacter
		return r, nil
	}
	if !ibanMod97Valid(value) {
		r.Reason = ReasonChecksumMismatch
		return r, nil
	}
	return result(TypeSEPACreditorID, SensitivityHigh, ReasonValid), nil
}

// ValidateMandateReference checks the SEPA mandate-reference character set and length.
func ValidateMandateReference(value string) (Result, error) {
	r := result(TypeMandateReference, SensitivityMedium, ReasonInvalidFormat)
	if len(value) > 35 {
		r.Reason = ReasonInvalidLength
	} else if strings.TrimSpace(value) == "" {
		r.Reason = ReasonEmpty
	} else if !asciiMandateChars(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeMandateReference, SensitivityMedium, ReasonValid)
	}
	return r, nil
}

func asciiMandateChars(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isASCIILetterOrDigit(c) || strings.ContainsRune(" /?:().,'+-", rune(c)) {
			continue
		}
		return false
	}
	return true
}

// ValidateWalletTag validates a wallet tag with caller-provided token rules.
func ValidateWalletTag(value string, rules []TokenRule) (Result, error) {
	got, err := ValidatePaymentToken(value, rules)
	got.Type = TypeWalletTag
	return got, err
}

// IdentifierOptions configures merchant and terminal identifiers.
type IdentifierOptions struct {
	MinLength int
	MaxLength int
	Allowed   string
	Pattern   *regexp.Regexp
}

// ValidateMerchantID checks a merchant ID against its configured format.
func ValidateMerchantID(value string, options IdentifierOptions) (Result, error) {
	return validateBusinessID(value, options, TypeMerchantID)
}

// ValidateTerminalID checks a terminal ID against its configured format.
func ValidateTerminalID(value string, options IdentifierOptions) (Result, error) {
	return validateBusinessID(value, options, TypeTerminalID)
}

func validateBusinessID(value string, options IdentifierOptions, t Type) (Result, error) {
	min, max := options.MinLength, options.MaxLength
	if min == 0 {
		min = 1
	}
	if max == 0 {
		max = 64
	}
	if min < 1 || max < min || !asciiTokenChars(options.Allowed) {
		return Result{}, fmt.Errorf("%w: invalid identifier rules", ErrInvalidConfiguration)
	}
	r := result(t, SensitivityMedium, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) < min || len(value) > max {
		r.Reason = ReasonInvalidLength
	} else if !asciiTokenChars(value) || options.Allowed != "" && !containsOnly(value, options.Allowed) {
		r.Reason = ReasonInvalidCharacter
	} else if options.Pattern != nil && !matchesWhole(options.Pattern, value) {
		r.Reason = ReasonRuleMismatch
	} else {
		r = result(t, SensitivityMedium, ReasonValid)
	}
	return r, nil
}

// ValidateSTAN requires the six-digit ISO 8583 System Trace Audit Number format.
func ValidateSTAN(value string) (Result, error) {
	return validateExactDigits(value, TypeSTAN, SensitivityMedium, 6)
}

// ValidateRRN requires the 12-digit ISO 8583 Retrieval Reference Number format.
func ValidateRRN(value string) (Result, error) {
	return validateExactDigits(value, TypeRRN, SensitivityMedium, 12)
}

var currencyMinorUnits = buildCurrencyMinorUnits()

// ValidateCurrencyCode checks a supported ISO 4217 alphabetic currency code.
func ValidateCurrencyCode(value string) (Result, error) {
	if value == "" {
		return result(TypeCurrency, SensitivityMedium, ReasonEmpty), nil
	}
	if len(value) != 3 {
		return result(TypeCurrency, SensitivityMedium, ReasonInvalidLength), nil
	}
	var ascii bool
	value, ascii = uppercaseASCII(value)
	r := result(TypeCurrency, SensitivityMedium, ReasonInvalidFormat)
	if !ascii {
		r.Reason = ReasonInvalidCharacter
	} else if !asciiLetters(value) {
		r.Reason = ReasonInvalidCharacter
	} else if _, ok := currencyMinorUnits[value]; !ok {
		r.Reason = ReasonRuleMismatch
	} else {
		r = result(TypeCurrency, SensitivityMedium, ReasonValid)
	}
	return r, nil
}

// CurrencyMinorUnits returns the ISO 4217 decimal precision for a supported code.
func CurrencyMinorUnits(code string) (int, bool) {
	units, ok := currencyMinorUnits[strings.ToUpper(code)]
	return units, ok
}

// ValidateAmount validates a decimal amount without floating-point conversion.
func ValidateAmount(value string, minorUnits int) (Result, error) {
	if minorUnits < 0 || minorUnits > 9 {
		return Result{}, fmt.Errorf("%w: minor units must be between 0 and 9", ErrInvalidConfiguration)
	}
	r := result(TypeAmount, SensitivityMedium, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(value) > 128 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if value[0] == '-' || value[0] == '+' {
		value = value[1:]
		if value == "" {
			r.Reason = ReasonInvalidFormat
			return r, nil
		}
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || parts[0] == "" || !asciiDigits(parts[0]) ||
		(len(parts[0]) > 1 && parts[0][0] == '0') {
		r.Reason = ReasonInvalidFormat
		return r, nil
	}
	if len(parts) == 2 {
		if !asciiDigits(parts[1]) {
			r.Reason = ReasonInvalidCharacter
			return r, nil
		}
		if minorUnits == 0 || len(parts[1]) > minorUnits {
			r.Reason = ReasonInvalidLength
			return r, nil
		}
	}
	return result(TypeAmount, SensitivityMedium, ReasonValid), nil
}

// ValidateUSDAmount validates a USD amount with two fractional digits maximum.
func ValidateUSDAmount(value string) (Result, error) {
	return ValidateAmount(value, 2)
}

// PANExposure classifies a PAN field without returning its contents.
type PANExposure string

const (
	// PANExposureUnknown indicates that the value is neither a recognized masked nor raw PAN.
	PANExposureUnknown PANExposure = "unknown"
	// PANExposureMasked indicates that the value contains a masked PAN shape.
	PANExposureMasked PANExposure = "masked"
	// PANExposureRaw indicates that the value appears to contain an unmasked PAN.
	PANExposureRaw PANExposure = "raw"
)

// ClassifyPANExposure detects raw or masked PAN-like strings.
func ClassifyPANExposure(value string) PANExposure {
	if len(value) > 64 {
		return PANExposureUnknown
	}
	digits, masks := 0, 0
	lastDigit := false
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= '0' && c <= '9':
			digits++
			lastDigit = true
		case c == '*' || c == 'X' || c == 'x' || c == '#':
			masks++
			lastDigit = false
		case c == ' ' || c == '-':
		default:
			return PANExposureUnknown
		}
	}
	if digits >= 13 && digits <= 19 && masks == 0 {
		return PANExposureRaw
	}
	if digits >= 4 && masks >= 8 && digits+masks >= 13 && digits+masks <= 19 &&
		lastDigit && len(value) > 0 && value[len(value)-1] >= '0' && value[len(value)-1] <= '9' {
		return PANExposureMasked
	}
	return PANExposureUnknown
}

// ValidateCardPayment checks PAN validity and the scheme-specific CVV length.
func ValidateCardPayment(pan, cvv string) (Result, error) {
	return ValidateCardDetails(pan, SchemeUnknown, cvv)
}

// ValidateCardDetails checks PAN validity, declared scheme, and scheme-specific CVV length.
func ValidateCardDetails(pan string, declaredScheme Scheme, cvv string) (Result, error) {
	panResult, _ := ValidatePAN(pan, PANOptions{DetectScheme: true})
	r := result(TypeCardDetails, SensitivityCritical, ReasonValid)
	if !panResult.Valid {
		r.Reason = panResult.Reason
		return r, nil
	}
	if declaredScheme != SchemeUnknown && declaredScheme != panResult.Scheme {
		r.Reason = ReasonRuleMismatch
		return r, nil
	}
	expected := 0
	scheme := panResult.Scheme
	if declaredScheme != SchemeUnknown {
		scheme = declaredScheme
	}
	switch scheme {
	case SchemeAmericanExpress:
		expected = 4
	case SchemeVisa, SchemeMastercard, SchemeDiscover:
		expected = 3
	}
	cvvResult, err := ValidateCVV(cvv, expected)
	if err != nil {
		return Result{}, err
	}
	if !cvvResult.Valid {
		r.Reason = cvvResult.Reason
	}
	return r, nil
}

// ValidateForbiddenPaymentFields rejects names that must not be persisted.
func ValidateForbiddenPaymentFields(fields map[string]string, extraForbidden []string) (Result, error) {
	forbidden := make(map[string]struct{}, len(extraForbidden))
	for _, field := range extraForbidden {
		if field == "" {
			return Result{}, fmt.Errorf("%w: forbidden field names must not be empty", ErrInvalidConfiguration)
		}
		forbidden[normalizeFieldName(field)] = struct{}{}
	}
	r := result(TypePaymentPolicy, SensitivityHigh, ReasonValid)
	for field := range fields {
		name := normalizeFieldName(field)
		_, explicitlyForbidden := forbidden[name]
		if explicitlyForbidden || hasSensitiveFieldSuffix(name) {
			r.Reason = ReasonForbiddenField
			return r, nil
		}
	}
	return r, nil
}

func hasSensitiveFieldSuffix(name string) bool {
	if strings.Contains(name, "magneticstripe") {
		return true
	}
	for _, suffix := range []string{
		"cvv", "cvc", "cid", "securitycode", "track1", "track2", "trackdata", "magneticstripe",
	} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func normalizeFieldName(value string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(value) {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// NormalizePaymentText trims and collapses Unicode whitespace, rejecting invalid UTF-8 and controls.
func NormalizePaymentText(value string) (string, error) {
	if len(value) > 4096 {
		return "", fmt.Errorf("%w: text exceeds normalization limit", ErrInvalidInput)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%w: invalid text encoding", ErrInvalidInput)
	}
	for _, c := range value {
		if (unicode.IsControl(c) || unicode.Is(unicode.Cf, c)) && !unicode.IsSpace(c) {
			return "", fmt.Errorf("%w: control character in text", ErrInvalidInput)
		}
	}
	return strings.Join(strings.Fields(value), " "), nil
}

// FieldValidator validates one field value and returns a value-free result.
type FieldValidator func(string) (Result, error)

// ValidateFieldMap validates configured map fields in sorted key order.
func ValidateFieldMap(fields map[string]string, rules map[string]FieldValidator) (map[string]Result, error) {
	keys := make([]string, 0, len(rules))
	for key, validator := range rules {
		if key == "" || validator == nil {
			return nil, fmt.Errorf("%w: field rules require names and validators", ErrInvalidConfiguration)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	results := make(map[string]Result, len(keys))
	for _, key := range keys {
		got, err := rules[key](fields[key])
		if err != nil {
			return nil, fmt.Errorf("%w: field validator failed", ErrInvalidConfiguration)
		}
		results[key] = got
	}
	return results, nil
}

// ValidateStructFields validates string fields using Go field names or `payment` tags.
func ValidateStructFields(value any, rules map[string]FieldValidator) (map[string]Result, error) {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return nil, fmt.Errorf("%w: expected a struct or pointer to struct", ErrInvalidConfiguration)
	}
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, fmt.Errorf("%w: expected a non-nil struct", ErrInvalidConfiguration)
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%w: expected a struct or pointer to struct", ErrInvalidConfiguration)
	}
	fields := make(map[string]string, len(rules))
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.PkgPath != "" || v.Field(i).Kind() != reflect.String {
			continue
		}
		name := field.Tag.Get("payment")
		if name == "" {
			name = field.Name
		}
		if v.Field(i).CanInterface() {
			fields[name] = v.Field(i).String()
		}
	}
	for name := range rules {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("%w: configured payment field not found", ErrInvalidConfiguration)
		}
	}
	return ValidateFieldMap(fields, rules)
}

func validateExactDigits(value string, t Type, sensitivity Sensitivity, length int) (Result, error) {
	r := result(t, sensitivity, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != length {
		r.Reason = ReasonInvalidLength
	} else if !asciiDigits(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(t, sensitivity, ReasonValid)
	}
	return r, nil
}

func normalizeDigitGroups(value string, groups ...int) (string, bool) {
	if !strings.Contains(value, "-") {
		return value, true
	}
	expectedLength := len(groups) - 1
	for _, length := range groups {
		expectedLength += length
	}
	if len(value) != expectedLength {
		return "", false
	}
	offset := 0
	for i, length := range groups {
		if !asciiDigits(value[offset : offset+length]) {
			return "", false
		}
		offset += length
		if i < len(groups)-1 {
			if value[offset] != '-' {
				return "", false
			}
			offset++
		}
	}
	return strings.ReplaceAll(value, "-", ""), true
}

func buildCurrencyMinorUnits() map[string]int {
	codes := strings.Fields("AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL BSD BTN BWP BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MXV MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD USN UYI UYU UYW UZS VES VND VUV WST XAD XAF XAG XAU XBA XBB XBC XBD XCD XCG XDR XOF XPD XPF XPT XSU XTS XUA XXX YER ZAR ZMW ZWG")
	units := make(map[string]int, len(codes))
	for _, code := range codes {
		units[code] = 2
	}
	for _, code := range strings.Fields("BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF XAG XAU XBA XBB XBC XBD XDR XPD XPT XTS XUA XXX") {
		units[code] = 0
	}
	for _, code := range strings.Fields("BHD IQD JOD KWD LYD OMR TND CLF UYW") {
		units[code] = 3
	}
	units["CLF"] = 4
	units["UYW"] = 4
	return units
}

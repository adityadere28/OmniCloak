package payment

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RoutingRail identifies a US ABA routing use.
type RoutingRail string

const (
	// RoutingACH identifies ACH routing.
	RoutingACH RoutingRail = "ach"
	// RoutingWire identifies wire routing.
	RoutingWire RoutingRail = "wire"
	// RoutingCheck identifies paper-check routing.
	RoutingCheck RoutingRail = "check"
)

// ValidateABARoutingForRail validates the ABA checksum and routing-prefix eligibility.
func ValidateABARoutingForRail(value string, rail RoutingRail) (Result, error) {
	var allowed func(int) bool
	switch rail {
	case RoutingACH:
		allowed = func(prefix int) bool {
			return inRange(prefix, 1, 12) || inRange(prefix, 21, 32) || inRange(prefix, 61, 72)
		}
	case RoutingWire:
		allowed = func(prefix int) bool { return inRange(prefix, 1, 12) || inRange(prefix, 21, 32) }
	case RoutingCheck:
		allowed = func(prefix int) bool {
			return prefix == 0 || inRange(prefix, 1, 12) || inRange(prefix, 21, 32) ||
				inRange(prefix, 61, 72) || prefix == 80
		}
	default:
		return Result{}, fmt.Errorf("%w: unsupported routing rail", ErrInvalidConfiguration)
	}
	r := result(TypeRoutingRail, SensitivityHigh, ReasonInvalidFormat)
	base, _ := ValidateABARoutingNumber(value)
	if !base.Valid {
		r.Reason = base.Reason
		return r, nil
	}
	prefix, _ := strconvAtoi2(value[:2])
	if !allowed(prefix) {
		r.Reason = ReasonRuleMismatch
		return r, nil
	}
	return result(TypeRoutingRail, SensitivityHigh, ReasonValid), nil
}

func strconvAtoi2(value string) (int, bool) {
	if len(value) != 2 || !asciiDigits(value) {
		return 0, false
	}
	return int(value[0]-'0')*10 + int(value[1]-'0'), true
}

func inRange(value, min, max int) bool {
	return value >= min && value <= max
}

// ValidateUSCheckMICR validates routing, account, and check-number components.
func ValidateUSCheckMICR(routing, account, checkNumber string) (Result, error) {
	r := result(TypeMICR, SensitivityHigh, ReasonInvalidFormat)
	routingResult, _ := ValidateABARoutingNumber(routing)
	if !routingResult.Valid {
		r.Reason = routingResult.Reason
		return r, nil
	}
	if account == "" || checkNumber == "" {
		r.Reason = ReasonEmpty
	} else if len(account) < 1 || len(account) > 17 || len(checkNumber) < 1 || len(checkNumber) > 10 {
		r.Reason = ReasonInvalidLength
	} else if !asciiDigits(account) || !asciiDigits(checkNumber) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeMICR, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// ValidateACHCompanyID checks the ten-character NACHA Company ID field.
func ValidateACHCompanyID(value string) (Result, error) {
	r := result(TypeACHCompanyID, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 10 {
		r.Reason = ReasonInvalidLength
	} else if !asciiAlphaNumeric(value) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeACHCompanyID, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// ValidateACHTraceNumber checks the 15-digit NACHA trace-number structure.
func ValidateACHTraceNumber(value string) (Result, error) {
	return validateExactDigits(value, TypeACHTrace, SensitivityHigh, 15)
}

// ValidateACHReturnCode checks a defined NACHA return code.
func ValidateACHReturnCode(value string) (Result, error) {
	return validateACHCode(value, achReturnCodes, "R")
}

// ValidateNOCCode checks a defined NACHA Notification of Change code.
func ValidateNOCCode(value string) (Result, error) {
	return validateACHCode(value, achNOCCodes, "C")
}

func validateACHCode(value string, allowed map[string]struct{}, prefix string) (Result, error) {
	r := result(TypeACHCode, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 3 {
		r.Reason = ReasonInvalidLength
	} else if value[0] != prefix[0] || !asciiDigits(value[1:]) {
		r.Reason = ReasonInvalidCharacter
	} else if _, ok := allowed[value]; !ok {
		r.Reason = ReasonRuleMismatch
	} else {
		r = result(TypeACHCode, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

var achReturnCodes = codeSet("R01 R02 R03 R04 R05 R06 R07 R08 R09 R10 R11 R12 R13 R14 R15 R16 R17 R18 R19 R20 R21 R22 R23 R24 R25 R26 R27 R28 R29 R30 R31 R32 R33 R34 R35 R36 R37 R38 R39 R40 R41 R42 R43 R44 R45 R46 R47 R50 R51 R52 R53 R61 R62 R63 R64 R65 R66 R67 R68 R69 R70 R71 R72 R73 R74 R75 R76 R77 R80 R81 R82 R83 R84 R85")
var achNOCCodes = codeSet("C01 C02 C03 C04 C05 C06 C07 C08 C09 C10 C11 C12 C13 C14")

func codeSet(values string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, value := range strings.Fields(values) {
		set[value] = struct{}{}
	}
	return set
}

// ValidateEIN checks the US EIN format and assigned prefix ranges, not ownership.
func ValidateEIN(value string) (Result, error) {
	digits, ok := normalizeTaxID(value, 2, 7)
	r := result(TypeEIN, SensitivityCritical, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if !ok {
		r.Reason = ReasonInvalidCharacter
	} else if len(digits) != 9 {
		r.Reason = ReasonInvalidLength
	} else {
		prefix, _ := strconvAtoi2(digits[:2])
		if !validEINPrefix(prefix) {
			r.Reason = ReasonRuleMismatch
		} else {
			r = result(TypeEIN, SensitivityCritical, ReasonValid)
		}
	}
	return r, nil
}

func validEINPrefix(prefix int) bool {
	return inRange(prefix, 1, 6) || inRange(prefix, 10, 16) || inRange(prefix, 20, 27) ||
		inRange(prefix, 30, 48) || inRange(prefix, 50, 68) || inRange(prefix, 71, 77) ||
		inRange(prefix, 80, 88) || inRange(prefix, 90, 99)
}

// ValidateITIN checks the US ITIN structure, not issuance or current validity.
func ValidateITIN(value string) (Result, error) {
	digits, ok := normalizeTaxID(value, 3, 2, 4)
	r := result(TypeITIN, SensitivityCritical, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if !ok {
		r.Reason = ReasonInvalidCharacter
	} else if len(digits) != 9 {
		r.Reason = ReasonInvalidLength
	} else {
		middle, _ := strconvAtoi2(digits[3:5])
		if digits[0] != '9' || !(inRange(middle, 50, 65) || inRange(middle, 70, 88) ||
			inRange(middle, 90, 92) || inRange(middle, 94, 99)) {
			r.Reason = ReasonRuleMismatch
		} else {
			r = result(TypeITIN, SensitivityCritical, ReasonValid)
		}
	}
	return r, nil
}

// ValidateSSN checks US SSN structural exclusions, not assignment or ownership.
func ValidateSSN(value string) (Result, error) {
	digits, ok := normalizeTaxID(value, 3, 2, 4)
	r := result(TypeSSN, SensitivityCritical, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if !ok {
		r.Reason = ReasonInvalidCharacter
	} else if len(digits) != 9 {
		r.Reason = ReasonInvalidLength
	} else if digits[:3] == "000" || digits[:3] == "666" || digits[0] == '9' ||
		digits[3:5] == "00" || digits[5:] == "0000" {
		r.Reason = ReasonRuleMismatch
	} else {
		r = result(TypeSSN, SensitivityCritical, ReasonValid)
	}
	return r, nil
}

func normalizeTaxID(value string, groups ...int) (string, bool) {
	if len(value) == 0 {
		return "", true
	}
	var b strings.Builder
	groupIndex, groupSize := 0, groups[0]
	segmentLength := 0
	for i := 0; i < len(value); i++ {
		if value[i] == '-' {
			if i == 0 || i == len(value)-1 || groupIndex >= len(groups)-1 || segmentLength != groupSize {
				return "", false
			}
			groupIndex++
			groupSize = groups[groupIndex]
			segmentLength = 0
			continue
		}
		if value[i] < '0' || value[i] > '9' {
			return "", false
		}
		b.WriteByte(value[i])
		segmentLength++
		if b.Len() > sumInts(groups) {
			return "", false
		}
	}
	return b.String(), groupIndex == 0 ||
		groupIndex == len(groups)-1 && segmentLength == groupSize && b.Len() == sumInts(groups)
}

func sumInts(values []int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

// ValidateUSZIP accepts five-digit ZIP and ZIP+4 formats.
func ValidateUSZIP(value string) (Result, error) {
	r := result(TypeUSZIP, SensitivityHigh, ReasonInvalidFormat)
	if value == "" {
		r.Reason = ReasonEmpty
	} else if len(value) != 5 && len(value) != 10 {
		r.Reason = ReasonInvalidLength
	} else if len(value) == 5 && !asciiDigits(value) ||
		len(value) == 10 && (value[5] != '-' || !asciiDigits(value[:5]) || !asciiDigits(value[6:])) {
		r.Reason = ReasonInvalidCharacter
	} else {
		r = result(TypeUSZIP, SensitivityHigh, ReasonValid)
	}
	return r, nil
}

// ValidateAVSAddress validates billing address line 1 and a US AVS postal code.
func ValidateAVSAddress(address, postalCode string) (Result, error) {
	r := result(TypeAVS, SensitivityHigh, ReasonInvalidFormat)
	if address == "" || postalCode == "" {
		r.Reason = ReasonEmpty
		return r, nil
	}
	if len(address) > 400 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	if !utf8.ValidString(address) {
		r.Reason = ReasonInvalidCharacter
		return r, nil
	}
	if utf8.RuneCountInString(address) > 100 {
		r.Reason = ReasonInvalidLength
		return r, nil
	}
	for _, char := range address {
		if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
			r.Reason = ReasonInvalidCharacter
			return r, nil
		}
	}
	zipResult, _ := ValidateUSZIP(postalCode)
	if !zipResult.Valid {
		r.Reason = zipResult.Reason
		return r, nil
	}
	return result(TypeAVS, SensitivityHigh, ReasonValid), nil
}

// AccountKind identifies the account class used for payment policy.
type AccountKind string

const (
	// AccountConsumer identifies a consumer account.
	AccountConsumer AccountKind = "consumer"
	// AccountCommercial identifies a commercial account.
	AccountCommercial AccountKind = "commercial"
)

// ValidateAccountKind accepts consumer or commercial account classifications.
func ValidateAccountKind(value string) (Result, error) {
	r := result(TypeAccountType, SensitivityMedium, ReasonRuleMismatch)
	if value == string(AccountConsumer) || value == string(AccountCommercial) {
		return result(TypeAccountType, SensitivityMedium, ReasonValid), nil
	}
	if value == "" {
		r.Reason = ReasonEmpty
	}
	return r, nil
}

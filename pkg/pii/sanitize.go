// Package pii removes or neutralizes PII before values cross an agent boundary.
package pii

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Mode selects how detected PII is treated.
type Mode string

const (
	// ModeDrop omits sensitive fields and PII-bearing values.
	ModeDrop Mode = "drop"
	// ModeRedact replaces sensitive values and matches with a fixed placeholder.
	ModeRedact Mode = "redact"
	// ModeChar masks each character in a sensitive value.
	ModeChar Mode = "char"
	// ModeLast4 preserves only the configured suffix of lower-risk values.
	ModeLast4 Mode = "last4"
	// ModePrefix preserves only the configured prefix of lower-risk values.
	ModePrefix Mode = "prefix"
	// ModeToken replaces lower-risk values with keyed HMAC-SHA256 tokens.
	ModeToken Mode = "token"
	// ModeAllowlist keeps only configured fields and sanitizes their contents.
	ModeAllowlist Mode = "allowlist"
)

// Options configures deterministic recursive sanitization. The empty mode defaults to drop.
type Options struct {
	// Mode selects sanitization behavior; zero selects ModeDrop.
	Mode Mode
	// Allowlist contains safe field names or full paths for ModeAllowlist.
	Allowlist []string
	// MaskChar is used by character and edge masking; zero selects '*'.
	MaskChar rune
	// EdgeCount configures ModeLast4 and ModePrefix; zero selects four runes.
	EdgeCount int
	// PreserveSeparators retains non-letter/digit formatting in mask modes.
	PreserveSeparators bool
	// TokenKey is the injected HMAC key and must contain at least 32 bytes in ModeToken.
	TokenKey []byte
	// MaxDepth limits recursive container traversal; zero selects 64.
	MaxDepth int
	// MaxNodes limits visited values; zero selects 10,000.
	MaxNodes int
	// MaxInputBytes limits each text value; zero selects 1 MiB.
	MaxInputBytes int
}

const redacted = "[REDACTED]"

// ErrInvalidConfiguration indicates invalid sanitizer options.
var ErrInvalidConfiguration = errors.New("invalid sanitizer configuration")

type detector struct {
	pattern  *regexp.Regexp
	highRisk bool
}

func compileDetector(expression string, highRisk bool) detector {
	return detector{
		pattern:  regexp.MustCompile(expression),
		highRisk: highRisk,
	}
}

var piiDetectors = []detector{
	compileDetector(`%B[^\r\n?]{8,78}\?`, true),
	compileDetector(`;[0-9]{13,19}=[0-9]{7,}[?]`, true),
	compileDetector(`\p{Nd}{3,20}`, true),
	compileDetector(`(?i)\b(?:cvv|cvc|cid|card[- _]?security[- _]?code)\b\s*(?:[:=]\s*|\s+)\p{Nd}{3,4}\b`, true),
	compileDetector(`(?i)\b(?:ssn|social[- _]?security[- _]?number|itin|ein|tax[- _]?id|account(?:[- _]?(?:number|no))?|routing(?:[- _]?(?:number|no))?|passport(?:[- _]?(?:number|no))?|card[- _]?(?:number|pan))\b\s*[:=#]\s*[A-Z0-9 -]{3,30}\b`, true),
	compileDetector(`(?i)[\p{L}\p{N}._%+-]+[@＠][\p{L}\p{N}.-]+[.．][\p{L}]{2,}`, false),
	compileDetector(`(?i)\p{L}{2}\p{Nd}{2}(?:[\p{Zs}]?[\p{L}\p{Nd}]){11,30}`, true),
	compileDetector(`(?:[0-9][ \t\r\n\p{Zs}-]?){12,18}[0-9]`, true),
	compileDetector(`\b[0-9]{3}-?[ ]?[0-9]{2}-?[ ]?[0-9]{4}\b`, true),
	compileDetector(`\b(?:\+?[0-9]{1,3}[ .-]?)?(?:\(?[0-9]{3}\)?[ .-]?)?[0-9]{3}[ .-]?[0-9]{4}\b`, false),
	compileDetector(`\b[0-9]{5,7}\b`, true),
	compileDetector(`(?i)\b(?:name|full[- _]?name|email|phone|mobile|address|date[- _]?of[- _]?birth|dob)\b\s*[:=]\s*[^,;\r\n]{1,100}`, false),
	compileDetector(`\b(?:[0-9]{1,2}[/-]){2}(?:[0-9]{2}|[0-9]{4})\b|\b[0-9]{4}-[0-9]{2}-[0-9]{2}\b`, false),
	compileDetector(`\b[0-9]{5}(?:-[0-9]{4})?\b`, false),
	compileDetector(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, false),
	compileDetector(`^[+-]?[0-9]+(?:\.[0-9]+)?[eE][+-]?[0-9]+$`, true),
	compileDetector(`(?:[0-9][0-9 \t\r\n\p{Zs}-]{6,}[0-9])|(?:\p{Nd}[\p{Nd}\p{Zs}-]{6,}\p{Nd})`, true),
}

type sanitizer struct {
	options Options
	allowed map[string]struct{}
	nodes   int
}

// SanitizeForAgent recursively removes or neutralizes PII before agent use.
// Unsupported values, malformed JSON, and resource-limit overflows are dropped.
func SanitizeForAgent(input any, options Options) (any, error) {
	normalized, allowed, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	s := sanitizer{options: normalized, allowed: allowed}
	value, drop, err := s.walk(reflect.ValueOf(input), "", "", false, 0)
	if err != nil {
		return nil, err
	}
	if drop {
		return nil, nil
	}
	return value, nil
}

// SkipPII reports whether a field name or path commonly identifies PII or credentials.
func SkipPII(fieldName string) bool {
	if len(fieldName) > 256 {
		return true
	}
	return fieldRisk(fieldName) != 0
}

type risk uint8

const (
	noRisk risk = iota
	personalRisk
	highRisk
)

var highRiskNames = []string{
	"cvv", "cvc", "cid", "securitycode", "cardnumber", "primaryaccountnumber",
	"pan", "track1", "track2", "trackdata", "magneticstripe", "bankaccount",
	"account", "accountid", "accountnumber", "routing", "routingnumber", "iban",
	"ssn", "socialsecuritynumber", "itin", "ein", "taxid", "paymenttoken", "token",
	"walletaddress", "wallettag", "password", "passwd",
	"secret", "secretkey", "credential", "apikey", "accesskey", "privatekey",
	"authtoken", "refreshtoken", "sessiontoken", "authorization", "authorizationheader",
}

var personalNames = []string{
	"name", "fullname", "firstname", "lastname", "email", "emailaddress",
	"phone", "phonenumber", "mobile", "address", "street", "city", "postalcode",
	"zipcode", "dob", "dateofbirth", "birthdate", "passport", "passportnumber",
	"license", "driverslicense", "nationalid", "patientid", "medicalrecordnumber",
	"healthid", "insuranceid", "memberid", "username", "userhandle", "ipaddress",
	"location", "geolocation", "deviceid", "diagnosis", "medicalhistory",
	"prescription", "medication", "healthcondition", "biometric", "geneticdata",
	"labresult", "bloodtype",
}

func fieldRisk(name string) risk {
	for _, char := range name {
		if char > unicode.MaxASCII {
			return highRisk
		}
	}
	found := noRisk
	for _, part := range splitFieldPath(name) {
		normalized := normalizeName(part)
		if matchesAlias(normalized, highRiskNames) {
			return highRisk
		}
		if matchesAlias(normalized, personalNames) {
			found = personalRisk
		}
	}
	normalized := normalizeName(name)
	if matchesAlias(normalized, highRiskNames) {
		return highRisk
	}
	if matchesAlias(normalized, personalNames) {
		found = personalRisk
	}
	return found
}

func matchesAlias(name string, aliases []string) bool {
	for _, alias := range aliases {
		if name == alias || strings.HasSuffix(name, alias) {
			return true
		}
	}
	return false
}

func normalizeName(value string) string {
	var b strings.Builder
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			b.WriteRune(unicode.ToLower(char))
		}
	}
	return b.String()
}

func splitFieldPath(value string) []string {
	return strings.FieldsFunc(value, func(char rune) bool {
		return !unicode.IsLetter(char) && !unicode.IsDigit(char)
	})
}

func normalizeOptions(options Options) (Options, map[string]struct{}, error) {
	if options.Mode == "" {
		options.Mode = ModeDrop
	}
	switch options.Mode {
	case ModeDrop, ModeRedact, ModeChar, ModeLast4, ModePrefix, ModeToken, ModeAllowlist:
	default:
		return Options{}, nil, ErrInvalidConfiguration
	}
	if options.MaskChar == 0 {
		options.MaskChar = '*'
	}
	if !unicode.IsGraphic(options.MaskChar) || unicode.IsSpace(options.MaskChar) ||
		unicode.IsLetter(options.MaskChar) || unicode.IsDigit(options.MaskChar) {
		return Options{}, nil, ErrInvalidConfiguration
	}
	if options.EdgeCount == 0 {
		options.EdgeCount = 4
	}
	if options.EdgeCount < 1 || options.EdgeCount > 8 {
		return Options{}, nil, ErrInvalidConfiguration
	}
	if options.MaxDepth == 0 {
		options.MaxDepth = 64
	}
	if options.MaxDepth < 1 || options.MaxDepth > 128 {
		return Options{}, nil, ErrInvalidConfiguration
	}
	if options.MaxNodes == 0 {
		options.MaxNodes = 10000
	}
	if options.MaxNodes < 1 || options.MaxNodes > 100000 {
		return Options{}, nil, ErrInvalidConfiguration
	}
	if options.MaxInputBytes == 0 {
		options.MaxInputBytes = 1 << 20
	}
	if options.MaxInputBytes < 1 || options.MaxInputBytes > 16<<20 {
		return Options{}, nil, ErrInvalidConfiguration
	}
	if options.Mode == ModeToken && (len(options.TokenKey) < 32 || len(options.TokenKey) > 4096) {
		return Options{}, nil, ErrInvalidConfiguration
	}
	if len(options.Allowlist) > 10000 {
		return Options{}, nil, ErrInvalidConfiguration
	}
	allowed := make(map[string]struct{}, len(options.Allowlist))
	for _, field := range options.Allowlist {
		if len(field) > 256 {
			return Options{}, nil, ErrInvalidConfiguration
		}
		normalized := normalizePath(field)
		if normalized == "" {
			return Options{}, nil, ErrInvalidConfiguration
		}
		allowed[normalized] = struct{}{}
	}
	return options, allowed, nil
}

func (s *sanitizer) walk(value reflect.Value, key, path string, approved bool, depth int) (any, bool, error) {
	if depth > s.options.MaxDepth || s.nodes >= s.options.MaxNodes {
		return nil, true, nil
	}
	s.nodes++
	if !value.IsValid() {
		return nil, false, nil
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, false, nil
		}
		return s.walk(value.Elem(), key, path, approved, depth+1)
	}

	if key != "" {
		fieldRisk := fieldRisk(key)
		isContainer := value.Kind() == reflect.Map || value.Kind() == reflect.Struct ||
			value.Kind() == reflect.Slice || value.Kind() == reflect.Array
		if s.options.Mode == ModeAllowlist && !s.allowedField(key, path) &&
			(!isContainer || !s.hasAllowedDescendant(path)) {
			return nil, true, nil
		}
		if fieldRisk != noRisk {
			return s.sanitizeSensitive(value, fieldRisk == highRisk)
		}
	}
	switch value.Kind() {
	case reflect.String:
		text := value.String()
		if len(text) > s.options.MaxInputBytes || !utf8.ValidString(text) || !safeText(text) {
			return nil, true, nil
		}
		return s.sanitizeText(text, key, path, approved, depth)
	case reflect.Map:
		if value.IsNil() {
			return nil, false, nil
		}
		if value.Type().Key().Kind() != reflect.String {
			return nil, true, nil
		}
		if value.Len() > s.options.MaxNodes-s.nodes {
			return nil, true, nil
		}
		type mapEntry struct {
			key   string
			value reflect.Value
		}
		entries := make([]mapEntry, 0, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			entries = append(entries, mapEntry{key: iterator.Key().String(), value: iterator.Value()})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
		result := make(map[string]any, value.Len())
		for _, entry := range entries {
			if s.nodes >= s.options.MaxNodes {
				break
			}
			field := entry.key
			if len(field) > s.options.MaxInputBytes || !utf8.ValidString(field) || s.hasPII(field) {
				continue
			}
			childPath := field
			if path != "" {
				childPath = path + "." + field
			}
			childApproved := s.allowedField(field, childPath)
			safe, drop, err := s.walk(entry.value, field, childPath, childApproved, depth+1)
			if err != nil {
				return nil, true, err
			}
			if !drop {
				result[field] = safe
			}
		}
		return result, false, nil
	case reflect.Struct:
		result := make(map[string]any, value.NumField())
		for i := 0; i < value.NumField(); i++ {
			if s.nodes >= s.options.MaxNodes {
				break
			}
			fieldInfo := value.Type().Field(i)
			if fieldInfo.PkgPath != "" {
				continue
			}
			field := jsonFieldName(fieldInfo)
			if field == "" || !value.Field(i).CanInterface() || s.hasPII(field) {
				continue
			}
			childPath := field
			if path != "" {
				childPath = path + "." + field
			}
			childApproved := s.allowedField(field, childPath)
			safe, drop, err := s.walk(value.Field(i), field, childPath, childApproved, depth+1)
			if err != nil {
				return nil, true, err
			}
			if !drop {
				result[field] = safe
			}
		}
		return result, false, nil
	case reflect.Slice:
		if value.IsNil() {
			return nil, false, nil
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return s.sanitizeBytes(value.Bytes(), key, path, approved, depth)
		}
		if s.options.Mode == ModeAllowlist && !approved && !s.hasAllowedDescendant(path) {
			return nil, true, nil
		}
		if text, ok := digitSequence(value); ok {
			if safe, drop := s.scrub(text); drop || safe != text {
				return safe, drop, nil
			}
		}
		fallthrough
	case reflect.Array:
		if s.options.Mode == ModeAllowlist && !approved && !s.hasAllowedDescendant(path) {
			return nil, true, nil
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.Len() > s.options.MaxInputBytes {
				return nil, true, nil
			}
			data := make([]byte, value.Len())
			for i := range data {
				data[i] = byte(value.Index(i).Uint())
			}
			return s.sanitizeBytes(data, key, path, approved, depth)
		}
		if text, ok := digitSequence(value); ok {
			if safe, drop := s.scrub(text); drop || safe != text {
				return safe, drop, nil
			}
		}
		result := make([]any, 0, value.Len())
		for i := 0; i < value.Len(); i++ {
			if s.nodes >= s.options.MaxNodes {
				break
			}
			safe, drop, err := s.walk(value.Index(i), "", path, approved, depth+1)
			if err != nil {
				return nil, true, err
			}
			if !drop {
				result = append(result, safe)
			}
		}
		return result, false, nil
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		if !value.CanInterface() {
			return nil, true, nil
		}
		text := scalarValueString(value)
		if s.options.Mode == ModeAllowlist && !approved {
			return nil, true, nil
		}
		safe, drop := s.scrub(text)
		if drop {
			return nil, true, nil
		}
		if safe != text {
			return safe, false, nil
		}
		return value.Interface(), false, nil
	default:
		return nil, true, nil
	}
}

func digitSequence(value reflect.Value) (string, bool) {
	if value.Len() < 3 || value.Len() > 20 {
		return "", false
	}
	digits := make([]byte, value.Len())
	for i := range digits {
		switch value.Index(i).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			number := value.Index(i).Int()
			if number < 0 || number > 9 {
				return "", false
			}
			digits[i] = byte('0' + number)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			number := value.Index(i).Uint()
			if number > 9 {
				return "", false
			}
			digits[i] = byte('0' + number)
		default:
			return "", false
		}
	}
	return string(digits), true
}

func (s *sanitizer) sanitizeSensitive(value reflect.Value, high bool) (any, bool, error) {
	if s.options.Mode == ModeDrop {
		return nil, true, nil
	}
	if high || s.options.Mode == ModeRedact || s.options.Mode == ModeAllowlist {
		return redacted, false, nil
	}
	text, ok := scalarString(value)
	if !ok {
		return redacted, false, nil
	}
	if len(text) > s.options.MaxInputBytes || !utf8.ValidString(text) || !safeText(text) {
		return nil, true, nil
	}
	return s.transform(text), false, nil
}

func scalarString(value reflect.Value) (string, bool) {
	for depth := 0; depth < 64 && value.IsValid() &&
		(value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer); depth++ {
		if value.IsNil() {
			return "", false
		}
		value = value.Elem()
	}
	if value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		return "", false
	}
	if !value.IsValid() {
		return "", false
	}
	switch value.Kind() {
	case reflect.String:
		return value.String(), true
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		if value.CanInterface() {
			return scalarValueString(value), true
		}
	}
	return "", false
}

func scalarValueString(value reflect.Value) string {
	switch value.Kind() {
	case reflect.Float32:
		return strconv.FormatFloat(value.Float(), 'f', -1, 32)
	case reflect.Float64:
		return strconv.FormatFloat(value.Float(), 'f', -1, 64)
	default:
		return fmt.Sprint(value.Interface())
	}
}

func (s *sanitizer) sanitizeBytes(value []byte, key, path string, approved bool, depth int) (any, bool, error) {
	if len(value) > s.options.MaxInputBytes || !utf8.Valid(value) || !safeText(string(value)) {
		return nil, true, nil
	}
	return s.sanitizeText(string(value), key, path, approved, depth)
}

func (s *sanitizer) sanitizeText(text, key, path string, approved bool, depth int) (any, bool, error) {
	if parsed, isJSON, invalid := decodeJSONText(text, s.options.MaxInputBytes); isJSON {
		return s.walk(reflect.ValueOf(parsed), key, path, approved, depth+1)
	} else if invalid {
		return nil, true, nil
	}
	if s.options.Mode == ModeAllowlist && !approved {
		return nil, true, nil
	}
	safe, drop := s.scrub(text)
	return safe, drop, nil
}

func safeText(value string) bool {
	for _, char := range value {
		if (unicode.IsControl(char) || unicode.Is(unicode.Cf, char)) && !unicode.IsSpace(char) {
			return false
		}
	}
	return true
}

func decodeJSONText(text string, maxBytes int) (any, bool, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false, false
	}
	if len(trimmed) > maxBytes || !json.Valid([]byte(trimmed)) {
		return nil, false, true
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false, true
	}
	return value, true, false
}

func jsonFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	if name, _, found := strings.Cut(tag, ","); found && name != "" {
		return name
	} else if !found && tag != "" {
		return tag
	}
	return field.Name
}

func (s *sanitizer) allowedField(key, path string) bool {
	if s.options.Mode != ModeAllowlist {
		return true
	}
	_, keyAllowed := s.allowed[normalizePath(key)]
	_, pathAllowed := s.allowed[normalizePath(path)]
	return keyAllowed || pathAllowed
}

func (s *sanitizer) hasAllowedDescendant(path string) bool {
	if s.options.Mode != ModeAllowlist {
		return true
	}
	prefix := normalizePath(path) + "."
	for allowed := range s.allowed {
		if strings.HasPrefix(allowed, prefix) {
			return true
		}
	}
	return false
}

func normalizePath(value string) string {
	parts := splitFieldPath(value)
	for i, part := range parts {
		parts[i] = normalizeName(part)
	}
	return strings.Join(parts, ".")
}

func (s *sanitizer) hasPII(value string) bool {
	matches := findMatches(value)
	return len(matches) != 0
}

type span struct {
	start    int
	end      int
	highRisk bool
}

func findMatches(value string) []span {
	var spans []span
	data := []byte(value)
	for _, detector := range piiDetectors {
		matches := detector.pattern.FindAllIndex(data, 10001)
		if len(matches)+len(spans) > 10000 {
			return []span{{start: 0, end: len(value), highRisk: true}}
		}
		for _, match := range matches {
			if len(match) == 2 && match[0] >= 0 && match[1] <= len(value) {
				spans = append(spans, span{start: match[0], end: match[1], highRisk: detector.highRisk})
			}
		}
	}
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end < spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	merged := spans[:1]
	for _, next := range spans[1:] {
		last := &merged[len(merged)-1]
		if next.start <= last.end {
			if next.end > last.end {
				last.end = next.end
			}
			last.highRisk = last.highRisk || next.highRisk
			continue
		}
		merged = append(merged, next)
	}
	return merged
}

func (s *sanitizer) scrub(value string) (string, bool) {
	matches := findMatches(value)
	if len(matches) == 0 {
		return value, false
	}
	if s.options.Mode == ModeDrop {
		return "", true
	}
	var result strings.Builder
	result.Grow(len(value))
	offset, projectedLength := 0, 0
	for _, match := range matches {
		replacement := redacted
		if !match.highRisk {
			replacement = s.transform(value[match.start:match.end])
		}
		projectedLength += match.start - offset + len(replacement)
		if projectedLength > s.options.MaxInputBytes {
			return redacted, false
		}
		result.WriteString(value[offset:match.start])
		result.WriteString(replacement)
		offset = match.end
	}
	projectedLength += len(value) - offset
	if projectedLength > s.options.MaxInputBytes {
		return redacted, false
	}
	result.WriteString(value[offset:])
	return result.String(), false
}

func (s *sanitizer) transform(value string) string {
	switch s.options.Mode {
	case ModeDrop:
		return ""
	case ModeRedact, ModeAllowlist:
		return redacted
	case ModeChar:
		return mask(value, s.options.MaskChar, s.options.PreserveSeparators)
	case ModeLast4:
		return edgeMask(value, s.options.MaskChar, s.options.EdgeCount, false, s.options.PreserveSeparators)
	case ModePrefix:
		return edgeMask(value, s.options.MaskChar, s.options.EdgeCount, true, s.options.PreserveSeparators)
	case ModeToken:
		mac := hmac.New(sha256.New, s.options.TokenKey)
		mac.Write([]byte("omnicloak/pii/v1\x00"))
		mac.Write([]byte(value))
		return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
	default:
		return redacted
	}
}

func mask(value string, char rune, preserveSeparators bool) string {
	runes := []rune(value)
	for i, current := range runes {
		if preserveSeparators && !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			continue
		}
		runes[i] = char
	}
	return string(runes)
}

func edgeMask(value string, char rune, count int, prefix, preserveSeparators bool) string {
	runes := []rune(value)
	eligible := make([]int, 0, len(runes))
	for i, current := range runes {
		if unicode.IsLetter(current) || unicode.IsDigit(current) {
			eligible = append(eligible, i)
		}
	}
	keep := make(map[int]struct{}, count)
	if prefix {
		for _, index := range eligible[:min(count, len(eligible))] {
			keep[index] = struct{}{}
		}
	} else {
		for _, index := range eligible[max(0, len(eligible)-count):] {
			keep[index] = struct{}{}
		}
	}
	for i, current := range runes {
		if _, ok := keep[i]; ok || preserveSeparators && !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			continue
		}
		runes[i] = char
	}
	return string(runes)
}

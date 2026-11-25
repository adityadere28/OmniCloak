# OmniCloak
Idiomatic, domain-aware PII validation package for Go across identity, financial, healthcare, and contact data.

## Payment validation

The reusable payment validators are available from `github.com/adityadere28/OmniCloak/pkg/payment`.
They validate locally and return a structured result with a non-sensitive reason code;
invalid input is not included in results. `Result.NonLoggable` marks PAN, CVV,
card-track, and cross-field card inputs as unsuitable for logs or persistence.

```go
result, err := payment.ValidatePAN("4111111111111111", payment.PANOptions{
	DetectScheme: true,
})
if err != nil {
	// Handle invalid validator configuration.
}
if !result.Valid {
	// Inspect result.Reason without logging the submitted value.
}
```

`pkg/payment` also provides CVV, card expiration, IBAN, ABA routing number,
bank account, and configurable payment-token validation.

Extended validators cover card metadata and track data, regional clearing
codes, ACH/SEPA/UPI fields, transaction identifiers and amounts, US payment
fields, and field-aware payload policies. Validators for institution-specific
New Zealand account checks require caller-supplied weights and modulus. Several
regional identifiers are structural checks only; they do not confirm issuance,
ownership, or enrollment with a financial institution.

## Agent-boundary PII sanitization

Import `github.com/adityadere28/OmniCloak/pkg/pii` and sanitize payloads before
passing them to an agent or tool. The default mode drops sensitive fields and
PII-bearing text; `SkipPII` is available for field-name guards. Other modes
include full redaction, character/edge masking, keyed HMAC tokens, and a
fail-closed allowlist.

```go
safe, err := pii.SanitizeForAgent(payload, pii.Options{})
if err != nil {
	// Invalid sanitizer configuration.
}
```

Partial masking is opt-in. High-risk fields (including CVV, raw PAN, track data,
and credentials) are always dropped or fully redacted, never partially exposed.

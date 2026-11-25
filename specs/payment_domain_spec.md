# Domain Spec: `payment` (PII Validation)

## 1. Purpose
Define deterministic validation rules for payment-related Personally Identifiable Information (PII) and financial instruments in Go.

## 2. Supported Identifiers & Rules

### Card Primary Account Number (PAN)
- **Format:** Numeric digits only (after optional stripping of spaces/hyphens only if explicitly enabled by config).
- **Length:** Typically 13–19 digits depending on card network/scheme.
- **Validation:**
  - Non-empty, all ASCII digits (`0-9`).
  - Passes Luhn checksum check.
  - Optional scheme detection (e.g., Visa, Mastercard, Amex, Discover) if configured.
- **Sample (Synthetic):** `4111111111111111`

### Card Security Code (CVV / CVC / CID)
- **Format:** 3 or 4 ASCII digits (4 for Amex-style CID, 3 for standard card networks).
- **Validation:** Strict digit length check; note that CVV should generally be flagged as sensitive/non-persistent in logs/payloads.
- **Sample (Synthetic):** `123`, `9876`

### Card Expiration Date
- **Format:** `MM/YY` or `MM/YYYY` (and structured month/year fields if validated by field).
- **Validation:** Month in `01..12`; optional check against current/reference clock for expired vs. valid dates (inject clock/time rather than hidden global state where possible).
- **Sample (Synthetic):** `12/29`

### International Bank Account Number (IBAN)
- **Format:** 2-letter ISO country code + 2 check digits + up to 30 alphanumeric BBAN characters (normalized/uppercase without spaces).
- **Validation:** Length bounds by country code (if country rules enabled) and ISO 7064 mod-97-10 checksum validation.
- **Sample (Synthetic):** `GB82WEST12345698765432`

### US ABA Routing Transit Number (RTN)
- **Format:** Exactly 9 ASCII digits.
- **Validation:** Passes ABA routing checksum:
  `3*(d1+d4+d7) + 7*(d2+d5+d8) + 1*(d3+d6+d9) mod 10 == 0`.
- **Sample (Synthetic):** `021000021`

### Bank Account Number (Generic / Domestic)
- **Format:** Alphanumeric/digits within configurable min/max length bounds (context-dependent; high false-positive risk without field name or context).
- **Validation:** Structural bounds + optional custom regex/rule per institution or region.
- **Sample (Synthetic):** `000123456789`

### Payment Token / Wallet Reference (Optional / Extensible)
- **Format:** Provider- or vault-prefixed token patterns (e.g., `tok_...`, `pm_...` — configurable patterns).
- **Validation:** Matches allowed prefix/charset/length rules without exposing raw PANs.

## 3. Validator Contract & Behavior
- **Deterministic:** No network calls, external APIs, or hidden global mutable state.
- **Safe on bad input:** Empty strings, whitespace, control characters, Unicode lookalikes, or oversized inputs must return a clean validation result/error—never `panic`.
- **Actionable output:** Indicate whether valid/matched, which PII type/rule matched, severity/sensitivity level, and a non-sensitive reason code (avoid echoing raw sensitive values in error messages or logs).

## 4. Required Test Cases
- Valid synthetic inputs per payment type.
- Checksum failures (e.g., flipped digit in PAN, IBAN, or ABA RTN).
- Invalid lengths, non-digit characters, invalid months (`00`, `13`), and empty/whitespace inputs.
- Boundary lengths (e.g., 12, 13, 19, 20 digits for card numbers).
- Ensure error/reason strings do not leak raw input values.

## 5. Extended Validations (Optional / Configurable)
- **Card Metadata:** BIN/IIN range & length checks, card service code, magnetic stripe track rules (flag as high-risk/non-loggable), cardholder name format.
- **Clearing & Routing Codes:** ISO 9362 BIC/SWIFT (8/11 chars), UK sort code, Indian IFSC, Canadian institution/transit, Australian BSB, NZ bank/account check digits.
- **Regional Rails & Mandates:** UPI VPA (`id@handle`), US ACH SEC codes, SEPA Creditor Identifier (mod-97) & Mandate Reference, wallet tags.
- **Transaction & Merchant IDs:** MID, TID, ISO 4217 currency code, monetary amount/minor-unit precision, STAN/RRN.
- **Cross-Field & Policy Checks:** PAN/scheme/CVV alignment, forbidden-field rules (e.g., raw CVV/track data), masked-vs-raw detection, Unicode/whitespace normalization, and struct/map field-aware validation.

## 6. United States (US) Specific Validations
- **Routing & Clearing Rails:** ABA prefix series checks (`01-12`, `61-72`, etc.), ACH vs. wire vs. check routing differentiation, US check MICR components.
- **NACHA / ACH Metadata:** SEC codes (`PPD`, `CCD`, `CTX`, `WEB`, `TEL`, `IAT`), ACH Company ID, trace numbers, and NACHA return/NOC codes.
- **Payout & Tax Identifiers (when paired with payments):** US EIN (`XX-XXXXXXX`), ITIN, SSN structural checks, and 5-digit / ZIP+4 billing postal codes.
- **US Card & Account Rules:** AVS address/ZIP inputs, Amex 4-digit CID vs. 3-digit CVV checks, consumer vs. commercial account type flags, and USD minor-unit (cents) validation.
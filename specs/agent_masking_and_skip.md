# Spec: Agent PII Masking & Skip Guard

## 1. Purpose
Define deterministic masking, redaction, and field-skipping behavior so sensitive payment and PII data is excluded or neutralized before reaching an AI agent, LLM prompt, tool call, or external model boundary.

## 2. Masking & Sanitization Modes
- **Field Skip / Drop (`drop`):** Omit sensitive keys/fields completely from maps, structs, or payloads so neither value nor structure is forwarded. Recommended default for high-risk fields (CVV/CVC, raw PAN, bank accounts, SSNs/EINs, tokens).
- **Full Redaction (`redact`):** Replace matched or sensitive values with a fixed placeholder (e.g., `[REDACTED]` or `[REDACTED:<TYPE>]`).
- **Character / Length Masking (`char`):** Replace characters with a mask character (e.g., `*` or `X`) preserving rune count or formatting separators when explicitly allowed.
- **Partial / Edge Masking (`last4` / `prefix`):** Retain only a minimal suffix or prefix (e.g., `****1111`). Must be explicitly opted into and avoided for strict zero-PII agent boundaries where correlation/display hints aren't required.
- **Keyed Tokenization / HMAC (`token`):** Replace values with a deterministic keyed token/HMAC using an injected secret/keyer (never plain unsalted hashes).
- **Fail-Closed Allowlist (`allowlist`):** Drop or redact any field not explicitly marked safe for agent consumption.

## 3. Single-Method Entry Point Contract
- **Single method:** Provide a single primary entry point (e.g., `SkipPII` / `SanitizeForAgent`) that handles:
  - Sensitive field names/paths (case-insensitive, whitespace/separator-normalized, including common aliases).
  - Pattern/detector matches within string values (card-like digit runs, IBAN/routing/account/ID patterns, etc.).
  - Nested containers (maps, slices/arrays, structs, JSON payloads) recursively.
- **Deterministic & side-effect free:** No network calls, external I/O, or hidden global mutable state.
- **Never panics:** Nil inputs, empty strings/maps/slices, unexpected types, deeply nested structures, or malformed/oversized inputs must safely degrade (drop or redact) without panicking.
- **Fail-closed default:** When ambiguous or unverified, prefer skipping or redacting over exposing raw values.

## 4. Security & Anti-Leakage Rules
- **No raw PII in outputs or errors:** Never echo raw sensitive values, partial secrets, or unmasked inputs in returned values, reasons, or error messages.
- **High-risk non-loggable fields:** CVV/CVC/CID, magnetic stripe track data, and raw credentials must always be dropped or fully redacted regardless of partial-mask settings.
- **Defense in depth:** Key-name checks alone are insufficient (due to renamed fields or free text); combine structural/field rules with content/pattern scrubbing and optional allowlisting.

## 5. Required Test Cases
- Dropping vs. redacting sensitive keys across flat and nested maps/structs/slices.
- Scrubbing PII-like patterns embedded inside strings and free text.
- Strict non-exposure of CVV/CVC and sensitive identifiers even when `last4` or `char` masking is requested.
- Fail-closed behavior on unknown keys when allowlist/strict mode is enabled.
- Nil, empty, malformed, oversized, and non-string/numeric/bool inputs returning safely without panics.
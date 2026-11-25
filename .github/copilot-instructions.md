# Copilot Instructions — `piidom` (Go PII Validation)

## Scope & Architecture
- Domain-scoped PII validators in Go: `identity`, `finance`, `health`, `contact`.
- Keep core validation deterministic, fast, and dependency-light (prefer stdlib; justify any external dependency).
- Return structured results/reasons and explicit `error` values; never `panic` on invalid or untrusted input.

## Go & Testing Style
- Follow idiomatic Go (`gofmt`, clear exported types/functions with Go doc comments, small focused functions).
- Write table-driven tests with `testing` covering valid cases, invalid formats/checksums, edge cases, and nil/empty inputs.
- Avoid over-engineering or unrequested abstractions.

## Privacy & Safety
- Never include real PII, credentials, API keys, or sensitive fixtures in code, comments, or tests. Use synthetic test data only.

## Output Efficiency
- Be concise. Provide code directly and keep explanations brief unless asked for a walkthrough.

<!-- rtk-instructions v2 -->
# RTK — Token-Optimized CLI

**rtk** is a CLI proxy that filters and compresses command outputs, cutting 60-90% of bash output.

## Rule

Prefix external programs with `rtk`:

```bash
# Instead of:              Use:
git status                 rtk git status
git log -10                rtk git log -10
cargo test                 rtk cargo test
docker ps                  rtk docker ps
kubectl get pods           rtk kubectl get pods
```

Do not prefix shell builtins or keywords — `test`, `[`, `read`, `cd`, `echo`,
`export`, `eval`, `source`, `printf`. Commands such as `test`, `read`, and
`env` also have RTK subcommands with different meanings; invoke the native
command directly when you need it.

## Meta commands (use directly)

```bash
rtk gain              # Token savings dashboard
rtk gain --history    # Per-command savings history
rtk discover          # Find missed rtk opportunities
rtk bypass <cmd>      # Run raw (no filtering) but track usage
```
<!-- /rtk-instructions -->
# Progress

## Current state

- **M0 — Foundations**: done.
- **M1 — Email parsing + source abstraction**: done.
- **M2 — Header analyzer**: done (pending PR review).
- **Next: M3 — Dataset + eval harness (header-only baseline).**

## M2 summary (2026-10-17)

What was built:

- `src/triage/analyzers/auth_results.py`: RFC 8601 `Authentication-Results` parser
  (authserv-id, method results, `ptype.property` values; comments, versions, repeated DKIM).
- `src/triage/analyzers/domains.py`: address/display-name extraction, organizational domain,
  relaxed alignment, Levenshtein distance, look-alike "skeleton", punycode decoding. No new deps.
- `src/triage/analyzers/headers.py`: `analyze_headers(email) -> list[Signal]` and
  `header_risk_score(signals)`. Signals: SPF/DKIM/DMARC results (only from the trusted
  receiving server), SPF/DKIM alignment, ARC-softened DMARC fail, untrusted/missing auth
  results, Reply-To and Return-Path mismatch, display-name brand mismatch, executive title from
  free webmail, lookalike domain, brand name inside an unrelated domain, IDN/punycode domain,
  Received-chain time order, Date after delivery / long before delivery / missing.
  Run on one file: `python -m triage.analyzers.headers <file.eml>`.
- 8 new header fixtures in `tests/fixtures/headers_*.eml`; 45 tests passing; lint and mypy clean.

Definition of done check: fixtures produce the expected signals, each with evidence quoted from
the headers; tests pass. Met.

No metrics produced. Header-only precision/recall/FPR is M3's job (`run_eval.py`).

Known limits to measure in M3:

- The mailing-list case (DKIM broken by the list, ARC pass) still gets medium/low signals.
- Header-only checks cannot see phishing sent from a domain the attacker owns with no brand
  reference (e.g. a parcel-redelivery lure that passes SPF/DKIM/DMARC); body/URL analysis (M4)
  is needed there.
- The protected-brand list includes the fictional vendors of the dataset scenario; see ADR-007.

## M1 summary (2026-10-11)

What was built:

- `src/triage/schemas.py`: `Signal`, `Header`, `Attachment`, `ParsedEmail` pydantic models.
- `src/triage/parsing.py`: `parse_eml(raw, source)` using the stdlib `email` package
  (`policy=default`). Extracts headers (repeated ones kept in order, RFC 2047 decoded), text and
  HTML bodies, http(s) URLs, attachments and inline images (bytes + SHA-256). Never raises;
  problems become `parse_issues` signals.
- `src/triage/sources/`: `EmailSource` interface and `EmlFileSource` (one file or a directory).
- `tests/fixtures/`: 8 hand-written `.eml` files (plain text, HTML-only with quoted-printable,
  multipart/alternative with base64, attachments incl. inline-disposition file, nested
  multipart with inline image and forwarded email, bad charsets, multipart without boundary,
  binary garbage).
- Tests: 22 passing (`make test`); `make lint` clean; `mypy src` clean.
- All 33 seed dataset emails parse with no issues (checked by a test).

Definition of done check: 5+ fixtures parse correctly (8), tests pass, a broken email does not
crash the app and produces signals instead. Met.

No metrics produced in this milestone (parsing only).

## Open questions

- None blocking for M2. Evidence strings quote domains (not full URLs or IPs); a shared defang
  helper arrives in M4 together with URL analysis.
- Forwarded `message/rfc822` attachments are not parsed recursively yet; revisit
  if M2/M4 need to analyze the inner email.

# Progress

## Current state

- **M0 — Foundations**: done.
- **M1 — Email parsing + source abstraction**: done (pending PR review).
- **Next: M2 — Header analyzer.**

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

- None blocking. Forwarded `message/rfc822` attachments are not parsed recursively yet; revisit
  if M2/M4 need to analyze the inner email.

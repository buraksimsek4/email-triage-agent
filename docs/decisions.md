# Decisions

Short records of design choices: what we chose and why.

## ADR-001: Parser lives in `parsing.py`, shared by every source (M1)

`EmlFileSource` and the future `GraphSource` both obtain raw RFC 5322 bytes (Graph gives them via
`GET /me/messages/{id}/$value`). Parsing those bytes is the same job either way, so it lives in one
function, `triage.parsing.parse_eml`, instead of inside each source. This guarantees both sources
produce an identical `ParsedEmail`.

## ADR-002: The parser never raises; problems become signals (M1)

Email is attacker-controlled and real mail is often malformed. Malformed MIME can itself be an
evasion trick, so it is evidence, not just an error. `parse_eml` catches everything and records
problems in `ParsedEmail.parse_issues` as `Signal`s (`mime_defect`, `malformed_header`,
`body_decode_error`, `mime_depth_exceeded`, `no_headers`, `parse_failed`). A single bad email can
never stop the pipeline.

## ADR-003: Attachments are bytes in memory, never files on disk (M1)

Attachments are kept as `bytes` with a SHA-256 hash. Nothing is written to disk with an executable
name, so nothing can be opened by accident. The bytes are excluded from `repr` and JSON output so
they never end up in logs. Forwarded emails (`message/rfc822`) are kept whole as attachments so
their body is not mixed into the outer email's body.

## ADR-004: pydantic is the first runtime dependency (M1)

`pydantic` (listed in the project's tech stack) validates every cross-module model. URL extraction
in M1 is a simple regex over both bodies; `beautifulsoup4` is deferred to M4, where link text vs
`href` analysis actually needs an HTML parser.

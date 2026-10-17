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

## ADR-005: Trust only our own server's Authentication-Results (M2)

Anyone can write an `Authentication-Results` header into a message before sending it. Only the
one added by our receiving server is real, so `HeaderConfig.trusted_authserv_ids` lists that
server (`mx1.testmailbox.example`) and every other copy becomes an `auth_results_untrusted`
signal. The receiving server adds its header on top, so the first trusted one is used. We do
not re-verify SPF/DKIM ourselves (`dkimpy`/`pyspf`); that would need DNS lookups at analysis
time and the receiving server already did the work.

## ADR-006: Organizational domain without the Public Suffix List (M2)

Alignment and mismatch checks compare organizational domains (`mail.contoso.example` ->
`contoso.example`). We use "last two labels" plus a short list of two-label suffixes such as
`com.tr` and `co.uk`, instead of adding `tldextract`. It is enough for the dataset and easy to
explain. If real-world mail with unusual suffixes appears, switch to `tldextract` (needs approval
as a new dependency).

## ADR-007: Simple, documented header risk score (M2)

`header_risk_score` adds points per signal by severity (info 0, low 5, medium 15, high 30) and
caps the total at 100. Points are a starting guess, not tuned; M3 measures them on the dev split
before any change. The protected-brand list in `DEFAULT_CONFIG` includes the fictional companies
of the dataset scenario (Contoso, Fabrikam, Northwind), as a real company would list its own
vendors. This helps header-only results on this dataset and must be disclosed next to any
header-only metric.

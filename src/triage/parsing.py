"""Turn raw email bytes into a ParsedEmail.

Email is attacker-controlled input, and real mail is often malformed. The parser therefore
never raises: anything odd it sees becomes a Signal in `parse_issues`, and later analyzers
decide what that means.
"""

import hashlib
import html
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message, MIMEPart
from email.parser import BytesParser

from triage.schemas import Attachment, Header, ParsedEmail, Signal

# Real mail rarely nests more than 3-4 levels; deeper trees are either broken or an attack.
MAX_MIME_DEPTH = 10
MAX_EVIDENCE_CHARS = 200

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_URL_TRAILING_PUNCTUATION = ".,;:!?)]}"
_FOLDED_LINE_RE = re.compile(r"\r?\n(?=[ \t])")


@dataclass
class _Parts:
    """Everything collected while walking the MIME tree."""

    text: list[str] = field(default_factory=list)
    html: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    inline_images: list[Attachment] = field(default_factory=list)
    issues: list[Signal] = field(default_factory=list)


def parse_eml(raw: bytes, source: str) -> ParsedEmail:
    """Parse one RFC 5322 message. `source` says where it came from (file path, Graph id)."""
    try:
        return _parse(raw, source)
    except Exception as exc:  # a single bad email must never stop the pipeline
        evidence = f"{type(exc).__name__}: {exc}"[:MAX_EVIDENCE_CHARS]
        return ParsedEmail(
            source=source,
            message_id=None,
            subject=None,
            headers=[],
            text_body=None,
            html_body=None,
            urls=[],
            attachments=[],
            inline_images=[],
            parse_issues=[Signal(name="parse_failed", severity="high", evidence=evidence)],
        )


def _parse(raw: bytes, source: str) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parts = _Parts()

    headers = _read_headers(msg, parts.issues)
    if not headers:
        parts.issues.append(
            Signal(name="no_headers", severity="medium", evidence="message has no header section")
        )

    _walk(msg, depth=0, parts=parts)

    text_body = "\n".join(parts.text) if parts.text else None
    html_body = "\n".join(parts.html) if parts.html else None
    return ParsedEmail(
        source=source,
        message_id=_first_header(headers, "Message-ID"),
        subject=_first_header(headers, "Subject"),
        headers=headers,
        text_body=text_body,
        html_body=html_body,
        urls=_extract_urls(text_body, html_body),
        attachments=parts.attachments,
        inline_images=parts.inline_images,
        parse_issues=parts.issues,
    )


def _read_headers(msg: MIMEPart, issues: list[Signal]) -> list[Header]:
    headers = []
    # raw_items() gives the undecoded values, so one broken header cannot hide the others.
    for name, raw_value in msg.raw_items():
        try:
            parsed = msg.policy.header_fetch_parse(name, raw_value)
            value = str(parsed)  # decodes RFC 2047 words like =?utf-8?b?...?=
            for defect in getattr(parsed, "defects", ()):
                issues.append(_defect_signal("malformed_header", name, defect))
        except Exception as exc:
            value = _FOLDED_LINE_RE.sub("", str(raw_value)).strip()
            issues.append(_defect_signal("malformed_header", name, exc))
        headers.append(Header(name=name, value=value))
    return headers


def _walk(part: MIMEPart, depth: int, parts: _Parts) -> None:
    content_type = part.get_content_type()
    for defect in part.defects:
        parts.issues.append(_defect_signal("mime_defect", content_type, defect))

    if depth > MAX_MIME_DEPTH:
        parts.issues.append(
            Signal(
                name="mime_depth_exceeded",
                severity="medium",
                evidence=f"MIME tree deeper than {MAX_MIME_DEPTH} levels; rest skipped",
            )
        )
        return

    # A forwarded email is kept whole as an attachment, so its body is not mixed into ours.
    if content_type == "message/rfc822":
        inner = part.get_payload(0)
        data = inner.as_bytes() if isinstance(inner, Message) else b""
        parts.attachments.append(_to_attachment(part, data))
        return

    if part.is_multipart():
        for child in part.iter_parts():
            _walk(child, depth + 1, parts)
        return

    # A multipart the stdlib could not split (e.g. no boundary): keep its text readable.
    if content_type.startswith("multipart/"):
        parts.text.append(_payload_as_text(part))
        return

    _handle_leaf(part, content_type, parts)


def _handle_leaf(part: MIMEPart, content_type: str, parts: _Parts) -> None:
    disposition = part.get_content_disposition()  # None, "inline" or "attachment"
    filename = part.get_filename()

    is_body = (
        content_type in ("text/plain", "text/html")
        and disposition != "attachment"
        and filename is None
    )
    if is_body:
        text = _decode_text(part, content_type, parts.issues)
        (parts.text if content_type == "text/plain" else parts.html).append(text)
        return

    attachment = _to_attachment(part, _decoded_payload(part))
    is_inline_image = content_type.startswith("image/") and (
        disposition == "inline" or attachment.content_id is not None
    )
    (parts.inline_images if is_inline_image else parts.attachments).append(attachment)


def _decode_text(part: MIMEPart, content_type: str, issues: list[Signal]) -> str:
    charset = part.get_content_charset()
    try:
        text = part.get_content()
    except (LookupError, UnicodeError) as exc:  # unknown charset name, e.g. "x-made-up"
        issues.append(
            Signal(
                name="body_decode_error",
                severity="medium",
                evidence=f"{content_type} charset={charset!r}: {type(exc).__name__}",
            )
        )
        return _payload_as_text(part)

    # The stdlib replaces undecodable bytes with U+FFFD instead of raising: charset was wrong.
    if "�" in text:
        issues.append(
            Signal(
                name="body_decode_error",
                severity="low",
                evidence=f"{content_type} charset={charset!r}: bytes did not match the charset",
            )
        )
    return text


def _decoded_payload(part: MIMEPart) -> bytes:
    """Body bytes with base64 / quoted-printable undone."""
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def _payload_as_text(part: MIMEPart) -> str:
    return _decoded_payload(part).decode("utf-8", errors="replace")


def _to_attachment(part: MIMEPart, data: bytes) -> Attachment:
    content_id = part.get("Content-ID")
    return Attachment(
        filename=part.get_filename(),
        content_type=part.get_content_type(),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        content_id=str(content_id).strip("<> ") if content_id else None,
        data=data,
    )


def _extract_urls(text_body: str | None, html_body: str | None) -> list[str]:
    """Find http(s) URLs in both bodies. Deeper link analysis (href vs text) is M4's job."""
    haystack = "\n".join([text_body or "", html.unescape(html_body or "")])
    urls: list[str] = []
    for match in _URL_RE.finditer(haystack):
        url = match.group().rstrip(_URL_TRAILING_PUNCTUATION)
        if url not in urls:
            urls.append(url)
    return urls


def _first_header(headers: list[Header], name: str) -> str | None:
    wanted = name.lower()
    return next((h.value for h in headers if h.name.lower() == wanted), None)


def _defect_signal(name: str, where: str, defect: Exception) -> Signal:
    evidence = f"{where}: {type(defect).__name__}"
    if str(defect):
        evidence += f": {defect}"
    return Signal(name=name, severity="low", evidence=evidence[:MAX_EVIDENCE_CHARS])

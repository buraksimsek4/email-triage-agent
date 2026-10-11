"""Pydantic models shared across modules: the single source of truth for data shapes."""

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]


class Signal(BaseModel):
    """One piece of evidence produced by deterministic code (parser or analyzer)."""

    name: str
    severity: Severity
    evidence: str


class Header(BaseModel):
    """One header line. Kept as a list, not a dict, because names repeat (e.g. Received)."""

    name: str
    value: str


class Attachment(BaseModel):
    """A non-body MIME part, kept only as bytes. It is never written to disk or opened."""

    filename: str | None
    content_type: str
    size: int
    sha256: str
    content_id: str | None = None
    # Raw bytes are needed by later analyzers but must not end up in logs or JSON output.
    data: bytes = Field(default=b"", repr=False, exclude=True)


class ParsedEmail(BaseModel):
    """Structured view of one email. Every source (.eml file, Graph) produces this same model."""

    source: str
    message_id: str | None
    subject: str | None
    headers: list[Header]
    text_body: str | None
    html_body: str | None
    urls: list[str]
    attachments: list[Attachment]
    inline_images: list[Attachment]
    parse_issues: list[Signal]

    def get_header(self, name: str) -> str | None:
        """First value of a header, matched case-insensitively."""
        values = self.get_all_headers(name)
        return values[0] if values else None

    def get_all_headers(self, name: str) -> list[str]:
        """All values of a header in the order they appear in the message."""
        wanted = name.lower()
        return [h.value for h in self.headers if h.name.lower() == wanted]

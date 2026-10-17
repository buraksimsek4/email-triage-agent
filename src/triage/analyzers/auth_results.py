"""Parse the Authentication-Results header (RFC 8601).

Example value, added by OUR receiving server after it checked the message:

    mx1.testmailbox.example; spf=pass smtp.mailfrom=contoso.example;
     dkim=pass header.d=contoso.example; dmarc=pass header.from=contoso.example

The first part names the server that did the checks (the "authserv-id"). Each part after a
";" is one check: `method=result`, followed by `ptype.property=value` details.
"""

import re

from pydantic import BaseModel

_COMMENT_RE = re.compile(r"\([^()]*\)")  # RFC 8601 allows (comments) anywhere
_METHOD_RE = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*([a-z0-9_-]+)", re.IGNORECASE)
_PROPERTY_RE = re.compile(r"([a-z0-9_-]+\.[a-z0-9_-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)", re.IGNORECASE)


class MethodResult(BaseModel):
    """One check, e.g. method="dkim", result="pass", properties={"header.d": "contoso.example"}."""

    method: str
    result: str
    properties: dict[str, str]


class AuthResults(BaseModel):
    authserv_id: str
    results: list[MethodResult]

    def first(self, method: str) -> MethodResult | None:
        return next((r for r in self.results if r.method == method), None)

    def all(self, method: str) -> list[MethodResult]:
        return [r for r in self.results if r.method == method]


def parse_authentication_results(value: str) -> AuthResults:
    """Parse one Authentication-Results value. Unknown or broken parts are skipped."""
    # Comments are removed twice so one level of nesting, "(a (b) c)", is also removed.
    cleaned = _COMMENT_RE.sub(" ", _COMMENT_RE.sub(" ", value))
    authserv_part, *method_parts = cleaned.split(";")
    # The authserv-id may be followed by a version number: "mx.example 1; spf=pass".
    authserv_tokens = authserv_part.split()
    authserv_id = authserv_tokens[0].lower() if authserv_tokens else ""

    results = []
    for part in method_parts:
        match = _METHOD_RE.match(part)
        if not match:
            continue  # e.g. the literal "none" meaning "no checks were done"
        properties = {
            name.lower(): raw.strip('"').lower()
            for name, raw in _PROPERTY_RE.findall(part[match.end() :])
        }
        results.append(
            MethodResult(
                method=match.group(1).lower(),
                result=match.group(2).lower(),
                properties=properties,
            )
        )
    return AuthResults(authserv_id=authserv_id, results=results)

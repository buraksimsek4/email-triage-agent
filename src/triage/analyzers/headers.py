"""Header analyzer: deterministic, explainable signals about who really sent an email.

No LLM and no network. Input is a ParsedEmail, output is a list of Signals. Every signal quotes
the header data that triggered it in `evidence`, so an analyst can check the reasoning.
"""

import re
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

from pydantic import BaseModel

from triage.analyzers.auth_results import AuthResults, parse_authentication_results
from triage.analyzers.domains import (
    address_domain,
    display_name,
    is_lookalike,
    org_domain,
    same_org,
    unicode_form,
)
from triage.schemas import ParsedEmail, Severity, Signal

MAX_EVIDENCE_CHARS = 200


class Brand(BaseModel):
    """A name worth protecting, and the only domains allowed to send mail as that name."""

    name: str
    keywords: list[str]  # lowercase words that point at the brand in a display name or domain
    domains: list[str]  # organizational domains the brand really uses


class HeaderConfig(BaseModel):
    # Only Authentication-Results added by these servers are trusted. Anyone can write an
    # Authentication-Results header into a message; only our own receiving server's is real.
    trusted_authserv_ids: list[str]
    protected_brands: list[Brand]
    freemail_domains: list[str]
    executive_titles: list[str]


# The test mailbox's own server and the brands this simulated company cares about: big
# platforms that are often impersonated, plus the fictional vendors from the dataset scenario.
DEFAULT_CONFIG = HeaderConfig(
    trusted_authserv_ids=["mx1.testmailbox.example"],
    protected_brands=[
        Brand(
            name="Microsoft",
            keywords=["microsoft", "m365", "office365", "outlook", "sharepoint", "onedrive"],
            domains=[
                "microsoft.com",
                "office.com",
                "outlook.com",
                "sharepoint.com",
                "onmicrosoft.com",
                "microsoftonline.com",
            ],
        ),
        Brand(name="DocuSign", keywords=["docusign"], domains=["docusign.com", "docusign.net"]),
        Brand(name="PayPal", keywords=["paypal"], domains=["paypal.com"]),
        Brand(name="Contoso", keywords=["contoso"], domains=["contoso.example"]),
        Brand(name="Fabrikam", keywords=["fabrikam"], domains=["fabrikam.example"]),
        Brand(name="Northwind", keywords=["northwind"], domains=["northwind-traders.example"]),
        Brand(name="Our company", keywords=[], domains=["testmailbox.example"]),
    ],
    freemail_domains=[
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "freemail-box.example",
    ],
    executive_titles=["ceo", "cfo", "coo", "cto", "president", "chairman", "director"],
)

# What each SPF/DKIM/DMARC result means for risk. Anything not listed (temperror, permerror,
# policy, ...) is "low": the check could not give an answer.
_AUTH_SEVERITY: dict[str, dict[str, Severity]] = {
    "spf": {"pass": "info", "fail": "medium", "softfail": "low", "neutral": "low", "none": "low"},
    "dkim": {"pass": "info", "fail": "medium", "none": "low", "neutral": "low"},
    "dmarc": {"pass": "info", "fail": "high", "none": "low"},
}

# Allowed clock difference between servers before we call timestamps inconsistent.
_CLOCK_SKEW = timedelta(minutes=15)
_OLD_MESSAGE = timedelta(days=3)

_SEVERITY_POINTS: dict[Severity, int] = {"info": 0, "low": 5, "medium": 15, "high": 30}


def analyze_headers(email: ParsedEmail, config: HeaderConfig = DEFAULT_CONFIG) -> list[Signal]:
    """Run every header check and return all signals, most important checks first."""
    from_domain = address_domain(email.get_header("From"))
    signals = _check_authentication(email, from_domain, config)
    signals += _check_address_mismatch(email, from_domain)
    signals += _check_display_name(email, from_domain, config)
    signals += _check_domains(email, config)
    signals += _check_timestamps(email)
    return signals


def header_risk_score(signals: list[Signal]) -> int:
    """0-100. Each signal adds points by severity (info 0, low 5, medium 15, high 30)."""
    return min(100, sum(_SEVERITY_POINTS[s.severity] for s in signals))


# --- SPF / DKIM / DMARC -------------------------------------------------------------------


def _check_authentication(
    email: ParsedEmail, from_domain: str | None, config: HeaderConfig
) -> list[Signal]:
    signals = []
    trusted: AuthResults | None = None
    for value in email.get_all_headers("Authentication-Results"):
        parsed = parse_authentication_results(value)
        if parsed.authserv_id not in config.trusted_authserv_ids:
            signals.append(
                _signal(
                    "auth_results_untrusted",
                    "low",
                    f"ignored Authentication-Results from '{parsed.authserv_id}': {value}",
                )
            )
        elif trusted is None:
            # Our server adds its header on top, so the first trusted one is the real one.
            trusted = parsed

    if trusted is None:
        signals.append(
            _signal(
                "auth_results_missing",
                "medium",
                "no Authentication-Results from a trusted server "
                f"({', '.join(config.trusted_authserv_ids)})",
            )
        )
        return signals

    arc = trusted.first("arc")
    for method in ("spf", "dkim", "dmarc"):
        result = trusted.first(method)
        if result is None:
            signals.append(_signal(f"{method}_missing", "low", f"no {method} result reported"))
            continue
        severity = _AUTH_SEVERITY[method].get(result.result, "low")
        evidence = _describe(method, result.result, result.properties)
        # Mailing lists and forwarders change messages, which breaks DKIM and DMARC.
        # ARC is a record from the forwarder saying "it passed when it reached me".
        if method == "dmarc" and result.result == "fail" and arc and arc.result == "pass":
            severity = "medium"
            evidence += "; arc=pass, so a mailing list or forwarder may have changed the message"
        signals.append(_signal(f"{method}_{result.result}", severity, evidence))

    if from_domain:
        signals += _check_alignment(trusted, from_domain)
    return signals


def _check_alignment(auth: AuthResults, from_domain: str) -> list[Signal]:
    """A pass only protects the From address if it is for the From domain ("aligned")."""
    signals = []
    spf = auth.first("spf")
    if spf and spf.result == "pass":
        mailfrom = spf.properties.get("smtp.mailfrom", "").rsplit("@", 1)[-1]
        if mailfrom and not same_org(mailfrom, from_domain):
            signals.append(
                _signal(
                    "spf_not_aligned",
                    "low",
                    f"spf passed for '{mailfrom}' but From domain is '{from_domain}'",
                )
            )
    passing_dkim = [d for d in auth.all("dkim") if d.result == "pass"]
    signing_domains = [d.properties.get("header.d", "") for d in passing_dkim]
    if passing_dkim and not any(same_org(d, from_domain) for d in signing_domains if d):
        signals.append(
            _signal(
                "dkim_not_aligned",
                "low",
                f"dkim passed for '{', '.join(signing_domains)}' but From domain is "
                f"'{from_domain}'",
            )
        )
    return signals


def _describe(method: str, result: str, properties: dict[str, str]) -> str:
    details = " ".join(f"{name}={value}" for name, value in properties.items())
    return f"{method}={result} {details}".strip()


# --- From vs Reply-To vs Return-Path -------------------------------------------------------


def _check_address_mismatch(email: ParsedEmail, from_domain: str | None) -> list[Signal]:
    if not from_domain:
        return [_signal("from_missing", "medium", "no usable address in the From header")]

    signals = []
    reply_to = address_domain(email.get_header("Reply-To"))
    if reply_to and not same_org(reply_to, from_domain):
        # Replies go to someone other than the apparent sender: classic in BEC.
        signals.append(
            _signal(
                "reply_to_mismatch",
                "medium",
                f"From domain '{from_domain}' but Reply-To domain '{reply_to}'",
            )
        )

    return_path = address_domain(email.get_header("Return-Path"))
    if return_path and not same_org(return_path, from_domain):
        # Common for newsletters and mailing lists, so only "low" on its own.
        signals.append(
            _signal(
                "return_path_mismatch",
                "low",
                f"From domain '{from_domain}' but Return-Path domain '{return_path}'",
            )
        )
    return signals


# --- Display name tricks -------------------------------------------------------------------


def _check_display_name(
    email: ParsedEmail, from_domain: str | None, config: HeaderConfig
) -> list[Signal]:
    name = display_name(email.get_header("From"))
    if not name or not from_domain:
        return []

    signals = []
    sender_org = org_domain(from_domain)
    for brand in config.protected_brands:
        mentioned = [k for k in brand.keywords if _contains_word(name, k)]
        if mentioned and sender_org not in brand.domains:
            signals.append(
                _signal(
                    "display_name_brand_mismatch",
                    "high",
                    f"display name '{name}' mentions {brand.name} but the address is at "
                    f"'{from_domain}'",
                )
            )

    if sender_org in config.freemail_domains:
        titles = [t for t in config.executive_titles if _contains_word(name, t)]
        if titles:
            # A "CEO" writing from a free webmail account is a textbook BEC opener.
            signals.append(
                _signal(
                    "executive_name_from_freemail",
                    "high",
                    f"display name '{name}' contains '{titles[0]}' but the address is a free "
                    f"webmail account at '{from_domain}'",
                )
            )
        else:
            signals.append(
                _signal("freemail_sender", "low", f"sender uses free webmail '{from_domain}'")
            )
    return signals


def _contains_word(text: str, word: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


# --- Lookalike, brand-in-domain and IDN domains --------------------------------------------


def _check_domains(email: ParsedEmail, config: HeaderConfig) -> list[Signal]:
    signals = []
    checked: set[str] = set()
    for header in ("From", "Reply-To", "Return-Path"):
        domain = address_domain(email.get_header(header))
        if not domain or domain in checked:
            continue
        checked.add(domain)
        signals += _check_one_domain(header, domain, config)
    return signals


def _check_one_domain(header: str, domain: str, config: HeaderConfig) -> list[Signal]:
    signals = []
    unicode_domain = unicode_form(domain)
    if unicode_domain is not None:
        # "xn--mcrosoft-..." is how DNS stores Unicode names; it can hide look-alike letters
        # from other alphabets, e.g. a Cyrillic "і" instead of a Latin "i".
        signals.append(
            _signal(
                "idn_domain",
                "medium",
                f"{header} domain '{domain}' is internationalized, displayed as '{unicode_domain}'",
            )
        )

    org = org_domain(domain)
    for brand in config.protected_brands:
        if org in brand.domains:
            continue
        lookalike_of = next((d for d in brand.domains if is_lookalike(org, d)), None)
        if lookalike_of:
            signals.append(
                _signal(
                    "lookalike_domain",
                    "high",
                    f"{header} domain '{org}' looks like {brand.name}'s '{lookalike_of}'",
                )
            )
            continue
        label = org.split(".")[0]
        keyword = next((k for k in brand.keywords if k in label), None)
        if keyword:
            signals.append(
                _signal(
                    "brand_in_unrelated_domain",
                    "medium",
                    f"{header} domain '{org}' contains '{keyword}' but is not a "
                    f"{brand.name} domain",
                )
            )
    return signals


# --- Date and Received chain ---------------------------------------------------------------


def _check_timestamps(email: ParsedEmail) -> list[Signal]:
    """Each server adds a Received header on top, so the list runs newest hop -> oldest hop."""
    received = email.get_all_headers("Received")
    if not received:
        return [_signal("no_received_headers", "low", "message has no Received headers")]

    signals = []
    hop_times = [_received_time(value) for value in received]
    for newer, older in zip(hop_times, hop_times[1:], strict=False):
        if newer and older and older - newer > _CLOCK_SKEW:
            signals.append(
                _signal(
                    "received_time_inconsistent",
                    "low",
                    f"an earlier hop is stamped {older.isoformat()}, after the later hop at "
                    f"{newer.isoformat()}",
                )
            )
            break

    delivered = hop_times[0]
    date_value = email.get_header("Date")
    sent = _parse_date(date_value)
    if date_value is None:
        signals.append(_signal("date_missing", "low", "message has no Date header"))
    elif sent is None:
        signals.append(_signal("date_unparseable", "low", f"Date: {date_value}"))
    elif delivered and sent - delivered > _CLOCK_SKEW:
        # A Date in the future keeps a message pinned to the top of a date-sorted inbox.
        signals.append(
            _signal(
                "date_after_delivery",
                "medium",
                f"Date {sent.isoformat()} is after our server received it at "
                f"{delivered.isoformat()}",
            )
        )
    elif delivered and delivered - sent > _OLD_MESSAGE:
        signals.append(
            _signal(
                "date_long_before_delivery",
                "low",
                f"Date {sent.isoformat()} but delivered {delivered.isoformat()}",
            )
        )
    return signals


def _received_time(value: str) -> datetime | None:
    # The timestamp is everything after the last ";": "from a by b with ESMTPS; <date>".
    if ";" not in value:
        return None
    return _parse_date(value.rsplit(";", 1)[1])


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return None
    # "-0000" means "timezone unknown" and parses as naive; treat it as UTC so we can compare.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _signal(name: str, severity: Severity, evidence: str) -> Signal:
    return Signal(name=name, severity=severity, evidence=evidence[:MAX_EVIDENCE_CHARS])


if __name__ == "__main__":
    # Try it: python -m triage.analyzers.headers eval/dataset/emails/phish_002.eml
    import sys
    from pathlib import Path

    from triage.parsing import parse_eml

    path = Path(sys.argv[1])
    found = analyze_headers(parse_eml(path.read_bytes(), source=str(path)))
    for item in found:
        print(f"{item.severity:<7} {item.name:<30} {item.evidence}")
    print(f"header risk score: {header_risk_score(found)}/100")

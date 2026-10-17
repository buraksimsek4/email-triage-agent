from pathlib import Path

import pytest

from triage.analyzers.headers import analyze_headers, header_risk_score
from triage.parsing import parse_eml
from triage.schemas import Signal

DATASET = Path(__file__).parent.parent / "eval" / "dataset" / "emails"


def by_name(signals):
    return {s.name: s for s in signals}


def test_clean_email_has_only_info_signals(parse_fixture):
    signals = analyze_headers(parse_fixture("headers_clean.eml"))

    assert {s.name for s in signals} == {"spf_pass", "dkim_pass", "dmarc_pass"}
    assert header_risk_score(signals) == 0


def test_spoofed_email(parse_fixture):
    signals = by_name(analyze_headers(parse_fixture("headers_spoofed.eml")))

    assert signals["dmarc_fail"].severity == "high"
    assert "header.from=contoso.example" in signals["dmarc_fail"].evidence
    assert signals["spf_fail"].severity == "medium"
    assert signals["dkim_none"].severity == "low"
    assert "freemail-box.example" in signals["reply_to_mismatch"].evidence
    assert "bulk-sender-77.example" in signals["return_path_mismatch"].evidence
    # "Microsoft 365" in the display name, but the address is at contoso.example.
    assert "Microsoft" in signals["display_name_brand_mismatch"].evidence


def test_only_our_own_servers_auth_results_are_trusted(parse_fixture):
    signals = by_name(analyze_headers(parse_fixture("headers_fake_auth.eml")))

    # The sender wrote its own "everything passed" header; our server said dmarc=fail.
    assert "dmarc_fail" in signals
    assert "dmarc_pass" not in signals
    assert "mx.fabrikam.example" in signals["auth_results_untrusted"].evidence


def test_lookalike_and_punycode_domains(parse_fixture):
    signals = by_name(analyze_headers(parse_fixture("headers_lookalike.eml")))

    # SPF/DKIM/DMARC all pass: the attacker owns the lookalike domain, so auth cannot help.
    assert signals["dmarc_pass"].severity == "info"
    assert signals["lookalike_domain"].severity == "high"
    assert "northwind-traders.example" in signals["lookalike_domain"].evidence
    assert "mіcrosoft.example" in signals["idn_domain"].evidence
    assert "display_name_brand_mismatch" in signals


def test_executive_title_from_freemail(parse_fixture):
    signals = by_name(analyze_headers(parse_fixture("headers_bec_freemail.eml")))

    assert signals["executive_name_from_freemail"].severity == "high"
    assert "freemail_sender" not in signals  # the stronger signal replaces the weak one


def test_mailing_list_dmarc_fail_is_softened_by_arc(parse_fixture):
    signals = by_name(analyze_headers(parse_fixture("headers_mailing_list.eml")))

    assert signals["dmarc_fail"].severity == "medium"
    assert "arc=pass" in signals["dmarc_fail"].evidence
    assert "lists.example" in signals["spf_not_aligned"].evidence


def test_timestamp_checks(parse_fixture):
    signals = by_name(analyze_headers(parse_fixture("headers_bad_times.eml")))

    assert signals["date_after_delivery"].severity == "medium"
    assert "received_time_inconsistent" in signals
    assert {"spf_none", "dkim_none", "dmarc_none"} <= signals.keys()


def test_missing_headers(parse_fixture):
    signals = by_name(analyze_headers(parse_fixture("headers_no_auth.eml")))

    assert signals["auth_results_missing"].severity == "medium"
    assert "no_received_headers" in signals


def test_from_without_address(parse_fixture):
    email = parse_fixture("headers_no_auth.eml")
    email.headers = [h for h in email.headers if h.name != "From"]

    assert "from_missing" in by_name(analyze_headers(email))


@pytest.mark.parametrize(
    ("severities", "expected"),
    [([], 0), (["info", "info"], 0), (["low", "medium", "high"], 50), (["high"] * 4, 100)],
)
def test_risk_score(severities, expected):
    signals = [Signal(name="x", severity=s, evidence="") for s in severities]

    assert header_risk_score(signals) == expected


def test_every_dataset_email_can_be_analyzed():
    for path in sorted(DATASET.glob("*.eml")):
        signals = analyze_headers(parse_eml(path.read_bytes(), source=str(path)))
        assert signals, path.name
        assert all(len(s.evidence) <= 200 for s in signals)

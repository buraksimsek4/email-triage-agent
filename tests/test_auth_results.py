from triage.analyzers.auth_results import parse_authentication_results


def test_parses_methods_results_and_properties():
    value = (
        "mx1.testmailbox.example; spf=pass smtp.mailfrom=contoso.example;"
        " dkim=pass header.d=contoso.example; dmarc=pass header.from=contoso.example"
    )

    auth = parse_authentication_results(value)

    assert auth.authserv_id == "mx1.testmailbox.example"
    assert [(r.method, r.result) for r in auth.results] == [
        ("spf", "pass"),
        ("dkim", "pass"),
        ("dmarc", "pass"),
    ]
    assert auth.first("dkim").properties == {"header.d": "contoso.example"}


def test_comments_version_and_case_are_handled():
    value = 'MX.Example 1; DMARC=Fail (p=reject dis=none) header.from="Contoso.Example"'

    auth = parse_authentication_results(value)

    assert auth.authserv_id == "mx.example"
    dmarc = auth.first("dmarc")
    assert dmarc.result == "fail"
    assert dmarc.properties == {"header.from": "contoso.example"}


def test_multiple_dkim_signatures_are_all_kept():
    value = "mx.example; dkim=fail header.d=a.example; dkim=pass header.d=b.example"

    auth = parse_authentication_results(value)

    assert [d.result for d in auth.all("dkim")] == ["fail", "pass"]


def test_none_and_garbage_parts_are_skipped():
    assert parse_authentication_results("mx.example; none").results == []
    assert parse_authentication_results(";;; ===").authserv_id == ""

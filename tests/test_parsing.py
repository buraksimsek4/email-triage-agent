import hashlib

import triage.parsing
from triage.parsing import MAX_MIME_DEPTH, parse_eml


def issue_names(email):
    return [issue.name for issue in email.parse_issues]


def test_plain_text_headers_and_body(parse_fixture):
    email = parse_fixture("plain_text.eml")

    assert email.message_id == "<plain-001@corp.example>"
    assert email.subject == "Printer on floor 3 is back online"
    assert email.get_header("reply-to") == "helpdesk@corp.example"
    # Repeated headers are all kept, in order, and folded lines are joined.
    received = email.get_all_headers("Received")
    assert len(received) == 2
    assert received[0].startswith("from mail.corp.example ([192.0.2.10])")
    assert "\n" not in received[0]
    assert "The floor 3 printer is fixed." in email.text_body
    assert email.html_body is None
    assert email.parse_issues == []


def test_url_trailing_punctuation_is_stripped(parse_fixture):
    email = parse_fixture("plain_text.eml")

    assert email.urls == ["https://status.corp.example/printers"]


def test_html_only_with_quoted_printable_and_encoded_subject(parse_fixture):
    email = parse_fixture("html_only.eml")

    assert email.subject == "Your points – October"  # RFC 2047 word decoded
    assert email.text_body is None
    assert "1,200 points" in email.html_body  # quoted-printable =2C decoded
    assert email.urls == ["https://rewards.fabrikam.example/redeem?a=1&b=2"]


def test_multipart_alternative_gives_both_bodies(parse_fixture):
    email = parse_fixture("alternative.eml")

    assert "We detected a new sign-in." in email.text_body  # base64 decoded
    assert email.html_body.startswith("<p>We detected a new sign-in.</p>")
    # The same link in both bodies is listed once.
    assert email.urls == ["https://account.contoso.example/activity"]


def test_attachments_are_bytes_with_sha256(parse_fixture):
    email = parse_fixture("attachments.eml")

    assert email.text_body == "Invoice attached.\n"
    assert [a.filename for a in email.attachments] == ["invoice.pdf", "notes.txt", "photo.png"]
    pdf = email.attachments[0]
    assert pdf.content_type == "application/pdf"
    assert pdf.data.startswith(b"%PDF-1.4")
    assert pdf.size == len(pdf.data)
    assert pdf.sha256 == hashlib.sha256(pdf.data).hexdigest()


def test_inline_disposition_file_is_an_attachment_not_body(parse_fixture):
    email = parse_fixture("attachments.eml")

    assert "inline-disposition file" not in email.text_body
    assert email.attachments[1].content_type == "text/plain"


def test_attached_image_is_not_an_inline_image(parse_fixture):
    email = parse_fixture("attachments.eml")

    assert email.inline_images == []


def test_attachment_bytes_are_left_out_of_json(parse_fixture):
    email = parse_fixture("attachments.eml")

    dumped = email.model_dump()
    assert "data" not in dumped["attachments"][0]
    assert "data=" not in repr(email.attachments[0])


def test_nested_multipart(parse_fixture):
    email = parse_fixture("nested.eml")

    assert email.text_body == "See the forwarded report below.\n"
    assert 'src="cid:logo123"' in email.html_body
    assert len(email.inline_images) == 1
    assert email.inline_images[0].content_id == "logo123"
    assert email.parse_issues == []


def test_forwarded_email_is_kept_as_attachment(parse_fixture):
    email = parse_fixture("nested.eml")

    assert len(email.attachments) == 1
    forwarded = email.attachments[0]
    assert forwarded.content_type == "message/rfc822"
    assert b"Inner body that must not be merged" in forwarded.data
    assert "Inner body" not in email.text_body


def test_bad_charsets_produce_signals_not_crashes(parse_fixture):
    email = parse_fixture("bad_charset.eml")

    assert "unknown charset body" in email.text_body
    assert "caf�" in email.text_body
    unknown, mismatched = email.parse_issues
    assert (unknown.name, unknown.severity) == ("body_decode_error", "medium")
    assert "x-made-up" in unknown.evidence
    assert (mismatched.name, mismatched.severity) == ("body_decode_error", "low")


def test_multipart_without_boundary_keeps_text(parse_fixture):
    email = parse_fixture("broken_mime.eml")

    assert "cannot be split" in email.text_body
    assert email.attachments == []
    assert "mime_defect" in issue_names(email)


def test_garbage_input_does_not_crash(parse_fixture):
    email = parse_fixture("garbage.eml")

    assert email.headers == []
    assert email.message_id is None
    assert "no_headers" in issue_names(email)


def test_empty_input_does_not_crash():
    email = parse_eml(b"", source="empty")

    assert "no_headers" in issue_names(email)


def test_too_deep_mime_tree_is_cut_off():
    depth = MAX_MIME_DEPTH + 5
    lines = ["From: a@deep.example", "MIME-Version: 1.0"]
    for level in range(depth):
        lines += [f'Content-Type: multipart/mixed; boundary="b{level}"', "", f"--b{level}"]
    lines += ["Content-Type: text/plain", "", "deepest text", ""]
    for level in reversed(range(depth)):
        lines += [f"--b{level}--", ""]
    raw = "\r\n".join(lines).encode()

    email = parse_eml(raw, source="deep")

    assert "mime_depth_exceeded" in issue_names(email)
    assert email.text_body is None


def test_unexpected_parser_error_becomes_parse_failed_signal(monkeypatch):
    def explode(raw, source):
        raise RuntimeError("boom")

    monkeypatch.setattr(triage.parsing, "_parse", explode)

    email = parse_eml(b"From: a@b.example\r\n\r\nhi", source="x.eml")

    assert email.source == "x.eml"
    assert [(i.name, i.severity) for i in email.parse_issues] == [("parse_failed", "high")]
    assert "RuntimeError: boom" in email.parse_issues[0].evidence

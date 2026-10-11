from pathlib import Path

import pytest

from triage.sources import EmailSource, EmlFileSource

FIXTURES = Path(__file__).parent / "fixtures"
DATASET = Path(__file__).parent.parent / "eval" / "dataset" / "emails"


def test_eml_file_source_is_an_email_source():
    assert isinstance(EmlFileSource(FIXTURES), EmailSource)


def test_single_file():
    emails = list(EmlFileSource(FIXTURES / "plain_text.eml").messages())

    assert len(emails) == 1
    assert emails[0].source.endswith("plain_text.eml")


def test_directory_yields_every_eml_sorted_by_name():
    emails = list(EmlFileSource(FIXTURES).messages())

    names = [Path(e.source).name for e in emails]
    assert names == sorted(p.name for p in FIXTURES.glob("*.eml"))


def test_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        list(EmlFileSource(FIXTURES / "does-not-exist").messages())


def test_every_dataset_email_parses_cleanly():
    emails = list(EmlFileSource(DATASET).messages())

    assert len(emails) == len(list(DATASET.glob("*.eml")))
    for email in emails:
        assert email.parse_issues == [], email.source
        assert email.message_id is not None, email.source
        assert email.text_body or email.html_body, email.source

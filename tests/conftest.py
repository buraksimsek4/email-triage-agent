from pathlib import Path

import pytest

from triage.parsing import parse_eml
from triage.schemas import ParsedEmail

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def parse_fixture():
    def _parse(name: str) -> ParsedEmail:
        path = FIXTURES / name
        return parse_eml(path.read_bytes(), source=str(path))

    return _parse

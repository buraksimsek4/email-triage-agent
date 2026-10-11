"""Read emails from .eml files on disk. Used offline for tests and eval."""

from collections.abc import Iterator
from pathlib import Path

from triage.parsing import parse_eml
from triage.schemas import ParsedEmail
from triage.sources.base import EmailSource


class EmlFileSource(EmailSource):
    """A single .eml file, or every .eml file in a directory (sorted by name, not recursive)."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def messages(self) -> Iterator[ParsedEmail]:
        for file in self._files():
            yield parse_eml(file.read_bytes(), source=str(file))

    def _files(self) -> list[Path]:
        if self.path.is_dir():
            return sorted(self.path.glob("*.eml"))
        if self.path.is_file():
            return [self.path]
        raise FileNotFoundError(f"No .eml file or directory at {self.path}")

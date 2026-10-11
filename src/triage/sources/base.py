"""The interface every email source implements."""

from abc import ABC, abstractmethod
from collections.abc import Iterator

from triage.schemas import ParsedEmail


class EmailSource(ABC):
    """Somewhere emails come from: .eml files now, a live mailbox (GraphSource) later.

    Analyzers only see ParsedEmail, so they never need to know which source was used.
    """

    @abstractmethod
    def messages(self) -> Iterator[ParsedEmail]:
        """Yield every available message, parsed."""

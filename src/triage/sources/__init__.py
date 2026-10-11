"""Email sources. Every source yields the same ParsedEmail model."""

from triage.sources.base import EmailSource
from triage.sources.eml_file import EmlFileSource

__all__ = ["EmailSource", "EmlFileSource"]

from abc import ABC, abstractmethod
from collections.abc import Generator
from pathlib import Path

from analyzer.models import LogEntry


class BaseParser(ABC):
    """
    Read a log file as a lazy stream of typed LogEntry objects.
    Concrete subclasses open the file line-by-line so the whole
    file is never held in memory at once.
    """

    @abstractmethod
    def parse(self, path: Path) -> Generator[LogEntry, None, None]:
        ...

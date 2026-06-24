"""
Common interface every format parser (JSON, XML, ...) must implement.
"""
from abc import ABC, abstractmethod
from typing import List
from core.schema import Field


class BaseParser(ABC):
    @abstractmethod
    def load(self, raw_text: str):
        """Parse raw_text into an in-memory document object (dict, ElementTree, ...)."""
        raise NotImplementedError

    @abstractmethod
    def extract_fields(self, doc) -> List[Field]:
        """Walk the in-memory document and return all leaf string Fields, with setters."""
        raise NotImplementedError

    @abstractmethod
    def dump(self, doc) -> str:
        """Serialize the in-memory document back to text."""
        raise NotImplementedError

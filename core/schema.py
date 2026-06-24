"""
Shared data structures.
"""
from dataclasses import dataclass, field
from typing import Callable, Any, Optional


@dataclass
class Field:
    """
    A single leaf value found inside a parsed document (JSON or XML),
    plus a setter closure that lets us write a new value back into the
    *original* document object in-place, regardless of source format.
    """
    path: str                     # human-readable location, e.g. "patient.ssn" or "/Patient/SSN"
    value: str                    # the current string value
    set_value: Callable[[str], None]   # call set_value(new_str) to mutate the doc in place


@dataclass
class DetectedEntity:
    entity_type: str              # e.g. "SSN", "EMAIL", "DIAGNOSIS"
    category: str                 # "PII" or "PHI"
    raw_value: str                # the exact substring detected
    field_path: str                # where it was found
    span: Optional[tuple] = None  # (start, end) offset within the field value, if partial match


@dataclass
class MaskRecord:
    token: str
    entity_type: str
    category: str
    field_path: str

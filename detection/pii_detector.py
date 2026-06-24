"""
Thin filter over rules_engine for PII-only results.
"""
from typing import List
from core.schema import DetectedEntity
from detection.rules_engine import detect_in_field


def detect_pii(field_path: str, value: str) -> List[DetectedEntity]:
    return [e for e in detect_in_field(field_path, value) if e.category == "PII"]

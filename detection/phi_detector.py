"""
Thin filter over rules_engine for PHI-only results.
"""
from typing import List
from core.schema import DetectedEntity
from detection.rules_engine import detect_in_field


def detect_phi(field_path: str, value: str) -> List[DetectedEntity]:
    return [e for e in detect_in_field(field_path, value) if e.category == "PHI"]

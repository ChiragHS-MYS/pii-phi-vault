"""
Regex + key-hint based detection. This is the single source of truth that
pii_detector.py and phi_detector.py filter by category.
"""
import re
import yaml
from typing import List
from config.settings import ENTITY_PATTERNS_FILE
from core.schema import DetectedEntity


def _load_config():
    with open(ENTITY_PATTERNS_FILE, "r") as f:
        return yaml.safe_load(f)


_CONFIG = _load_config()
_PATTERNS = [e for e in _CONFIG["entities"] if e.get("pattern")]
_KEY_HINTS = _CONFIG.get("key_hints", {})

_COMPILED = [
    (e["type"], e["category"], re.compile(e["pattern"], re.IGNORECASE))
    for e in _PATTERNS
]


def _last_key(field_path: str) -> str:
    """Pull the trailing key/tag/attribute name out of a field path for key-hint matching."""
    cleaned = field_path.replace("]", "").replace("[", ".")
    cleaned = cleaned.replace("@", "")
    cleaned = cleaned.replace("/", ".")
    cleaned = cleaned.replace(" ", "_").replace("-", "_")
    parts = [p for p in cleaned.split(".") if p]
    return parts[-1].lower() if parts else ""


def detect_in_field(field_path: str, value: str) -> List[DetectedEntity]:
    """
    Detect entities within a single field's value.
    1. Key-hint match: if the field's own key/tag name is a known PII/PHI key,
       treat the WHOLE value as that entity (covers plain names, free-text
       addresses, etc. that no generic regex could safely catch).
    2. Regex pass: scan the value for embedded patterns (covers free-text
       notes fields containing an email, SSN, ICD code, etc.).
    """
    results: List[DetectedEntity] = []

    key = _last_key(field_path)
    if key in _KEY_HINTS and value.strip():
        hint = _KEY_HINTS[key]
        results.append(DetectedEntity(
            entity_type=hint["type"],
            category=hint["category"],
            raw_value=value,
            field_path=field_path,
            span=(0, len(value)),
        ))
        # whole-value match found via key hint; still also scan for embedded
        # values, but avoid duplicate overlapping spans.

    for entity_type, category, pattern in _COMPILED:
        for m in pattern.finditer(value):
            span = m.span()
            # skip if it's already fully covered by a key-hint whole-value match
            if results and results[0].span == (0, len(value)) and span == (0, len(value)):
                continue
            results.append(DetectedEntity(
                entity_type=entity_type,
                category=category,
                raw_value=m.group(),
                field_path=field_path,
                span=span,
            ))

    return results

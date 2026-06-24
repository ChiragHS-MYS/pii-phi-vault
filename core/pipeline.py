"""
Top-level orchestration. Pick the right parser for the input format,
run mask or demask, and serialize the result back to text.
"""
import uuid
from typing import Tuple, Dict, Any
from parsers.json_parser import JSONParser
from parsers.xml_parser import XMLParser
from parsers.text_parser import PlainTextParser
from masking.mask_engine import mask_fields
from demasking.demask_engine import demask_fields

_PARSERS = {
    "json": JSONParser(),
    "xml": XMLParser(),
    "text": PlainTextParser(),
}


def detect_format(raw_text: str) -> str:
    stripped = raw_text.strip()
    if stripped.startswith("<"):
        return "xml"
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    return "text"


def mask_document(raw_text: str, fmt: str = None, document_id: str = None) -> Tuple[str, str, Dict[str, Any]]:
    fmt = fmt or detect_format(raw_text)
    document_id = document_id or str(uuid.uuid4())
    parser = _PARSERS[fmt]

    doc = parser.load(raw_text)
    fields = parser.extract_fields(doc)
    summary = mask_fields(fields, document_id)
    masked_text = parser.dump(doc)

    return masked_text, document_id, summary


def demask_document(masked_text: str, document_id: str, fmt: str = None) -> Tuple[str, Dict[str, Any]]:
    fmt = fmt or detect_format(masked_text)
    parser = _PARSERS[fmt]

    doc = parser.load(masked_text)
    fields = parser.extract_fields(doc)
    summary = demask_fields(fields, document_id)
    original_text = parser.dump(doc)

    return original_text, summary


def detect_only(raw_text: str, fmt: str = None):
    """Run detection without masking — useful for a preview/audit pass."""
    from detection.rules_engine import detect_in_field
    fmt = fmt or detect_format(raw_text)
    parser = _PARSERS[fmt]
    doc = parser.load(raw_text)
    fields = parser.extract_fields(doc)

    found = []
    for field in fields:
        if not field.value:
            continue
        for entity in detect_in_field(field.path, field.value):
            found.append({
                "field_path": entity.field_path,
                "entity_type": entity.entity_type,
                "category": entity.category,
                "value": entity.raw_value,
            })
    return found

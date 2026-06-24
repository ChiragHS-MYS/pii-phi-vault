"""
Orchestrates: parsed Fields -> detect entities -> replace with tokens
-> store real values (encrypted) in the vault keyed by document_id.
"""
from typing import List, Dict, Any
from core.schema import Field, DetectedEntity
from detection.rules_engine import detect_in_field
from masking.tokenizer import generate_token
from masking import vault
from audit.audit_log import log_event


def mask_fields(fields: List[Field], document_id: str) -> Dict[str, Any]:
    """
    Mutates each Field's underlying document in place via field.set_value().
    Returns a summary: counts of PII/PHI entities masked.
    """
    summary = {
        "PII": 0,
        "PHI": 0,
        "tokens": [],
        "masked_entities": []
    }

    for field in fields:
        if not field.value:
            continue

        entities: List[DetectedEntity] = detect_in_field(field.path, field.value)
        if not entities:
            continue

        # If a whole-field match exists (key-hint), it supersedes partial
        # regex matches within the same value to avoid double-masking.
        whole_match = next((e for e in entities if e.span == (0, len(field.value))), None)
        if whole_match:
            entities = [whole_match]

        # Apply replacements right-to-left so earlier spans' offsets stay valid.
        new_value = field.value
        for entity in sorted(entities, key=lambda e: e.span[0], reverse=True):
            token = generate_token(entity.entity_type)
            vault.store(
                document_id=document_id,
                token=token,
                entity_type=entity.entity_type,
                category=entity.category,
                field_path=entity.field_path,
                real_value=entity.raw_value,
            )
            start, end = entity.span
            new_value = new_value[:start] + token + new_value[end:]
            summary[entity.category] += 1
            summary["tokens"].append(token)
            summary["masked_entities"].append({
                "token": token,
                "entity_type": entity.entity_type,
                "category": entity.category,
                "field_path": entity.field_path,
                "raw_value": entity.raw_value
            })

        field.set_value(new_value)

    log_event("MASK", document_id, summary)
    return summary

"""
Reverses masking: scans each Field's value for token patterns, looks each
token up in the vault (scoped to document_id), decrypts, and substitutes
the real value back in.
"""
import re
from typing import List, Dict, Any
from core.schema import Field
from config.settings import TOKEN_REGEX
from masking import vault
from audit.audit_log import log_event

_TOKEN_PATTERN = re.compile(TOKEN_REGEX)


def demask_fields(fields: List[Field], document_id: str) -> Dict[str, Any]:
    summary = {
        "restored": 0,
        "unresolved": [],
        "restored_entities": []
    }

    for field in fields:
        if not field.value or "‹" not in field.value:
            continue

        tokens = _TOKEN_PATTERN.findall(field.value)
        if not tokens:
            continue

        new_value = field.value
        for token in tokens:
            details = vault.resolve_details(document_id, token)
            if details is None:
                summary["unresolved"].append(token)
                continue
            new_value = new_value.replace(token, details["real_value"])
            summary["restored"] += 1
            summary["restored_entities"].append({
                "token": token,
                "entity_type": details["entity_type"],
                "category": details["category"],
                "real_value": details["real_value"]
            })

        field.set_value(new_value)

    log_event("DEMASK", document_id, summary)
    return summary

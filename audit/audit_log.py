"""
Lightweight append-only audit trail. Logs WHAT happened (action, document_id,
counts/token list) but never the real sensitive values themselves.
"""
import json
from datetime import datetime, timezone
from config.settings import AUDIT_LOG_FILE


def log_event(action: str, document_id: str, details: dict) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "document_id": document_id,
        "details": details,
    }
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

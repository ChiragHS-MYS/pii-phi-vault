"""
Vault: the ONLY place the token <-> real-value mapping exists.
Scoped per document_id, so losing/leaking one document's vault entries
doesn't expose every document ever processed.
"""
import sqlite3
from contextlib import closing
from typing import Optional
from config.settings import VAULT_DB_PATH
from masking.encryptor import encrypt, decrypt


def _connect():
    conn = sqlite3.connect(VAULT_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mask_vault (
            document_id TEXT NOT NULL,
            token TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            category TEXT NOT NULL,
            field_path TEXT,
            encrypted_value BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (document_id, token)
        )
    """)
    return conn


def store(document_id: str, token: str, entity_type: str, category: str,
          field_path: str, real_value: str) -> None:
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO mask_vault "
            "(document_id, token, entity_type, category, field_path, encrypted_value) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (document_id, token, entity_type, category, field_path, encrypt(real_value)),
        )
        conn.commit()


def resolve(document_id: str, token: str) -> Optional[str]:
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT encrypted_value FROM mask_vault WHERE document_id = ? AND token = ?",
            (document_id, token),
        ).fetchone()
    if row is None:
        return None
    return decrypt(row[0])


def resolve_details(document_id: str, token: str) -> Optional[dict]:
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT encrypted_value, entity_type, category, field_path FROM mask_vault WHERE document_id = ? AND token = ?",
            (document_id, token),
        ).fetchone()
    if row is None:
        return None
    return {
        "real_value": decrypt(row[0]),
        "entity_type": row[1],
        "category": row[2],
        "field_path": row[3],
    }


def list_entries(document_id: str):
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT token, entity_type, category, field_path FROM mask_vault WHERE document_id = ?",
            (document_id,),
        ).fetchall()
    return [
        {"token": r[0], "entity_type": r[1], "category": r[2], "field_path": r[3]}
        for r in rows
    ]


def purge(document_id: str) -> None:
    """Permanently delete a document's vault entries (irreversible)."""
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM mask_vault WHERE document_id = ?", (document_id,))
        conn.commit()

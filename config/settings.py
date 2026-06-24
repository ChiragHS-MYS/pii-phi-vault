"""
Global configuration: file paths, encryption key bootstrap, logging level.
Keep secrets OUT of source control — KEY_FILE is gitignored.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

CONFIG_DIR = BASE_DIR / "config"
STORAGE_DIR = BASE_DIR / "storage"
AUDIT_DIR = BASE_DIR / "audit"

ENTITY_PATTERNS_FILE = CONFIG_DIR / "entity_patterns.yaml"
VAULT_DB_PATH = STORAGE_DIR / "vault.db"
KEY_FILE = STORAGE_DIR / "vault.key"
AUDIT_LOG_FILE = AUDIT_DIR / "audit.log"

# Token wrapper format: anything matching this is treated as a mask token
# during demasking. Kept deliberately unusual so it can't collide with
# real document content.
TOKEN_PREFIX = "‹"
TOKEN_SUFFIX = "›"
TOKEN_REGEX = r"‹[A-Z_]+_[0-9a-fA-F]{8}›"

LOG_LEVEL = os.environ.get("PII_VAULT_LOG_LEVEL", "INFO")

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

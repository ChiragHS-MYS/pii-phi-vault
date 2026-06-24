"""
Symmetric encryption for everything stored in the vault. Real PII/PHI
values are NEVER stored in plaintext, including at rest in vault.db.
"""
from cryptography.fernet import Fernet
from config.settings import KEY_FILE


def _load_or_create_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> bytes:
    return _fernet.encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes) -> str:
    return _fernet.decrypt(ciphertext).decode("utf-8")


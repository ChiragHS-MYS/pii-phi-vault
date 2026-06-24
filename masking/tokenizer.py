"""
Generates mask tokens. Tokens are deliberately NOT derived from the value
(no hashing of the real value) — they're random, so a token alone tells
you nothing about the original data without access to the encrypted vault.
"""
import uuid
from config.settings import TOKEN_PREFIX, TOKEN_SUFFIX


def generate_token(entity_type: str) -> str:
    suffix = uuid.uuid4().hex[:8]
    return f"{TOKEN_PREFIX}{entity_type.upper()}_{suffix}{TOKEN_SUFFIX}"

# pii-phi-vault

Takes JSON or XML input, detects PII (Personally Identifiable Information)
and PHI (Personal Health Identifiable Information), masks it with reversible
tokens, and can demask it back to the exact original — as long as you have
the `document_id` returned at mask time.

## How reversibility works

Masking does **not** use derivable/hashable tokens. Each detected entity is
replaced with a random token like `‹SSN_a1b2c3d4›`, and the real value is
encrypted (Fernet/AES) and stored in a SQLite vault (`storage/vault.db`),
keyed by `(document_id, token)`. The token itself reveals nothing about the
original value — you can only reverse it by querying the vault with the
correct `document_id`.

```
mask:    "123-45-6789"  --detect-->  SSN  --token-->  ‹SSN_a1b2c3d4›
                                                  |
                                                  v
                                vault[document_id][‹SSN_a1b2c3d4›] = encrypt("123-45-6789")

demask:  ‹SSN_a1b2c3d4›  --lookup(document_id)-->  decrypt(...)  -->  "123-45-6789"
```

## Project structure

```
config/           entity regex patterns + key-name hints, settings
parsers/          JSON / XML -> list of Field(path, value, setter), and back to text
detection/        rules_engine (regex + key hints) -> pii_detector / phi_detector
masking/          tokenizer, encryptor, vault (SQLite), mask_engine
demasking/        demask_engine (token -> vault lookup -> decrypt -> restore)
core/             schema (dataclasses), pipeline (format detection + orchestration)
api/              FastAPI app: /detect /mask /demask /vault
audit/            append-only audit log (actions + counts, never raw values)
storage/          vault.db + vault.key (gitignored, created on first run)
samples/          example fictional JSON/XML inputs
tests/            mask -> demask round-trip tests
```

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run the API

```bash
uvicorn api.main:app --reload --port 8000
```

```bash
# Mask
curl -X POST http://localhost:8000/mask \
  -H "Content-Type: application/json" \
  -d "{\"content\": $(python -c "import json;print(json.dumps(open('samples/sample_input.json').read()))")}"

# -> returns { masked_content, document_id, summary }
# SAVE document_id — you need it to demask later.

# Demask
curl -X POST http://localhost:8000/demask \
  -H "Content-Type: application/json" \
  -d '{"content": "<masked_content from above>", "document_id": "<id from above>"}'
```

## Run tests directly

```bash
python tests/test_mask_demask_roundtrip.py
# or
pytest tests/
```

## Extending detection

Add new patterns/key-hints in `config/entity_patterns.yaml` — no code
changes needed for new regex-detectable entity types. For fuzzy cases
(e.g. names in free text that don't sit under an obvious key), plug in
an NER model (spaCy / Microsoft Presidio) inside `detection/rules_engine.py`
as an additional pass.

## Security notes

- `storage/vault.key` and `storage/vault.db` are gitignored — never commit them.
- Vault entries are scoped per `document_id`; losing one document's data
  doesn't expose others.
- The audit log records actions/counts only, never the sensitive values.
- `DELETE /vault/{document_id}` permanently destroys the mapping — after
  that, masked content for that document can never be demasked again.

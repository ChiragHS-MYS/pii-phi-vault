"""
Verifies mask -> demask round-trips to the exact original content,
for both JSON and XML, using fresh document_ids so tests don't collide.
"""
import json
import uuid
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import pipeline
from masking import vault

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_json_roundtrip():
    raw = (SAMPLES_DIR / "sample_input.json").read_text()
    doc_id = f"test-{uuid.uuid4()}"

    masked_text, doc_id, summary = pipeline.mask_document(raw, fmt="json", document_id=doc_id)

    assert summary["PII"] > 0
    assert summary["PHI"] > 0
    assert "Asha Verma" not in masked_text
    assert "123-45-6789" not in masked_text

    restored_text, demask_summary = pipeline.demask_document(masked_text, doc_id, fmt="json")

    assert json.loads(restored_text) == json.loads(raw)
    assert demask_summary["unresolved"] == []

    vault.purge(doc_id)


def test_xml_roundtrip():
    raw = (SAMPLES_DIR / "sample_input.xml").read_text()
    doc_id = f"test-{uuid.uuid4()}"

    masked_text, doc_id, summary = pipeline.mask_document(raw, fmt="xml", document_id=doc_id)

    assert summary["PII"] > 0
    assert "Rohan Mehta" not in masked_text
    assert "987-65-4321" not in masked_text

    restored_text, demask_summary = pipeline.demask_document(masked_text, doc_id, fmt="xml")

    assert "Rohan Mehta" in restored_text
    assert "987-65-4321" in restored_text
    assert demask_summary["unresolved"] == []

    vault.purge(doc_id)


def test_wrong_document_id_cannot_demask():
    raw = (SAMPLES_DIR / "sample_input.json").read_text()
    doc_id = f"test-{uuid.uuid4()}"
    wrong_id = f"test-{uuid.uuid4()}"

    masked_text, doc_id, _ = pipeline.mask_document(raw, fmt="json", document_id=doc_id)
    _, summary = pipeline.demask_document(masked_text, wrong_id, fmt="json")

    # tokens exist but belong to a different document_id -> unresolved
    assert len(summary["unresolved"]) > 0

    vault.purge(doc_id)


if __name__ == "__main__":
    test_json_roundtrip()
    test_xml_roundtrip()
    test_wrong_document_id_cannot_demask()
    print("All tests passed.")

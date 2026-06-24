import sys
from pathlib import Path
import io
import uuid
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.main import app
from core import pipeline
from masking import vault

client = TestClient(app)


def make_mock_pdf(text: str) -> bytes:
    """Helper to generate a basic valid PDF containing custom text."""
    # BT /F1 12 Tf 50 700 Td (TEXT) Tj ET
    # Note: parentheses in text must be escaped to prevent PDF syntax issues.
    escaped_text = text.replace("(", "\\(").replace(")", "\\)")
    stream_content = f"BT\n/F1 12 Tf\n50 700 Td\n({escaped_text}) Tj\nET"
    stream_len = len(stream_content.encode("utf-8"))

    pdf_template = (
        f"%PDF-1.1\n"
        f"1 0 obj\n"
        f"<< /Type /Catalog /Pages 2 0 R >>\n"
        f"endobj\n"
        f"2 0 obj\n"
        f"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        f"endobj\n"
        f"3 0 obj\n"
        f"<< /Type /Page\n"
        f"   /Parent 2 0 R\n"
        f"   /Resources << /Font << /F1 4 0 R >> >>\n"
        f"   /MediaBox [0 0 612 792]\n"
        f"   /Contents 5 0 R\n"
        f">>\n"
        f"endobj\n"
        f"4 0 obj\n"
        f"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
        f"endobj\n"
        f"5 0 obj\n"
        f"<< /Length {stream_len} >>\n"
        f"stream\n"
        f"{stream_content}\n"
        f"endstream\n"
        f"endobj\n"
        f"xref\n"
        f"0 6\n"
        f"0000000000 65535 f\n"
        f"0000000009 00000 n\n"
        f"0000000058 00000 n\n"
        f"0000000115 00000 n\n"
        f"0000000244 00000 n\n"
        f"0000000311 00000 n\n"
        f"trailer\n"
        f"<< /Size 6 /Root 1 0 R >>\n"
        f"startxref\n"
        f"406\n"
        f"%%EOF\n"
    )
    return pdf_template.encode("utf-8")


def test_pdf_extraction_endpoint():
    # 1. Generate PDF content
    test_text = "Patient: Asha Verma, SSN: 123-45-6789, Email: asha.verma@example.com"
    pdf_bytes = make_mock_pdf(test_text)

    # 2. Upload file to FastAPI endpoint
    response = client.post(
        "/api/extract-pdf",
        files={"file": ("test.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
    )

    assert response.status_code == 200
    data = response.json()
    assert "content" in data
    # pypdf returns extracted text (might strip outer spaces/newlines)
    extracted_text = data["content"].strip()
    assert "Asha Verma" in extracted_text
    assert "123-45-6789" in extracted_text
    assert "asha.verma@example.com" in extracted_text


def test_pdf_pipeline_integration():
    # Test end-to-end flow: Extract PDF -> Mask -> Demask
    test_text = "Patient SSN is 987-65-4321, contact him at test@example.com."
    pdf_bytes = make_mock_pdf(test_text)

    # Step 1: Extract PDF
    response = client.post(
        "/api/extract-pdf",
        files={"file": ("test.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
    )
    assert response.status_code == 200
    extracted_text = response.json()["content"]

    # Step 2: Mask Document (treated as "text" format)
    doc_id = f"test-pdf-{uuid.uuid4()}"
    masked_text, doc_id, summary = pipeline.mask_document(
        extracted_text, fmt="text", document_id=doc_id
    )

    assert summary["PII"] == 2  # SSN and EMAIL should be masked
    assert len(summary["masked_entities"]) == 2
    assert summary["masked_entities"][0]["raw_value"].rstrip(".") in ("987-65-4321", "test@example.com")
    assert "987-65-4321" not in masked_text
    assert "test@example.com" not in masked_text
    assert "‹SSN_" in masked_text
    assert "‹EMAIL_" in masked_text

    # Step 3: Demask Document
    restored_text, demask_summary = pipeline.demask_document(
        masked_text, doc_id, fmt="text"
    )

    assert demask_summary["unresolved"] == []
    assert len(demask_summary["restored_entities"]) == 2
    assert demask_summary["restored_entities"][0]["real_value"].rstrip(".") in ("987-65-4321", "test@example.com")
    # Stripping space/newlines to match original clean text
    assert "987-65-4321" in restored_text
    assert "test@example.com" in restored_text

    # Cleanup
    vault.purge(doc_id)


def test_invalid_file_rejected():
    response = client.post(
        "/api/extract-pdf",
        files={"file": ("test.txt", io.BytesIO(b"Hello World"), "text/plain")},
    )
    assert response.status_code == 400
    assert "Only PDF files are supported" in response.json()["detail"]


def test_pdf_key_value_masking():
    # PDF with key-value data which should trigger key hint masking
    test_text = (
        "Patient Name: Asha Verma\n"
        "DOB: 1989-04-12\n"
        "Diagnosis: Asthma, unspecified"
    )
    pdf_bytes = make_mock_pdf(test_text)

    # 1. Extract
    response = client.post(
        "/api/extract-pdf",
        files={"file": ("test.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
    )
    assert response.status_code == 200
    extracted_text = response.json()["content"]

    # 2. Mask
    doc_id = f"test-pdf-kv-{uuid.uuid4()}"
    masked_text, doc_id, summary = pipeline.mask_document(
        extracted_text, fmt="text", document_id=doc_id
    )

    # We expect Patient Name (NAME/PHI) to be masked, DOB (DOB/PII) to be masked, and Diagnosis (DIAGNOSIS/PHI) to be masked.
    assert summary["PHI"] >= 2  # Name + Diagnosis
    assert summary["PII"] >= 1  # DOB
    assert len(summary["masked_entities"]) == 3
    assert any(e["entity_type"] == "NAME" for e in summary["masked_entities"])
    assert any(e["entity_type"] == "DIAGNOSIS" for e in summary["masked_entities"])
    assert any(e["entity_type"] == "DOB" for e in summary["masked_entities"])
    assert "Asha Verma" not in masked_text
    assert "1989-04-12" not in masked_text
    assert "Asthma, unspecified" not in masked_text
    assert "‹NAME_" in masked_text
    assert "‹DOB_" in masked_text
    assert "‹DIAGNOSIS_" in masked_text

    # 3. Demask
    restored_text, demask_summary = pipeline.demask_document(
        masked_text, doc_id, fmt="text"
    )
    assert demask_summary["unresolved"] == []
    assert len(demask_summary["restored_entities"]) == 3
    assert any(e["entity_type"] == "NAME" for e in demask_summary["restored_entities"])
    assert "Asha Verma" in restored_text
    assert "1989-04-12" in restored_text
    assert "Asthma, unspecified" in restored_text

    # Cleanup
    vault.purge(doc_id)


def test_aadhaar_masking():
    # Test Aadhaar masking via regex matching
    raw_text = "My Aadhaar Card number is 1234 5678 9012, please save it."
    doc_id = f"test-aadhaar-{uuid.uuid4()}"

    masked_text, doc_id, summary = pipeline.mask_document(raw_text, fmt="text", document_id=doc_id)

    assert summary["PII"] == 1
    assert "1234 5678 9012" not in masked_text
    assert "‹AADHAAR_" in masked_text

    restored_text, demask_summary = pipeline.demask_document(masked_text, doc_id, fmt="text")
    assert "1234 5678 9012" in restored_text
    assert demask_summary["unresolved"] == []

    vault.purge(doc_id)


def test_custom_document_id_integration():
    # Test that passing a custom document ID binds the document correctly
    raw_text = "Patient SSN is 111-22-3333."
    custom_doc_id = f"my-custom-doc-{uuid.uuid4()}"

    # Step 1: Mask with custom document ID via API endpoint
    response = client.post(
        "/mask",
        json={"content": raw_text, "document_id": custom_doc_id}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["document_id"] == custom_doc_id
    masked_text = data["masked_content"]
    assert "111-22-3333" not in masked_text

    # Step 2: Query Vault to verify entries exist under custom_doc_id
    response_vault = client.get(f"/vault/{custom_doc_id}")
    assert response_vault.status_code == 200
    vault_data = response_vault.json()
    assert vault_data["document_id"] == custom_doc_id
    assert len(vault_data["entries"]) == 1

    # Step 3: Demask using the custom document ID
    response_demask = client.post(
        "/demask",
        json={"content": masked_text, "document_id": custom_doc_id}
    )
    assert response_demask.status_code == 200
    demask_data = response_demask.json()
    assert "111-22-3333" in demask_data["original_content"]
    assert demask_data["summary"]["unresolved"] == []

    # Cleanup
    client.delete(f"/vault/{custom_doc_id}")




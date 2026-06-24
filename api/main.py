"""
REST API.

POST /detect   { "content": "...", "format": "json"|"xml" (optional) }
               -> list of detected PII/PHI entities, nothing is altered/stored

POST /mask     { "content": "...", "format": "json"|"xml" (optional) }
               -> { masked_content, document_id, summary }
               document_id MUST be saved by the caller — it's required to demask.

POST /demask   { "content": "<masked content>", "document_id": "...", "format": "..." }
               -> { original_content, summary }

GET  /vault/{document_id}  -> list of (non-sensitive) token metadata for a document
"""
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
import json

from core import pipeline
from masking import vault
from config.settings import AUDIT_LOG_FILE, BASE_DIR

app = FastAPI(title="PII/PHI Vault API", version="1.0.0")

# Enable CORS for flexible developer integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ContentRequest(BaseModel):
    content: str
    format: Optional[str] = None  # "json" | "xml", auto-detected if omitted
    document_id: Optional[str] = None


class DemaskRequest(BaseModel):
    content: str
    document_id: str
    format: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/detect")
def detect(req: ContentRequest):
    try:
        return {"entities": pipeline.detect_only(req.content, req.format)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/mask")
def mask(req: ContentRequest):
    try:
        masked_content, document_id, summary = pipeline.mask_document(
            req.content, req.format, req.document_id
        )
        return {
            "masked_content": masked_content,
            "document_id": document_id,
            "summary": summary,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/demask")
def demask(req: DemaskRequest):
    try:
        original_content, summary = pipeline.demask_document(
            req.content, req.document_id, req.format
        )
        return {"original_content": original_content, "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/vault/{document_id}")
def vault_entries(document_id: str):
    return {"document_id": document_id, "entries": vault.list_entries(document_id)}


@app.delete("/vault/{document_id}")
def vault_purge(document_id: str):
    vault.purge(document_id)
    return {"document_id": document_id, "purged": True}


@app.get("/api/audit")
def get_audit_log():
    try:
        if not AUDIT_LOG_FILE.exists():
            return []
        logs = []
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line))
        # Return in reverse chronological order
        return logs[::-1]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/samples/{fmt}")
def get_sample(fmt: str):
    if fmt not in ("json", "xml"):
        raise HTTPException(status_code=400, detail="Invalid format. Use 'json' or 'xml'.")
    sample_file = BASE_DIR / "samples" / f"sample_input.{fmt}"
    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="Sample file not found.")
    return {"content": sample_file.read_text(encoding="utf-8")}


@app.post("/api/extract-pdf")
def extract_pdf(file: UploadFile = File(...)):
    if not file.filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")
    try:
        from pypdf import PdfReader
        import io
        
        content = file.file.read()
        reader = PdfReader(io.BytesIO(content))
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        
        if not text.strip():
            raise HTTPException(
                status_code=400,
                detail="No text could be extracted from this PDF. It might be scanned or empty."
            )
            
        return {"content": text}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF extraction error: {str(e)}")




# Static UI files mounting
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def read_index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse(
            "<h1>PII/PHI Vault API is running!</h1>"
            "<p>Frontend static files index.html not found yet in api/static/.</p>"
        )
    return FileResponse(str(index_file))


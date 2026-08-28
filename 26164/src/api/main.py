import os
import time
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from ecdat.service import ScanService, ScannerError, AnalysisError

SCANNER_VERSION = "0.1.0"

app = FastAPI(
    title="ECDAT Cryptographic Discovery API",
    version=SCANNER_VERSION,
    description="Scan source repositories for cryptographic assets and assess their post-quantum migration risk.",
)


# ── Request models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_path: str
    language_filters: Optional[List[str]] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Liveness probe — returns 200 when the service is up."""
    return {"status": "ok"}


@app.get("/version")
def version():
    """Return the current scanner version string."""
    return {"version": SCANNER_VERSION}


@app.post("/api/v1/scan")
def scan_endpoint(request: ScanRequest):
    """
    Scan a local file or directory for cryptographic assets.

    - **target_path**: absolute path to the file or directory to scan.
    - **language_filters**: optional list of language names to restrict scanning
      (supported: ``python``, ``java``, ``c``, ``cpp``, ``pem``).
    """
    service = ScanService()
    try:
        return service.run_scan(request.target_path, request.language_filters)
    except ValueError as e:
        return {"error": {"code": "INVALID_INPUT", "message": str(e)}}
    except ScannerError as e:
        return {"error": {"code": "SCANNER_FAILURE", "message": str(e)}}
    except AnalysisError as e:
        return {"error": {"code": "ANALYSIS_FAILURE", "message": str(e)}}
    except Exception as e:
        return {"error": {"code": "INTERNAL_ERROR", "message": f"An unexpected failure occurred: {str(e)}"}}

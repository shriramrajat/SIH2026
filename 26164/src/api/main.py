import os
import time
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ecdat.scanner import Scanner
from ecdat.risk import classify_assets

app = FastAPI(title="ECDAT API")

class ScanRequest(BaseModel):
    target_path: str
    language_filters: Optional[List[str]] = None

@app.post("/api/v1/scan")
def scan_endpoint(request: ScanRequest):
    target_path = request.target_path
    
    if not os.path.exists(target_path):
        return {"error": {"code": "INVALID_INPUT", "message": f"Target path does not exist: {target_path}"}}
    
    start_time = time.time()
    
    try:
        scanner = Scanner()
        target = Path(target_path)
        effective_root = target if target.is_dir() else target.parent
        files = scanner.discover_files(target_path)
        
        if request.language_filters:
            lang_ext_map = {
                "python": {".py"},
                "java": {".java"},
                "c": {".c", ".h"},
                "cpp": {".cpp", ".hpp"},
                "pem": {".pem", ".crt", ".key"}
            }
            valid_exts = set()
            for lf in request.language_filters:
                valid_exts.update(lang_ext_map.get(lf.lower(), set()))
            
            if valid_exts:
                files = [f for f in files if f.suffix.lower() in valid_exts]
                
        total_files = len(files)
        
        assets = []
        for file_path in files:
            assets.extend(scanner.scan_file(file_path, root_dir=effective_root))
            
    except Exception as e:
        return {"error": {"code": "SCANNER_FAILURE", "message": "Scanner encountered an internal failure."}}
        
    try:
        assessments = classify_assets(assets)
    except Exception as e:
        return {"error": {"code": "ANALYSIS_FAILURE", "message": "Analysis encountered an internal failure."}}
        
    findings = []
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    quantum_threat_counts = {"shor": 0, "grover": 0, "none": 0}
    algorithm_distribution = {}
    
    assessments_by_id = {a.asset_id: a for a in assessments}
    
    for asset in assets:
        assessment = assessments_by_id.get(asset.asset_id)
        
        if assessment:
            sev = assessment.severity.value
            qt = assessment.quantum_threat.value
            rec = assessment.pqc_recommendation
        else:
            sev = "medium"
            qt = "none"
            rec = None
            
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        quantum_threat_counts[qt] = quantum_threat_counts.get(qt, 0) + 1
        
        alg = asset.algorithm
        algorithm_distribution[alg] = algorithm_distribution.get(alg, 0) + 1
        
        finding = {
            "finding_id": asset.asset_id,
            "algorithm": asset.algorithm,
            "category": asset.category,
            "file_location": {
                "file_path": str(asset.file_path).replace("\\", "/"),
                "line_number": asset.line_number
            },
            "evidence": {
                "code_snippet": asset.evidence.code_snippet if asset.evidence else asset.code_snippet,
                "detection_mechanism": asset.evidence.detection_mechanism if asset.evidence else "unknown",
                "matched_rule_id": asset.evidence.matched_rule_id if asset.evidence else "unknown"
            },
            "risk": {
                "severity": sev,
                "reason": assessment.reason if assessment else "Unknown algorithm mapped to default risk.",
                "confidence": assessment.confidence if assessment else 0.5,
                "quantum_threat": qt,
                "pqc_recommendation": {
                    "target_algorithm": rec.target_algorithm,
                    "nist_standard": rec.nist_standard,
                    "migration_type": rec.migration_type
                } if rec else None
            }
        }
        findings.append(finding)
        
    duration_ms = int((time.time() - start_time) * 1000)
    
    return {
        "summary": {
            "total_files_scanned": total_files,
            "total_crypto_assets": len(assets),
            "severity_counts": severity_counts,
            "quantum_threat_counts": quantum_threat_counts,
            "algorithm_distribution": algorithm_distribution,
            "quantum_vulnerable_assets": quantum_threat_counts.get("shor", 0) + quantum_threat_counts.get("grover", 0)
        },
        "findings": findings,
        "metadata": {
            "scan_duration_ms": duration_ms,
            "scanner_version": "0.1.0"
        }
    }

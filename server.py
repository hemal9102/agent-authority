"""
Agent Authority Web API & Application Server
Serves the standards-grounded audit engine, badge generator, and static web dashboard.
Reference Implementation for IETF draft-shah-agent-readiness-evaluation-00.
"""

import os
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from engine.scanner import AsyncRFCScanner
from engine.scorer import score_telemetry

app = FastAPI(
    title="Agent Authority API",
    description="Deterministic evaluation of website agent-readiness grounded in IETF RFCs and W3C standards.",
    version="1.0.0"
)

# Enable CORS for embedding badges and API consumers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRequest(BaseModel):
    target: str

# In-memory LRU/dict cache for badge queries
_BADGE_CACHE = {}

@app.post("/api/audit")
async def audit_endpoint(payload: AuditRequest):
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target domain or URL is required.")
    
    scanner = AsyncRFCScanner()
    try:
        telemetry = await scanner.scan_domain(target)
        score_res = score_telemetry(telemetry)
        
        # Cache for badge
        domain_key = telemetry.get("hostname", target).lower()
        _BADGE_CACHE[domain_key] = score_res["overall_score"]

        return {
            "success": True,
            "target": target,
            "telemetry": telemetry,
            "score": score_res
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit scan failed: {str(e)}")

@app.get("/api/badge/{domain}")
async def badge_endpoint(domain: str):
    domain_clean = domain.strip().lower()
    score = _BADGE_CACHE.get(domain_clean)
    
    if score is None:
        try:
            scanner = AsyncRFCScanner(timeout=5.0)
            telemetry = await scanner.scan_domain(domain_clean)
            score_res = score_telemetry(telemetry)
            score = score_res["overall_score"]
            _BADGE_CACHE[domain_clean] = score
        except Exception:
            score = "--"

    if isinstance(score, (int, float)):
        if score >= 80:
            color = "#10b981"  # Emerald green
        elif score >= 50:
            color = "#f59e0b"  # Amber
        else:
            color = "#ef4444"  # Red
        val_str = f"{score}/100"
    else:
        color = "#6b7280"
        val_str = str(score)

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="180" height="28" role="img" aria-label="Agent Authority: {val_str}">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="180" height="28" rx="6" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <rect width="112" height="28" fill="#18181b"/>
    <rect x="112" width="68" height="28" fill="{color}"/>
    <rect width="180" height="28" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="56" y="18" fill="#a1a1aa" font-weight="500">Agent Authority</text>
    <text x="146" y="18" font-weight="700">{val_str}</text>
  </g>
</svg>"""

    return Response(content=svg, media_type="image/svg+xml")

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "engine": "Agent Authority RFC Diagnostic Engine",
        "standard": "IETF draft-shah-agent-readiness-evaluation-00"
    }

# Mount static frontend directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "public")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

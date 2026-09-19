"""
REVENANT — Control Plane REST API (FastAPI)
Exposes endpoints for campaign dispatching, mission monitoring, finding exploration,
and multi-format report generation with Layer 1 Scope Enforcement.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from control_plane.schemas.models import Finding, HostAsset
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError
from orchestrator.blackboard import Blackboard
from orchestrator.engine import Orchestrator
from reporting.generator import ReportGenerator

app = FastAPI(
    title="REVENANT Control Plane API",
    version="2.0.0",
    description="Autonomous Full-Spectrum AI Red Teaming & Security Operations Platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory mission registry (persisted to PostgreSQL in production stack)
campaigns_db: Dict[str, Dict[str, Any]] = {}


class CampaignCreateRequest(BaseModel):
    target: str = Field(..., json_schema_extra={"example": "http://localhost:3000"})
    scope: ScopeManifest
    max_iterations: int = Field(default=25, ge=1, le=100)


class CampaignResponse(BaseModel):
    campaign_id: str
    target: str
    status: str
    created_at: str
    summary: Dict[str, Any]


@app.get("/api/v1/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """System health check endpoint."""
    return {
        "status": "healthy",
        "platform": "REVENANT",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post(
    "/api/v1/campaigns",
    response_model=CampaignResponse,
    status_code=201,
    tags=["Campaigns"],
)
def create_and_start_campaign(request: CampaignCreateRequest):
    """
    Launch an autonomous security campaign.
    Enforces Layer 1 Scope Check on intake before any engine starts.
    """
    # 1. LAYER 1 SCOPE INTAKE GATE
    scope_engine = ScopeEngine(request.scope)
    try:
        scope_engine.validate_or_raise(request.target)
    except ScopeViolationError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "SCOPE_VIOLATION",
                "message": str(exc),
                "target": exc.target,
                "reason": exc.reason,
            },
        )

    campaign_id = str(uuid.uuid4())
    blackboard = Blackboard(campaign_id=campaign_id)
    orchestrator = Orchestrator(blackboard=blackboard)

    # Run the autonomous campaign loop
    summary = orchestrator.start_campaign(
        target=request.target,
        scope=request.scope,
        max_iterations=request.max_iterations,
    )

    created_at = datetime.now(timezone.utc).isoformat()
    record = {
        "campaign_id": campaign_id,
        "target": request.target,
        "status": "COMPLETED",
        "created_at": created_at,
        "summary": summary,
        "blackboard": blackboard,
        "scope": request.scope,
    }
    campaigns_db[campaign_id] = record

    return CampaignResponse(
        campaign_id=campaign_id,
        target=request.target,
        status="COMPLETED",
        created_at=created_at,
        summary=summary,
    )


@app.get("/api/v1/campaigns/{campaign_id}", tags=["Campaigns"])
def get_campaign(campaign_id: str):
    """Get mission summary and status."""
    if campaign_id not in campaigns_db:
        raise HTTPException(status_code=404, detail="Campaign not found")
    record = campaigns_db[campaign_id]
    return {
        "campaign_id": record["campaign_id"],
        "target": record["target"],
        "status": record["status"],
        "created_at": record["created_at"],
        "summary": record["summary"],
    }


@app.get("/api/v1/campaigns/{campaign_id}/findings", tags=["Campaigns"])
def get_campaign_findings(campaign_id: str) -> List[Finding]:
    """Retrieve all findings discovered during a campaign."""
    if campaign_id not in campaigns_db:
        raise HTTPException(status_code=404, detail="Campaign not found")
    bb: Blackboard = campaigns_db[campaign_id]["blackboard"]
    return bb.get_findings()


@app.get("/api/v1/campaigns/{campaign_id}/assets", tags=["Campaigns"])
def get_campaign_assets(campaign_id: str) -> List[HostAsset]:
    """Retrieve all assets discovered during a campaign."""
    if campaign_id not in campaigns_db:
        raise HTTPException(status_code=404, detail="Campaign not found")
    bb: Blackboard = campaigns_db[campaign_id]["blackboard"]
    return bb.get_assets()


@app.get("/api/v1/campaigns/{campaign_id}/report", tags=["Reporting"])
def get_campaign_report(
    campaign_id: str,
    format: str = Query(
        "markdown",
        pattern="^(markdown|html|sarif|json|faraday|dradis)$",
        description="Desired export format",
    ),
):
    """
    Download or view campaign report in Markdown, HTML, SARIF v2.1.0, JSON, Faraday, or Dradis.
    """
    if campaign_id not in campaigns_db:
        raise HTTPException(status_code=404, detail="Campaign not found")

    record = campaigns_db[campaign_id]
    bb: Blackboard = record["blackboard"]

    generator = ReportGenerator(
        campaign_id=campaign_id,
        target=record["target"],
        assets=bb.get_assets(),
        findings=bb.get_findings(),
        metadata={"status": record["status"], "created_at": record["created_at"]},
    )

    if format == "html":
        return HTMLResponse(content=generator.generate_html(), status_code=200)
    elif format == "sarif":
        return JSONResponse(content=generator.generate_sarif(), status_code=200)
    elif format == "json":
        return JSONResponse(content=generator.generate_json(), status_code=200)
    elif format == "faraday":
        return JSONResponse(content=generator.generate_faraday(), status_code=200)
    elif format == "dradis":
        return JSONResponse(content=generator.generate_dradis(), status_code=200)
    else:
        return PlainTextResponse(content=generator.generate_markdown(), status_code=200)


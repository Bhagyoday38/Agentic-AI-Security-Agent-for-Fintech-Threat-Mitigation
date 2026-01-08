# ai-security-agent/app/api/endpoints.py
import logging
import os
import json
import time
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, WebSocket, WebSocketDisconnect, Response, BackgroundTasks
from fastapi.responses import JSONResponse
from collections import defaultdict

from ..config import settings
from ..state import app_state
from ..models import EventData, ReportRequest
from ..services.detection import detect_llm_anomaly, detect_brute_force, detect_dos_ddos, calculate_risk_score
from ..services.reporting import create_pdf_report
from ..utils import log_secure_attack_event
from .websocket import manager

logger = logging.getLogger("Runner." + __name__)
router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(60)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.get("/analytics")
async def get_analytics_endpoint():
    attack_stats = defaultdict(int)
    history = list(app_state.attack_history)
    for attack in history:
        attack_stats[attack.get("attack_type", "Unknown")] += 1
    return {
        "attack_type_counts": dict(attack_stats),
        "total_threat_events": len(history),
        "rate_limited_ip_count": len({ip for ip, exp in app_state.rate_limited_ips.items() if exp > time.time()})
    }


@router.post("/log_event")
async def handle_event(request: Request, event_data: EventData):
    ip = event_data.source_ip or (
        request.client.host if request.client else "127.0.0.1")
    event_data.source_ip = ip

    # 1. Run Static Fallback Detectors (Always Run)
    detections = []
    for d in [detect_dos_ddos, detect_brute_force]:
        res = await d(event_data)
        if res:
            detections.append(res)

    # 2. Run LLM Anomaly Detection (Only if healthy)
    llm_res = await detect_llm_anomaly(event_data)
    if llm_res:
        detections.append(llm_res)

    if not detections:
        return {"status": "ok"}

    risk = calculate_risk_score(detections)
    primary = max(detections, key=lambda x: settings.SEVERITY_WEIGHTS.get(
        x.get("severity", "LOW"), 0))
    report = {**primary, "timestamp": datetime.now(
        timezone.utc).isoformat(), "ip": ip, "risk_score": risk.score}

    log_secure_attack_event(report)
    app_state.attack_history.append(report)
    await manager.broadcast({"type": "attack_detected", **report})
    return report


@router.post("/download_report")
async def download_report_endpoint(request_data: ReportRequest):
    client = app_state.http_client
    if not client:
        raise HTTPException(503, "Client Offline")

    stats = await get_analytics_endpoint()
    # Filter: "Lighter Mode" - only analyze unique threat types found in logs
    unique_threats = list({l.get("attack_type"): l for l in list(
        app_state.attack_history)[-50:]}.values())

    system_prompt = (
        "You are a SOC Expert. Provide a technical breakdown for each unique threat in the logs. "
        "For each, list: ANALYSIS, IMPACT, MITIGATION. Use ### headers. Be concise."
    )

    try:
        response = await client.post(
            f"{settings.OLLAMA_URL}/api/generate",
            json={
                "model": settings.LLM_MODEL_NAME, "system": system_prompt,
                "prompt": f"Stats: {json.dumps(stats)}\nThreats: {json.dumps(unique_threats[:10])}",
                "stream": False, "options": {"num_gpu": 1, "num_predict": 1000}
            }, timeout=90.0
        )
        analysis_text = response.json().get("response", "Analysis failed.")
    except Exception:
        analysis_text = "### Status: AI Analysis Offline\nManual log review required."

    pdf_bytes = await asyncio.to_thread(create_pdf_report, analysis_text, stats, request_data.trend_chart_img, request_data.severity_chart_img)
    return Response(content=pdf_bytes, media_type="application/pdf", headers={'Content-Disposition': 'attachment; filename="AI_Report.pdf"'})

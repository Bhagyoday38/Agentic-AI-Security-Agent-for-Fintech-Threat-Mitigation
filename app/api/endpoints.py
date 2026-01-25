# app/api/endpoints.py
import logging
import os
import json
import asyncio
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, WebSocket, WebSocketDisconnect, Response, BackgroundTasks
from ..config import settings
from ..state import app_state
from ..models import EventData, ReportRequest
from ..services.detection import (
    detect_llm_anomaly, detect_brute_force, detect_dos_ddos, detect_static_patterns
)
from ..services.reporting import create_pdf_report
from ..services.simulation import run_simulation_background_task
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


@router.post("/log_event")
async def handle_event(request: Request, event_data: EventData):
    ip = event_data.source_ip or (
        request.client.host if request.client else "127.0.0.1")
    event_data.source_ip = ip
    detections = []
    # 1. Run Static Rules
    for d in [detect_dos_ddos, detect_brute_force, detect_static_patterns]:
        res = await d(event_data)
        if res:
            detections.append(res)
    # 2. Run LLM
    if not any(d.get("severity") == "CRITICAL" for d in detections):
        llm_res = await detect_llm_anomaly(event_data)
        if llm_res:
            detections.append(llm_res)

    if not detections:
        return {"status": "ok"}
    primary = detections[0]
    report = {**primary, "timestamp": datetime.now(
        timezone.utc).isoformat(), "ip": ip, "data": event_data.data}
    app_state.attack_history.append(report)
    app_state.error_event_timestamps.append(time.time())
    await manager.broadcast({"type": "attack_detected", **report})
    return report


@router.post("/download_report")
async def download_report_endpoint(request_data: ReportRequest):
    if not app_state.http_client:
        raise HTTPException(503, "Client Offline")

    # SAMPLING LOGIC: Ensure EVERY unique attack type detected is analyzed
    history = list(app_state.attack_history)
    unique_types = set(a.get("attack_type")
                       for a in history if a.get("attack_type"))
    threat_samples = []
    for atype in unique_types:
        sample = next(a for a in reversed(history)
                      if a.get("attack_type") == atype)
        threat_samples.append({"type": atype, "severity": sample.get(
            "severity"), "reason": sample.get("reason")})

    system_prompt = (
        "You are a Senior Security Specialist. For EVERY unique attack type listed, you MUST write a professional technical report "
        "consisting of: ### [Threat Name]\n- TECHNICAL ANALYSIS: prose breakdown of the vector.\n- IMPACT: risk to the network.\n"
        "- MITIGATION: exactly 3 technical steps to block this.\nBe technical and detailed."
    )

    try:
        response = await app_state.http_client.post(
            f"{settings.OLLAMA_URL}/api/generate",
            json={"model": settings.LLM_MODEL_NAME, "system": system_prompt, "prompt": f"Analyze: {json.dumps(threat_samples)}", "stream": False, "options": {
                "num_gpu": 1, "num_predict": 1500}},
            timeout=120.0
        )
        report_text = response.json().get("response", "Analysis failed.")
    except:
        # Matches error in source [cite: 32]
        report_text = "### Analysis Error\nAI Core unreachable during report generation."

    pdf_bytes = await asyncio.to_thread(create_pdf_report, report_text, {}, request_data.trend_chart_img, request_data.severity_chart_img)
    return Response(content=pdf_bytes, media_type="application/pdf", headers={'Content-Disposition': 'attachment; filename="Security_Audit.pdf"'})


@router.get("/attack_log")
async def get_attack_log():
    return list(app_state.attack_history)


@router.post("/run_simulation")
async def trigger_sim(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_simulation_background_task)
    return {"message": "Simulation started"}

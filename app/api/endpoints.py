# ai-security-agent/app/api/endpoints.py
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
from ..services.detection import detect_llm_anomaly, detect_brute_force, detect_dos_ddos, calculate_risk_score
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
async def handle_event(request: Request, event: EventData):
    ip = event.source_ip or (
        request.client.host if request.client else "127.0.0.1")
    event.source_ip = ip
    detections = []
    for d in [detect_dos_ddos, detect_brute_force]:
        res = await d(event)
        if res:
            detections.append(res)
    llm_res = await detect_llm_anomaly(event)
    if llm_res:
        detections.append(llm_res)

    if not detections:
        return {"status": "ok"}
    report = {
        **detections[0], "timestamp": datetime.now(timezone.utc).isoformat(), "ip": ip}
    app_state.attack_history.append(report)
    app_state.error_event_timestamps.append(time.time())
    await manager.broadcast({"type": "attack_detected", **report})
    return report


@router.post("/run_simulation")
async def trigger_simulation(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_simulation_background_task)
    return {"message": "Simulation started"}


@router.post("/download_report")
async def download_report_endpoint(request_data: ReportRequest):
    if not app_state.http_client:
        raise HTTPException(503, "HTTP Client Offline")
    top_threats = list(app_state.attack_history)[-10:]
    system_prompt = "Perform technical breakdown for each unique threat: Analysis, Impact, Mitigation. Use ### headers."
    try:
        response = await app_state.http_client.post(f"{settings.OLLAMA_URL}/api/generate", json={"model": settings.LLM_MODEL_NAME, "system": system_prompt, "prompt": json.dumps(top_threats), "stream": False, "options": {"num_gpu": 1, "num_predict": 1200}}, timeout=120.0)
        report_text = response.json().get("response", "Analysis unavailable.")
    except:
        report_text = "### Analysis Offline\nManual review of logs required."
    pdf_bytes = await asyncio.to_thread(create_pdf_report, report_text, {}, request_data.trend_chart_img, request_data.severity_chart_img)
    return Response(content=pdf_bytes, media_type="application/pdf", headers={'Content-Disposition': 'attachment; filename="Security_Report.pdf"'})


@router.get("/attack_log")
async def get_attack_log():
    return list(app_state.attack_history)

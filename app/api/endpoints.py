import asyncio
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect

from ..state import app_state
from ..services.detection import (
    detect_dos_static,
    detect_static_patterns,
    detect_llm_anomaly
)
from .websocket import manager, broadcast_attack_event

router = APIRouter()


# ✅ WebSocket
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(60)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# 🔥 COMMON DETECTION FUNCTION
async def process_event(data, ip):
    event = type("obj", (), {
        "data": data,
        "model_dump": lambda: data
    })()

    app_state.request_timestamps.append(time.time())

    for detector in [detect_dos_static, detect_static_patterns, detect_llm_anomaly]:
        result = await detector(event)

        if result:
            attack = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": ip,
                **result
            }

            app_state.attack_history.append(attack)
            app_state.error_event_timestamps.append(time.time())

            await broadcast_attack_event(attack)
            return attack

    return None


# 🔥 EXTERNAL ATTACK (FIXED)
@router.post("/ingest")
async def ingest(request: Request):
    data = await request.json()
    ip = data.get("ip", request.client.host)

    result = await process_event(data, ip)

    return result or {"status": "safe"}


# 🔥 INTERNAL EVENT
@router.post("/log_event")
async def log_event(request: Request):
    data = await request.json()
    ip = request.client.host

    result = await process_event(data, ip)

    return result or {"status": "safe"}
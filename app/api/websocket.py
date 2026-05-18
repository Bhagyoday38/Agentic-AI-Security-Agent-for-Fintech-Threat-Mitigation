import asyncio
import logging
import time
from typing import List
from fastapi import WebSocket
from ..state import app_state

logger = logging.getLogger("Runner")


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


# ✅ STANDARDIZED ATTACK EVENT
async def broadcast_attack_event(attack_data: dict):
    await manager.broadcast({
        "type": "attack_event",
        "data": attack_data
    })


# ✅ METRICS (FIXED)
async def broadcast_metrics_periodically():
    logger.info("Starting live metrics broadcasting task...")

    while True:
        try:
            now = time.time()

            recent_reqs = [t for t in app_state.request_timestamps if t > now - 60]
            recent_errs = [t for t in app_state.error_event_timestamps if t > now - 60]

            ai_status = "BUSY" if app_state.llm_circuit_state.is_open else "ONLINE"
            if not app_state.http_client:
                ai_status = "OFFLINE"

            metrics_payload = {
                "type": "metrics_update",
                "requests_per_minute": len(recent_reqs),
                "error_events_per_minute": len(recent_errs),
                "total_threats": len(app_state.attack_history),
                "active_ws_clients": len(manager.active_connections),  # 🔥 FIX
                "llm_status": ai_status,
                "llm_reason": "Monitoring live traffic..." if ai_status == "ONLINE"
                else "Processing anomaly..."
            }

            await manager.broadcast(metrics_payload)
            await asyncio.sleep(1)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Metrics Broadcast Error: {e}")
            await asyncio.sleep(5)
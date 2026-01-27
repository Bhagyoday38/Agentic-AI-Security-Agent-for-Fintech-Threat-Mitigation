# app/api/websocket.py
import asyncio
import json
import logging
import time
from typing import List
from fastapi import WebSocket
from ..state import app_state
from ..config import settings

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


async def broadcast_metrics_periodically():
    """Background task to push live stats to the dashboard."""
    logger.info("Starting live metrics broadcasting task...")
    while True:
        try:
            now = time.time()

            # Calculate live traffic window (last 60s)
            recent_reqs = [
                t for t in app_state.request_timestamps if t > now - 60]
            recent_errs = [
                t for t in app_state.error_event_timestamps if t > now - 60]

            # Determine AI Health
            ai_status = "BUSY" if app_state.llm_circuit_state.is_open else "ONLINE"
            if not app_state.http_client:
                ai_status = "OFFLINE"

            metrics_payload = {
                "type": "metrics_update",
                "requests_per_minute": len(recent_reqs),
                "error_events_per_minute": len(recent_errs),
                "total_threats": len(app_state.attack_history),
                "llm_status": ai_status,
                "llm_reason": "Monitoring live traffic..." if ai_status == "ONLINE" else "Processing complex anomaly..."
            }

            await manager.broadcast(metrics_payload)
            await asyncio.sleep(1)  # Update UI every second
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Metrics Broadcast Error: {e}")
            await asyncio.sleep(5)

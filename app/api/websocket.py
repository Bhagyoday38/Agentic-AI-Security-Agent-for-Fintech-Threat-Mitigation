# app/api/websocket.py
import asyncio
import json
import logging
import time
from typing import Set
from fastapi import WebSocket, WebSocketDisconnect

from ..state import app_state
from ..config import settings

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(
            f"WebSocket client connected: {websocket.client} (Total: {len(self.active_connections)})")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(
            f"WebSocket client disconnected: {websocket.client} (Total: {len(self.active_connections)})")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            # logger.debug("Broadcast skipped: No active clients.")
            return
        try:
            message_json = json.dumps(message, default=str)
        except TypeError as e:
            logger.error(f"Msg serialization failed: {e} - Msg: {message}")
            return

        disconnected_clients = set()
        # Iterate over a copy of the set to allow safe modification
        for client in self.active_connections:
            try:
                await client.send_text(message_json)
            except Exception as e:
                # --- FIX: More descriptive error log ---
                logger.warning(
                    f"WS send failed for {client.client}: {type(e).__name__} - {e}. Removing.")
                disconnected_clients.add(client)

        # Remove all failed clients at the end
        self.active_connections -= disconnected_clients


manager = ConnectionManager()


async def broadcast_metrics_periodically():
    """Periodically calculates and broadcasts system metrics via WebSocket."""
    logger.info("Starting metrics broadcasting task...")
    while True:
        try:
            await asyncio.sleep(5)
            now = time.time()
            cutoff = now - settings.TIME_WINDOW_SECONDS
            while app_state.request_timestamps and app_state.request_timestamps[0] < cutoff:
                app_state.request_timestamps.popleft()
            requests_per_minute = len(app_state.request_timestamps)
            while app_state.error_event_timestamps and app_state.error_event_timestamps[0] < cutoff:
                app_state.error_event_timestamps.popleft()
            errors_per_minute = len(app_state.error_event_timestamps)
            llm_state = app_state.llm_circuit_state
            llm_status = "OPEN" if llm_state.is_open else (
                "DEGRADED" if llm_state.failure_count > 0 else "ACTIVE")
            llm_reason = llm_state.last_error if (
                llm_state.is_open or llm_state.failure_count > 0) else "AI analysis operational."
            metrics = {"type": "metrics_update", "requests_per_minute": requests_per_minute, "error_events_per_minute": errors_per_minute, "monitored_websites_count": len(
                app_state.monitored_websites), "active_ws_clients": len(manager.active_connections), "llm_status": llm_status, "llm_reason": llm_reason}
            await manager.broadcast(metrics)
        except asyncio.CancelledError:
            logger.info("Metrics broadcasting task cancelled.")
            break
        except Exception as e:
            logger.error(f"Error in metrics loop: {e}", exc_info=True)
            await asyncio.sleep(30)

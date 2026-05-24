import logging
import asyncio
import httpx
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, cast
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .config import settings
from .state import app_state
from .api.endpoints import router as api_router
from .api.websocket import manager, broadcast_metrics_periodically


if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


async def ollama_health_monitor():
    while True:
        await asyncio.sleep(20)

        # Cast to Any to prevent Pylance from inferring 'None' or 'Never'
        client = cast(Any, app_state.http_client)
        if not client:
            continue
        try:
            res = await client.get(settings.OLLAMA_URL, timeout=5.0)

            # Cast circuit state to Any to satisfy dynamic property checks safely
            circuit = cast(Any, app_state.llm_circuit_state)
            if res.status_code == 200 and getattr(circuit, "is_open", False):
                circuit.is_open = False
                logging.info("Ollama Status: Healthy.")
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):

    client = httpx.AsyncClient(timeout=httpx.Timeout(100.0), verify=False)
    setattr(app_state, "http_client", client)

    metrics_task = asyncio.create_task(broadcast_metrics_periodically())
    health_task = asyncio.create_task(ollama_health_monitor())

    yield

    metrics_task.cancel()
    health_task.cancel()

    # Safely extract and close the async client instance
    final_client = cast(Any, app_state.http_client)
    if final_client:
        await final_client.aclose()


app = FastAPI(title="AI Security Agent", lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(api_router)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)


static_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "static"
)

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/")
async def get_index():
    index_file = os.path.join(static_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)

    return {"message": "Static index.html not found. Check your folder structure."}

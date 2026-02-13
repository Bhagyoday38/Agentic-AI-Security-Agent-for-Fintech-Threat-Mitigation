import logging
import asyncio
import httpx
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from .config import settings
from .state import app_state
from .api.endpoints import router as api_router
from .api.websocket import broadcast_metrics_periodically


async def ollama_health_monitor():
    """Background task to restore AI connectivity automatically."""
    while True:
        await asyncio.sleep(20)
        if not app_state.http_client:
            continue
        try:
            res = await app_state.http_client.get(settings.OLLAMA_URL, timeout=5.0)
            if res.status_code == 200 and app_state.llm_circuit_state.is_open:
                app_state.llm_circuit_state.is_open = False
                logging.info("Ollama Status: Healthy.")
        except:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):

    app_state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(100.0), verify=False)

    metrics_task = asyncio.create_task(broadcast_metrics_periodically())
    health_task = asyncio.create_task(ollama_health_monitor())
    yield
    metrics_task.cancel()
    health_task.cancel()
    if app_state.http_client:
        await app_state.http_client.aclose()

app = FastAPI(title="AI Security Agent", lifespan=lifespan)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(api_router)


static_path = os.path.join(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))), "static")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/")
async def get_index():

    index_file = os.path.join(static_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Static index.html not found. Check your folder structure."}

# ai-security-agent/app/main.py
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
    """Background monitor to reconnect LLM automatically."""
    while True:
        await asyncio.sleep(20)
        if not app_state.http_client:
            continue
        try:
            res = await app_state.http_client.get(settings.OLLAMA_URL, timeout=5.0)
            if res.status_code == 200 and app_state.llm_circuit_state.is_open:
                app_state.llm_circuit_state.is_open = False
                logging.info("Ollama Restored: AI core back online.")
        except:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    app_state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(45.0), verify=False)
    app.state.metrics_task = asyncio.create_task(
        broadcast_metrics_periodically())
    app.state.health_task = asyncio.create_task(ollama_health_monitor())
    yield
    app.state.metrics_task.cancel()
    app.state.health_task.cancel()
    if app_state.http_client:
        await app_state.http_client.aclose()

app = FastAPI(title="AI Security Agent", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[
                   "*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(api_router)

# Fix 404: Use absolute path for static files
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
static_path = os.path.join(root_path, "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/")
async def get_index():
    return FileResponse(os.path.join(static_path, "index.html"))

# ai-security-agent/app/main.py
import logging
import asyncio
import httpx
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .state import app_state
from .api.endpoints import router as api_router
from .services.monitoring import stop_all_monitoring
from .api.websocket import broadcast_metrics_periodically

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] Runner: %(message)s')
logger = logging.getLogger("Runner")


async def check_ollama_health():
    """Independent task to automatically reconnect LLM if it goes down."""
    while True:
        await asyncio.sleep(settings.LLM_HEALTH_CHECK_INTERVAL)
        if not app_state.http_client:
            continue

        try:
            # Check base endpoint
            res = await app_state.http_client.get(settings.OLLAMA_URL, timeout=5.0)
            if res.status_code == 200:
                if app_state.llm_circuit_state.is_open:
                    logger.info("Ollama Restored: Resetting circuit breaker.")
                    app_state.llm_circuit_state.is_open = False
                    app_state.llm_circuit_state.failure_count = 0
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Shared Client
    app_state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(45.0), verify=False)

    # Start background tasks
    app.state.metrics_task = asyncio.create_task(
        broadcast_metrics_periodically())
    app.state.health_task = asyncio.create_task(check_ollama_health())

    logger.info("Security Agent services initialized.")
    yield
    # Shutdown
    app.state.metrics_task.cancel()
    app.state.health_task.cancel()
    await stop_all_monitoring()
    if app_state.http_client:
        await app_state.http_client.aclose()

app = FastAPI(title="AI Security Agent", lifespan=lifespan)

# Enable CORS for WebSockets and Local UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def get_index():
    index_path = os.path.join(static_dir, "index.html")
    return FileResponse(index_path) if os.path.exists(index_path) else PlainTextResponse("UI Missing", 404)

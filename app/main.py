# app/main.py
import logging
import asyncio
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
import os

# Import components
from .config import settings
from .state import app_state
from .api.endpoints import router as api_router
from .services.monitoring import start_website_monitoring, stop_all_monitoring, WebsiteMonitorConfig
from .api.websocket import broadcast_metrics_periodically

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)


async def check_ollama_connection(client: httpx.AsyncClient, url: str):
    """Checks basic connectivity to the Ollama API."""
    # Initialize health_url before try block
    health_url = url.split(
        '/api/')[0] if '/api/' in url else url  # Get base URL
    if not health_url.endswith('/'):
        health_url += '/'
    try:
        logger.info(f"Checking Ollama connection at: {health_url}")
        # Short timeout for health check
        response = await client.get(health_url, timeout=5.0)
        response.raise_for_status()
        logger.info(
            f"Ollama connection successful: Status {response.status_code}")
        # Optionally check response content if Ollama has a specific health message
        # if "Ollama is running" in response.text: logger.info("Ollama health check passed.")
        return True
    except httpx.TimeoutException:
        logger.error(
            f"Ollama connection check timed out accessing {health_url}.")
    except httpx.ConnectError:
        logger.error(
            f"Ollama connection check failed: Could not connect to {health_url}. Is Ollama running?")
    except httpx.RequestError as e:
        logger.error(
            f"Ollama connection check failed: Request error accessing {health_url} - {e}")
    except Exception as e:
        logger.error(f"Ollama connection check failed: Unexpected error - {e}")
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application startup and shutdown events."""
    logger.info("Application starting up...")

    # --- Startup ---
    timeout = httpx.Timeout(15.0, connect=5.0)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
    app_state.http_client = httpx.AsyncClient(
        timeout=timeout, limits=limits, verify=False)
    logger.info("Shared HTTP client initialized.")

    # --- Check Ollama Connection on Startup ---
    await check_ollama_connection(app_state.http_client, settings.OLLAMA_URL)
    # ----------------------------------------

    # Start background tasks
    app.state.metrics_task = asyncio.create_task(
        broadcast_metrics_periodically(), name="metrics_broadcaster")
    logger.info("Metrics broadcasting task started.")

    logger.info("Security Agent startup complete.")
    yield  # Application runs here

    # --- Shutdown ---
    logger.info("Application shutting down...")
    # (Shutdown logic remains the same as previous answer)
    if hasattr(app.state, 'metrics_task') and not app.state.metrics_task.done():
        app.state.metrics_task.cancel()
        try:
            await app.state.metrics_task
        except asyncio.CancelledError:
            logger.info("Metrics broadcaster task successfully cancelled.")
        except Exception as e:
            logger.error(
                f"Error during metrics task cancellation: {e}", exc_info=True)
    await stop_all_monitoring()
    if app_state.http_client:
        await app_state.http_client.aclose()
        logger.info("Shared HTTP client closed.")
    logger.info("Application shutdown complete.")


# Create FastAPI app instance
app = FastAPI(
    title="AI Security Agent",
    description="Real-time threat detection and website monitoring using AI.",
    version="1.0.1",  # Incremented version
    lifespan=lifespan
)

app.include_router(api_router)

static_dir = "static"
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    logger.info(f"Mounted static directory '{static_dir}' at '/static'")
else:
    logger.warning(f"Static directory '{static_dir}' not found.")


@app.get("/", include_in_schema=False)
async def get_index_html():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type='text/html')
    else:
        logger.error("index.html not found.")
        return PlainTextResponse("Frontend file (index.html) not found.", status_code=404)


@app.get("/health", status_code=200, tags=["Health"])
async def health_check(): return {"status": "ok"}

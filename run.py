# run.py
import uvicorn
import os
import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] Runner: %(message)s')

if __name__ == "__main__":
    app_module_str = "app.main:app"
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload_flag = os.getenv("DEV_MODE", "false").lower() == "true"
    reload_dirs = [os.path.dirname(
        os.path.abspath(__file__))] if reload_flag else None

    print("=" * 60)
    print("   Starting AI Security Agent Server")
    print("=" * 60)
    logging.info(f"Loading ASGI app from: {app_module_str}")
    logging.info(f"Server will run on: http://{host}:{port}")
    logging.info(f"Auto-reload enabled: {reload_flag}")
    if reload_dirs:
        logging.info(f"Reload directories: {reload_dirs}")
    print("=" * 60)

    try:
        uvicorn.run(
            app_module_str,
            host=host,
            port=port,
            reload=reload_flag,
            reload_dirs=reload_dirs,
            log_level="info",
        )
    except ImportError as e:
        logging.error(
            f"ImportError: Could not import ASGI app '{app_module_str}'. Check file structure and imports.")
        logging.error(f"Details: {e}")
    except Exception as e:
        logging.error(f"Failed to start Uvicorn server: {e}", exc_info=True)

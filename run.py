# run.py
import uvicorn
import os

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    print("=" * 60)
    print("   AI Security Agent Dashboard: Starting...")
    print("=" * 60)

    uvicorn.run("app.main:app", host=host, port=port, log_level="info")

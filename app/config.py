# app/config.py
from pydantic_settings import BaseSettings
from typing import Dict, Optional


class Settings(BaseSettings):
    TIME_WINDOW_SECONDS: int = 100
    DOS_ATTACK_THRESHOLD: int = 50
    SCANNING_THRESHOLD: int = 15
    BRUTE_FORCE_THRESHOLD: int = 5
    CREDENTIAL_STUFFING_THRESHOLD: int = 10

    LLM_MODEL_NAME: str = "gemma2:2b"
    OLLAMA_URL: str = "http://localhost:11434"
    LLM_REQUEST_TIMEOUT: float = 100.0  # Increased to 100s

    SSL_EXPIRY_WARNING: int = 30
    SLACK_WEBHOOK_URL: Optional[str] = None
    DISCORD_WEBHOOK_URL: Optional[str] = None
    LOG_JSON_FILE: str = "attack_events.json"

    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 0
    }


settings = Settings()

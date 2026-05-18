from pydantic_settings import BaseSettings
from typing import Dict, Optional


class Settings(BaseSettings):
    # Detection Thresholds
    TIME_WINDOW_SECONDS: int = 100
    DOS_ATTACK_THRESHOLD: int = 50
    SCANNING_THRESHOLD: int = 15
    BRUTE_FORCE_THRESHOLD: int = 5

    # Intelligence Config
    LLM_MODEL_NAME: str = "mistal"
    OLLAMA_URL: str = "http://localhost:11434"

    # Notification Hooks (Agentic Alerts)
    SLACK_WEBHOOK_URL: Optional[str] = None
    DISCORD_WEBHOOK_URL: Optional[str] = None

    # Threat Weighting
    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 0
    }
    LOG_JSON_FILE: str = "attack_logs.json"


settings = Settings()

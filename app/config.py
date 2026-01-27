# app/config.py
from pydantic_settings import BaseSettings
from typing import Dict


class Settings(BaseSettings):
    # Static Thresholds
    TIME_WINDOW_SECONDS: int = 60
    DOS_ATTACK_THRESHOLD: int = 50
    SCANNING_THRESHOLD: int = 15
    BRUTE_FORCE_THRESHOLD: int = 5
    # Failed logins across different accounts from 1 IP
    CREDENTIAL_STUFFING_THRESHOLD: int = 10

    # LLM Configuration
    LLM_MODEL_NAME: str = "gemma2:2b"
    OLLAMA_URL: str = "http://localhost:11434"
    LLM_REQUEST_TIMEOUT: float = 10.0

    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 0
    }


settings = Settings()

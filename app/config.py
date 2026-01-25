# app/config.py
from typing import Dict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Detection Thresholds
    TIME_WINDOW_SECONDS: int = 60
    DOS_ATTACK_THRESHOLD: int = 50
    BRUTE_FORCE_THRESHOLD: int = 3
    CARD_TEST_THRESHOLD: int = 5
    ATO_TIME_WINDOW: int = 30

    # --- LLM Configuration ---
    LLM_MODEL_NAME: str = "gemma2:2b"
    OLLAMA_URL: str = "http://localhost:11434"
    LLM_MAX_FAILURES: int = 2
    LLM_REQUEST_TIMEOUT: float = 10.0

    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

    class Config:
        env_file = '.env'
        extra = 'ignore'


settings = Settings()

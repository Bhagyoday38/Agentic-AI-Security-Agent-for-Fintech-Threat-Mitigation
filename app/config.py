# app/config.py
import os
from typing import List, Dict, Set
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Detection Thresholds
    TIME_WINDOW_SECONDS: int = 60
    DOS_ATTACK_THRESHOLD: int = 50
    BRUTE_FORCE_THRESHOLD: int = 3
    RATE_LIMIT_DURATION: int = 300
    CARD_TEST_THRESHOLD: int = 5
    ATO_TIME_WINDOW: int = 30

    # LLM Configuration
    LLM_MODEL_NAME: str = "mistral"
    OLLAMA_URL: str = "http://localhost:11434"
    LLM_MAX_FAILURES: int = 3
    LLM_COOLDOWN_SECONDS: int = 45
    LLM_HEALTH_CHECK_INTERVAL: int = 20

    # Constants
    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0
    }
    LOG_JSON_FILE: str = "attack_log.json"

    class Config:
        env_file = '.env'
        extra = 'ignore'


settings = Settings()

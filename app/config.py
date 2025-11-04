# app/config.py
import os
from typing import List, Dict, Set
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- Detection Thresholds ---
    TIME_WINDOW_SECONDS: int = 60
    DOS_ATTACK_THRESHOLD: int = 50
    DDOS_IP_THRESHOLD: int = 5
    BRUTE_FORCE_THRESHOLD: int = 3
    RATE_LIMIT_DURATION: int = 300  # seconds
    CARD_TEST_THRESHOLD: int = 5  # failures per IP in window
    ATO_VELOCITY_THRESHOLD: int = 3  # login failures per user in window
    ATO_TIME_WINDOW: int = 30  # seconds

    # --- Website Monitoring Config ---
    WEBSITE_MONITOR_INTERVAL: int = 300  # Default check interval in seconds
    RESPONSE_TIME_THRESHOLD: int = 5000  # milliseconds
    SSL_EXPIRY_WARNING: int = 30  # days
    CONTENT_CHANGE_THRESHOLD: float = 0.8  # Similarity threshold for content check

    # --- LLM Configuration ---
    LLM_MODEL_NAME: str = "mistral"
    OLLAMA_URL: str = "http://localhost:11434"  # Default Ollama URL
    LLM_MAX_FAILURES: int = 5
    LLM_COOLDOWN_SECONDS: int = 60

    # --- Webhook & API Keys ---
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")

    # --- Constants ---
    PII_FIELDS: List[str] = ["email", "phone_number",
                             "billing_address", "name", "password"]
    PAYMENT_FIELDS: Set[str] = {
        "card_number", "cvv", "expiry_date", "payment_token", "transaction_id",
        "amount", "billing_address", "card_brand", "issuer_country", "bin"
    }
    SEVERITY_WEIGHTS: Dict[str, int] = {
        "CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0
    }

    # --- File Paths ---
    LOG_JSON_FILE: str = "attack_log.json"

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'
        extra = 'ignore'


# --- Create the settings instance ---
settings = Settings()

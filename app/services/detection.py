import time
import json
import asyncio
import re
import logging
import httpx
from typing import Optional, Dict
from ..state import app_state
from ..config import settings

logger = logging.getLogger("SecurityRunner")
llm_semaphore = asyncio.Semaphore(1)


async def detect_dos_static(event) -> Optional[Dict]:
    now = time.time()

    while app_state.request_timestamps and app_state.request_timestamps[0] < now - 100:
        app_state.request_timestamps.popleft()

    if len(app_state.request_timestamps) > settings.DOS_ATTACK_THRESHOLD:
        return {"is_attack": True, "attack_type": "DoS", "severity": "CRITICAL", "confidence": 1.0}
    return None


async def detect_static_patterns(event) -> Optional[Dict]:
    payload = str(event.data).lower()
    patterns = {
        "SQL Injection": r"(union\s+select|or\s+1=1|drop\s+table|--|information_schema)",
        "XSS": r"(<script|onerror=|alert\(|javascript:|<iframe>)",
        "Command Injection": r"(\||;|&&|`|\$\(|/bin/sh|/bin/bash|nc\s+|curl\s+)"
    }
    for atype, regex in patterns.items():
        if re.search(regex, payload):
            return {"is_attack": True, "attack_type": atype, "severity": "HIGH", "confidence": 0.95}
    return None


async def detect_llm_anomaly(event) -> Optional[Dict]:
    """AI Behavioral Analysis: Increased timeout to prevent simulation failures."""
    if app_state.llm_circuit_state.is_open or not app_state.http_client:
        return None

    if llm_semaphore.locked():
        return None

    async with llm_semaphore:
        try:
            payload = {
                "model": settings.LLM_MODEL_NAME,
                "system": "Respond ONLY with JSON: {'is_malicious': bool, 'attack_type': str, 'severity': str, 'confidence': float, 'reason': str}.",
                "prompt": f"Analyze: {json.dumps(event.model_dump())}",
                "stream": False, "format": "json",
                "options": {"num_gpu": 33, "num_ctx": 2048, "num_batch": 128}
            }
            # Increased timeout to 100s as requested
            res = await app_state.http_client.post(
                f"{settings.OLLAMA_URL}/api/generate",
                json=payload,
                timeout=100.0
            )
            result = json.loads(res.json().get("response"))
            if result.get("is_malicious"):
                app_state.llm_circuit_state.failure_count = 0
                return {"is_attack": True, **result}
        except (httpx.ReadTimeout, httpx.ConnectError):
            app_state.llm_circuit_state.failure_count += 1
            if app_state.llm_circuit_state.failure_count >= 3:
                app_state.llm_circuit_state.is_open = True
        except Exception:
            pass
    return None

import time
import json
import asyncio
import re
import logging
import httpx
from typing import Optional, Dict
from collections import deque
from ..state import app_state
from ..config import settings

logger = logging.getLogger("SecurityRunner")
llm_semaphore = asyncio.Semaphore(1)


# 🔴 DoS Detection
async def detect_dos_static(event) -> Optional[Dict]:
    now = time.time()

    if not isinstance(app_state.request_timestamps, deque):
        app_state.request_timestamps = deque(app_state.request_timestamps)

    while app_state.request_timestamps and app_state.request_timestamps[0] < now - 100:
        app_state.request_timestamps.popleft()

    if len(app_state.request_timestamps) > settings.DOS_ATTACK_THRESHOLD:
        return {
            "is_attack": True,
            "attack_type": "DDoS",
            "severity": "CRITICAL",
            "confidence": 1.0,
            "reason": "Traffic spike detected"
        }
    return None


# 🟡 Signature Detection
async def detect_static_patterns(event) -> Optional[Dict]:
    payload = str(event.data).lower()

    patterns = {
        "SQL Injection": r"(union\s+select|or\s+1=1|drop\s+table|--)",
        "XSS": r"(<script|alert\()",
        "Command Injection": r"(\||;|&&)"
    }

    for atype, regex in patterns.items():
        if re.search(regex, payload):
            return {
                "is_attack": True,
                "attack_type": atype,
                "severity": "HIGH",
                "confidence": 0.95,
                "reason": f"{atype} detected"
            }

    return None


# 🔁 Fallback
async def fallback_detection(event):
    return await detect_static_patterns(event)


# 🧠 Mistral AI Detection
async def detect_llm_anomaly(event) -> Optional[Dict]:

    if app_state.llm_circuit_state.is_open or not app_state.http_client:
        return None

    if llm_semaphore.locked():
        return None

    async with llm_semaphore:
        try:
            prompt = """
You are a cybersecurity AI.

Classify into:
DDoS, SQL Injection, XSS, Command Injection, Phishing, Malware, Brute Force, Normal

Return ONLY JSON:
{
 "is_malicious": true/false,
 "attack_type": "XSS",
 "severity": "LOW/MEDIUM/HIGH/CRITICAL",
 "confidence": 0.0-1.0,
 "reason": "short"
}
"""

            res = await app_state.http_client.post(
                f"{settings.OLLAMA_URL}/api/generate",
                json={
                    "model": settings.LLM_MODEL_NAME,
                    "prompt": f"{prompt}\n\n{json.dumps(event.model_dump())}",
                    "stream": False
                },
                timeout=60.0
            )

            raw = res.json().get("response", "")

            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not match:
                return await fallback_detection(event)

            result = json.loads(match.group())

            if not result.get("is_malicious"):
                return None

            return {
                "is_attack": True,
                "attack_type": result.get("attack_type"),
                "severity": result.get("severity", "MEDIUM").upper(),
                "confidence": float(result.get("confidence", 0.8)),
                "reason": result.get("reason", "")
            }

        except Exception:
            return await fallback_detection(event)

    return None
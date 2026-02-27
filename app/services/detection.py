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
    """Static DoS detection based on request frequency thresholds."""
    now = time.time()

    # Clear timestamps outside the current window
    while app_state.request_timestamps and app_state.request_timestamps[0] < now - 100:
        app_state.request_timestamps.popleft()

    # Trigger alert if threshold exceeded
    if len(app_state.request_timestamps) > settings.DOS_ATTACK_THRESHOLD:
        return {
            "is_attack": True,
            "attack_type": "DoS",
            "severity": "CRITICAL",
            "confidence": 1.0,
            "reason": f"Traffic spike detected: {len(app_state.request_timestamps)} requests in 100s window."
        }
    return None


async def detect_static_patterns(event) -> Optional[Dict]:
    """Pattern matching for known web attack signatures."""
    payload = str(event.data).lower()
    patterns = {
        "SQL Injection": r"(union\s+select|or\s+1=1|drop\s+table|--|information_schema)",
        "XSS": r"(<script|onerror=|alert\(|javascript:|<iframe>)",
        "Command Injection": r"(\||;|&&|`|\$\(|/bin/sh|/bin/bash|nc\s+|curl\s+)"
    }
    for atype, regex in patterns.items():
        if re.search(regex, payload):
            return {
                "is_attack": True,
                "attack_type": atype,
                "severity": "HIGH",
                "confidence": 0.95,
                "reason": f"Static signature match for {atype} in request payload."
            }
    return None


async def detect_llm_anomaly(event) -> Optional[Dict]:
    """
    Agentic AI Behavioral Analysis: 
    Classifies complex threats (Botnets, Ransomware) and provides mitigation reasoning.
    """
    if app_state.llm_circuit_state.is_open or not app_state.http_client:
        return None

    # Non-blocking check to prevent simulation bottlenecks
    if llm_semaphore.locked():
        return None

    async with llm_semaphore:
        try:
            # Updated Agentic System Prompt
            system_instruction = (
                "You are an Autonomous Threat Intelligence Engine. Analyze telemetry for "
                "patterns like Botnets, Ransomware, or Credential Harvesters. "
                "Respond ONLY with JSON: {'is_malicious': bool, 'attack_type': str, "
                "'severity': str, 'confidence': float, 'reason': str}."
            )

            payload = {
                "model": settings.LLM_MODEL_NAME,
                "system": system_instruction,
                "prompt": f"Analyze telemetry: {json.dumps(event.model_dump())}",
                "stream": False,
                "format": "json",
                "options": {"num_gpu": 33, "num_ctx": 2048, "num_batch": 128}
            }

            # Extended 100s timeout to handle deep behavioral clustering
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
                logger.error(
                    "AI Core Circuit Breaker: OPEN (Too many failures)")
        except Exception as e:
            logger.error(f"AI Analysis Error: {e}")

    return None

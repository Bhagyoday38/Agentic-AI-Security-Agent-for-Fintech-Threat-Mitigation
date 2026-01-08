# ai-security-agent/app/services/detection.py
import time
import json
import logging
import asyncio
from typing import Optional, Dict, List
from ..config import settings
from ..state import app_state
from ..models import EventData, RiskScore

logger = logging.getLogger("Runner." + __name__)
llm_semaphore = asyncio.Semaphore(2)  # Prevent GPU memory choke


async def detect_llm_anomaly(event: EventData) -> Optional[Dict]:
    if event.event_type == "simulated_high_traffic" or app_state.dos_attack_in_progress:
        return None

    state = app_state.llm_circuit_state
    if state.is_open:
        return None

    # FIX: Pylance Narrowing
    client = app_state.http_client
    if not client:
        return None

    async with llm_semaphore:
        system_prompt = (
            "Analyze event. Respond ONLY JSON object: "
            "{'is_malicious': bool, 'attack_type': str, 'severity': str, 'confidence': float, 'reason': str}."
        )
        try:
            payload = {
                "model": settings.LLM_MODEL_NAME,
                "system": system_prompt,
                "prompt": f"Analyze: {json.dumps(event.model_dump())}",
                "stream": False, "format": "json",
                "options": {"num_gpu": 1, "temperature": 0.2, "num_thread": 8}
            }
            response = await client.post(f"{settings.OLLAMA_URL}/api/generate", json=payload, timeout=30.0)
            response.raise_for_status()
            parsed = json.loads(response.json().get("response"))

            state.failure_count = 0
            if parsed.get("is_malicious"):
                return {
                    "is_attack": True, "attack_type": parsed.get("attack_type"),
                    "reason": parsed.get("reason"), "severity": parsed.get("severity", "MEDIUM"),
                    "confidence": parsed.get("confidence", 0.7)
                }
        except Exception as e:
            state.failure_count += 1
            if state.failure_count >= settings.LLM_MAX_FAILURES:
                state.is_open = True
                logger.error(f"LLM Circuit Breaker Tripped: {e}")
    return None

# --- Static Rule-Based Detectors (Fallback) ---


async def detect_brute_force(event: EventData) -> Optional[Dict]:
    if event.event_type != "login_failure" or not event.user_id:
        return None
    log = app_state.brute_force_log[event.user_id]
    log.append(time.time())
    while log and log[0] < time.time() - settings.ATO_TIME_WINDOW:
        log.popleft()
    if len(log) >= settings.BRUTE_FORCE_THRESHOLD:
        return {"is_attack": True, "attack_type": "Brute Force", "severity": "HIGH", "confidence": 0.9, "reason": "Static: Threshold exceeded."}
    return None


async def detect_dos_ddos(event: EventData) -> Optional[Dict]:
    now = time.time()
    app_state.request_timestamps.append(now)
    while app_state.request_timestamps and app_state.request_timestamps[0] < now - settings.TIME_WINDOW_SECONDS:
        app_state.request_timestamps.popleft()
    if len(app_state.request_timestamps) > settings.DOS_ATTACK_THRESHOLD:
        return {"is_attack": True, "attack_type": "DoS", "severity": "CRITICAL", "confidence": 0.9, "reason": "Static: Traffic Spike."}
    return None


def calculate_risk_score(detections: List[Dict]) -> RiskScore:
    if not detections:
        return RiskScore(score=0.0, factors=[], severity="NONE")
    primary = max(detections, key=lambda x: settings.SEVERITY_WEIGHTS.get(
        x.get("severity", "LOW"), 0))
    return RiskScore(score=primary.get("confidence", 0.5), factors=[primary.get("attack_type")], severity=primary.get("severity"))

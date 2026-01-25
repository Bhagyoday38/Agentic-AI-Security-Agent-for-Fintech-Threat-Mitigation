# app/services/detection.py
import time
import json
import asyncio
import re
from typing import Optional, Dict, List
from ..config import settings
from ..state import app_state
from ..models import EventData, RiskScore

llm_semaphore = asyncio.Semaphore(1)


async def detect_static_patterns(event: EventData) -> Optional[Dict]:
    """Instant detection for SQLi and XSS payloads."""
    payload = str(event.data).lower()
    if re.search(r"union\s+select|or\s+1=1|drop\s+table|--", payload):
        return {"is_attack": True, "attack_type": "SQL Injection", "reason": "Static Regex Match", "severity": "HIGH", "confidence": 0.95}
    if re.search(r"<script|onerror=|alert\(|javascript:", payload):
        return {"is_attack": True, "attack_type": "XSS", "reason": "Static Regex Match", "severity": "HIGH", "confidence": 0.95}
    return None


async def detect_brute_force(event: EventData) -> Optional[Dict]:
    if event.event_type != "login_failure" or not event.user_id:
        return None
    log = app_state.brute_force_log[event.user_id]
    log.append(time.time())
    if len(log) >= settings.BRUTE_FORCE_THRESHOLD:
        return {"is_attack": True, "attack_type": "Brute Force", "severity": "HIGH", "confidence": 0.9, "reason": "Limit reached"}
    return None


async def detect_dos_ddos(event: EventData) -> Optional[Dict]:
    """ALWAYS STATIC: Fast detection to protect GPU 0."""
    now = time.time()
    app_state.request_timestamps.append(now)
    while app_state.request_timestamps and app_state.request_timestamps[0] < now - settings.TIME_WINDOW_SECONDS:
        app_state.request_timestamps.popleft()
    if len(app_state.request_timestamps) > settings.DOS_ATTACK_THRESHOLD:
        return {"is_attack": True, "attack_type": "DoS", "reason": "Traffic limit exceeded", "severity": "CRITICAL", "confidence": 1.0}
    return None


async def detect_llm_anomaly(event: EventData) -> Optional[Dict]:
    """AI Detection using Gemma 2 on Dedicated GPU 0."""
    if app_state.llm_circuit_state.is_open or not app_state.http_client or llm_semaphore.locked():
        return None
    async with llm_semaphore:
        try:
            payload = {
                "model": settings.LLM_MODEL_NAME,
                "system": "Respond ONLY with JSON: {'is_malicious': bool, 'attack_type': str, 'severity': str, 'confidence': float, 'reason': str}.",
                "prompt": f"Analyze: {json.dumps(event.model_dump())}",
                "stream": False, "format": "json",
                "options": {"num_gpu": 1, "temperature": 0.1}
            }
            response = await app_state.http_client.post(f"{settings.OLLAMA_URL}/api/generate", json=payload, timeout=settings.LLM_REQUEST_TIMEOUT)
            parsed = json.loads(response.json().get("response"))
            if parsed.get("is_malicious"):
                return {"is_attack": True, "attack_type": parsed.get("attack_type"), "reason": parsed.get("reason"), "severity": parsed.get("severity", "MEDIUM"), "confidence": parsed.get("confidence", 0.7)}
        except:
            pass
    return None


def calculate_risk_score(detections: List[Dict]) -> RiskScore:
    if not detections:
        return RiskScore(score=0.0, factors=[], severity="NONE")
    primary = max(detections, key=lambda x: settings.SEVERITY_WEIGHTS.get(
        x.get("severity", "LOW"), 0))
    return RiskScore(score=float(primary.get("confidence", 0.5)), factors=[str(primary.get("attack_type"))], severity=str(primary.get("severity")))

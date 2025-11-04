# app/services/detection.py
import time
import json
import logging
import httpx
import random
import re
from typing import Optional, Dict, List, Callable, Awaitable

from ..config import settings
from ..state import app_state
from ..models import EventData, RiskScore

logger = logging.getLogger("Runner." + __name__)

# --- LLM Anomaly Detection (UPDATED) ---


async def detect_llm_anomaly(event: EventData) -> Optional[Dict]:
    # --- FIX: Immediately ignore DoS events to protect LLM ---
    if event.event_type == "simulated_high_traffic":
        return None
    # --- END FIX ---

    state = app_state.llm_circuit_state
    now = time.time()
    if state.is_open:
        if now - state.last_failure_time > settings.LLM_COOLDOWN_SECONDS:
            logger.info(
                "LLM Circuit Breaker: Cooldown expired. Attempting half-open.")
            state.is_open = False
            state.failure_count = 0
        else:
            return None
    if not app_state.http_client:
        logger.warning("LLM detection skipped: HTTP client unavailable.")
        return None

    system_prompt = (
        "You are a cybersecurity analyst AI. Analyze the event JSON data provided. "
        "Your response MUST be a single JSON object with exactly five keys: "
        "'is_malicious' (boolean), "
        "'attack_type' (string, e.g., 'SQL Injection', 'XSS', 'Benign', 'Brute Force Attempt', 'Payment Anomaly'), "
        "'severity' (string: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'NONE'), "
        "'confidence' (float, a score between 0.0 and 1.0, e.g., 0.85), and "
        "'reason' (string: concise explanation). "
        "Do NOT include any text before or after the JSON. "
        "Pay attention to behavioral anomalies: multiple 'login_failure' events are 'Brute Force'. "
        "Multiple 'payment_failure' events are 'Card Testing'. "
        "A 'simulated_payment_anomaly' event is a 'Payment Anomaly'."
    )

    try:
        event_dict = event.model_dump(exclude={'headers', 'user_agent', 'device_fingerprint', 'session_id'}) if hasattr(
            event, 'model_dump') else event.dict(exclude={'headers', 'user_agent', 'device_fingerprint', 'session_id'})
        event_json_for_prompt = json.dumps(event_dict, indent=2)
    except Exception as e:
        logger.error(f"LLM Error: Failed to serialize event data: {e}")
        return None

    request_payload = {"model": settings.LLM_MODEL_NAME, "system": system_prompt,
                       "prompt": f"Analyze event:\n```json\n{event_json_for_prompt}\n```", "stream": False, "format": "json"}
    ollama_url = f"{settings.OLLAMA_URL}/api/generate"
    error_msg = "Unknown LLM error"
    llm_response_str = ""

    try:
        logger.debug(
            f"LLM Request -> {ollama_url} (Model: {settings.LLM_MODEL_NAME})")
        response = await app_state.http_client.post(ollama_url, json=request_payload, timeout=30.0)
        response.raise_for_status()
        response_data = response.json()
        llm_response_str = response_data.get("response")
        logger.debug(
            f"LLM Response <- Status={response.status_code}, Raw='{llm_response_str[:150]}...'")
        if not llm_response_str:
            raise ValueError("LLM returned empty response string.")

        parsed_response = None
        try:
            parsed_response = json.loads(llm_response_str)
        except json.JSONDecodeError as e:
            json_match = re.search(r'\{.*\}', llm_response_str, re.DOTALL)
            if json_match:
                logger.warning(
                    f"LLM response had extra text. Extracted JSON. Original: '{llm_response_str[:100]}...'")
                try:
                    parsed_response = json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    raise ValueError(
                        f"Failed parsing extracted JSON: {e}. Extracted: '{json_match.group(0)[:100]}...'")
            else:
                raise ValueError(
                    f"Invalid JSON response: {e}. Response: '{llm_response_str[:150]}...'")
        if not isinstance(parsed_response, dict):
            raise ValueError(
                f"LLM response is not a JSON object. Type: {type(parsed_response)}")

        required_keys = {"is_malicious", "attack_type",
                         "severity", "reason", "confidence"}
        missing_keys = required_keys - set(parsed_response.keys())
        if missing_keys:
            raise ValueError(
                f"LLM response missing keys: {missing_keys}. Got: {list(parsed_response.keys())}")

        is_malicious = parsed_response.get("is_malicious")
        if isinstance(is_malicious, str):
            is_malicious = is_malicious.lower() == 'true'
        elif not isinstance(is_malicious, bool):
            logger.error(
                f"LLM validation error: 'is_malicious' not boolean (type: {type(is_malicious)}, value: {is_malicious}). Full LLM JSON: {parsed_response}")
            raise ValueError(
                f"'is_malicious' not boolean (got {type(is_malicious)}).")

        confidence_val = 0.7
        try:
            confidence_val = float(parsed_response.get("confidence", 0.7))
        except (ValueError, TypeError):
            logger.warning(
                f"LLM returned invalid confidence '{parsed_response.get('confidence')}', using 0.7.")
        confidence_val = max(0.0, min(1.0, confidence_val))

        if state.failure_count > 0:
            logger.info("LLM Circuit Breaker: Connection successful.")
        state.failure_count = 0
        state.is_open = False

        if is_malicious:
            severity = str(parsed_response.get("severity", "MEDIUM")).upper()
            if severity not in settings.SEVERITY_WEIGHTS and severity != "NONE":
                logger.warning(
                    f"LLM invalid severity '{severity}', using MEDIUM.")
                severity = "MEDIUM"
            if severity == "NONE":
                return None
            attack_type = str(parsed_response.get("attack_type", "AI Anomaly"))
            reason = str(parsed_response.get(
                "reason", "AI detected activity."))
            logger.info(
                f"LLM detected malicious: Type='{attack_type}', Severity='{severity}', Conf='{confidence_val}'")
            return {"is_attack": True, "attack_type": attack_type, "reason": reason, "severity": severity, "confidence": confidence_val}
        else:
            logger.debug("LLM classified event as benign.")
            return None

    except httpx.TimeoutException:
        error_msg = f"Request to {ollama_url} timed out (30s)."
    except httpx.ConnectError as e:
        error_msg = f"Connection error to {settings.OLLAMA_URL}: {e}."
    except httpx.HTTPStatusError as e:
        error_msg = f"LLM request failed: Status={e.response.status_code}, Error='{e}'"
    except httpx.RequestError as e:
        error_msg = f"LLM request failed: {type(e).__name__} - {e}"
    except (json.JSONDecodeError, ValueError) as e:
        error_msg = str(e)
    except Exception as e:
        error_msg = f"Unexpected error: {type(e).__name__} - {e}"
        logger.error(f"Unexpected LLM error: {e}", exc_info=True)

    logger.warning(f"LLM detection failed: {error_msg}")
    state.failure_count += 1
    state.last_failure_time = now
    state.last_error = error_msg
    if state.failure_count >= settings.LLM_MAX_FAILURES and not state.is_open:
        logger.error(
            f"LLM Circuit Breaker: TRIPPING circuit for {settings.LLM_COOLDOWN_SECONDS}s. Last error: {error_msg}")
        state.is_open = True
    elif not state.is_open:
        logger.warning(
            f"LLM failure count: {state.failure_count}/{settings.LLM_MAX_FAILURES}.")
    return None

# --- Card Testing Detection (Unchanged) ---


async def detect_card_testing(event: EventData) -> Optional[Dict]:
    if event.event_type != "payment_failure":
        return None
    now = time.time()
    ip = event.source_ip
    card_identifier = event.data.get(
        "payment_token") or event.data.get("card_bin")
    if not (ip and card_identifier):
        return None
    log = app_state.card_failure_log[ip]
    log.append((now, card_identifier))
    cutoff_time = now - 300
    while log and log[0][0] < cutoff_time:
        log.popleft()
    unique_cards_tried = len({identifier for _, identifier in log})
    if unique_cards_tried >= settings.CARD_TEST_THRESHOLD:
        logger.warning(
            f"Card Testing detected: IP {ip} tested {unique_cards_tried} identifiers.")
        return {"is_attack": True, "attack_type": "Card Testing", "reason": f"IP {ip} had {unique_cards_tried} payment failures for distinct cards/tokens in 5 min.", "severity": "CRITICAL", "confidence": 0.95}
    return None

# --- Brute Force Detection (Unchanged) ---


async def detect_brute_force(event: EventData) -> Optional[Dict]:
    if event.event_type != "login_failure":
        return None
    now = time.time()
    user_id = event.user_id
    ip = event.source_ip
    if not user_id:
        return None
    user_log = app_state.brute_force_log[user_id]
    user_log.append(now)
    cutoff_time = now - settings.ATO_TIME_WINDOW
    while user_log and user_log[0] < cutoff_time:
        user_log.popleft()
    failure_count = len(user_log)
    logger.debug(
        f"Brute force check: User '{user_id}' failure count {failure_count}/{settings.BRUTE_FORCE_THRESHOLD}.")
    if failure_count >= settings.BRUTE_FORCE_THRESHOLD:
        logger.warning(
            f"Brute Force detected: User '{user_id}' failed login {failure_count} times. Last IP: {ip}")
        return {"is_attack": True, "attack_type": "Brute Force", "reason": f"User '{user_id}' failed login {failure_count} times in {settings.ATO_TIME_WINDOW}s.", "severity": "HIGH", "confidence": 0.90}
    return None

# --- DoS/DDoS Detection (Unchanged) ---


async def detect_dos_ddos(event: EventData) -> Optional[Dict]:
    now = time.time()
    cutoff = now - settings.TIME_WINDOW_SECONDS
    app_state.request_timestamps.append(now)
    while app_state.request_timestamps and app_state.request_timestamps[0] < cutoff:
        app_state.request_timestamps.popleft()
    global_request_count = len(app_state.request_timestamps)
    ip = event.source_ip
    active_ips_count = 0
    if ip:
        ip_log = app_state.ip_request_log[ip]
        ip_log.append(now)
        while ip_log and ip_log[0] < cutoff:
            ip_log.popleft()
        if random.randint(1, 100) == 1:
            ips_to_remove = [
                k for k, v in app_state.ip_request_log.items() if not v or v[-1] < cutoff]
            [app_state.ip_request_log.pop(inactive_ip, None)
             for inactive_ip in ips_to_remove]
        active_ips_count = sum(
            1 for log in app_state.ip_request_log.values() if log and log[-1] >= cutoff)
    if global_request_count > settings.DOS_ATTACK_THRESHOLD:
        if app_state.dos_attack_in_progress:
            return None
        app_state.dos_attack_in_progress = True
        attack_type = "DDoS" if active_ips_count > settings.DDOS_IP_THRESHOLD else "DoS"
        reason = f"Threshold exceeded: {global_request_count} req/{settings.TIME_WINDOW_SECONDS}s from {active_ips_count} IPs."
        logger.critical(f"--- {attack_type} DETECTED --- : {reason}")
        return {"is_attack": True, "attack_type": attack_type, "reason": reason, "severity": "CRITICAL", "confidence": 0.90}
    else:
        if app_state.dos_attack_in_progress:
            logger.info(
                f"--- DoS/DDoS Cooldown --- : Rate dropped below threshold ({global_request_count} req/{settings.TIME_WINDOW_SECONDS}s).")
            app_state.dos_attack_in_progress = False
    return None

# --- Detector Pipeline (Unchanged) ---
DETECTOR_PIPELINE: List[Callable[[EventData], Awaitable[Optional[Dict]]]] = [
    detect_dos_ddos,
    detect_card_testing,
    detect_brute_force,
    detect_llm_anomaly,
]

# --- Risk Score Calculation (Unchanged) ---


def calculate_risk_score(event: EventData, detections: List[Dict]) -> RiskScore:
    if not detections:
        return RiskScore(score=0.0, factors=[], severity="NONE")
    total_weighted_score = 0
    highest_severity_level = 0
    factors = set()
    for d in detections:
        severity = d.get("severity", "LOW")
        confidence = d.get("confidence", 0.5)
        weight = settings.SEVERITY_WEIGHTS.get(severity, 0)
        total_weighted_score += confidence * weight
        factors.add(d['attack_type'])
        highest_severity_level = max(highest_severity_level, weight)
    max_weight = settings.SEVERITY_WEIGHTS.get("CRITICAL", 5)
    normalized_score = min(total_weighted_score /
                           max_weight, 1.0) if max_weight > 0 else 0.0
    if highest_severity_level == settings.SEVERITY_WEIGHTS["CRITICAL"]:
        final_severity = "CRITICAL"
        normalized_score = max(normalized_score, 0.8)
    elif highest_severity_level == settings.SEVERITY_WEIGHTS["HIGH"]:
        final_severity = "HIGH"
        normalized_score = max(normalized_score, 0.6)
    elif highest_severity_level == settings.SEVERITY_WEIGHTS["MEDIUM"]:
        final_severity = "MEDIUM"
    elif highest_severity_level == settings.SEVERITY_WEIGHTS["LOW"]:
        final_severity = "LOW"
    else:
        final_severity = "NONE"
    return RiskScore(score=round(normalized_score, 2), factors=list(factors), severity=final_severity)

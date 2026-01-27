# app/state.py
from dataclasses import dataclass, field
from typing import Optional, Dict, Deque, Any
from collections import deque, defaultdict
import httpx


@dataclass
class LLMCircuitState:
    is_open: bool = False
    failure_count: int = 0


@dataclass
class AppState:
    request_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=2000))
    error_event_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=2000))
    attack_history: Deque = field(default_factory=lambda: deque(maxlen=1000))
    rate_limited_ips: Dict[str, float] = field(default_factory=dict)
    ip_request_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100)))

    http_client: Optional[httpx.AsyncClient] = None
    # FIX: Use the proper dataclass to prevent AttributeError
    llm_circuit_state: LLMCircuitState = field(default_factory=LLMCircuitState)


app_state = AppState()

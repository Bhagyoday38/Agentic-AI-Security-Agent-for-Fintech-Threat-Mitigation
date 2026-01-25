# app/state.py
from typing import Optional, Dict, Deque, Set, Any
from dataclasses import dataclass, field
from collections import deque, defaultdict
import httpx


@dataclass
class LLMCircuitState:
    is_open: bool = False
    failure_count: int = 0


@dataclass
class AppState:
    rate_limited_ips: Dict[str, float] = field(default_factory=dict)
    ip_request_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100)))
    card_failure_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=20)))
    brute_force_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=20)))
    request_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=500))
    error_event_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=500))
    attack_history: Deque = field(default_factory=lambda: deque(maxlen=1000))

    # UI State Fix
    monitored_websites: Dict[str, Any] = field(default_factory=dict)
    website_incidents: Deque = field(default_factory=lambda: deque(maxlen=500))

    llm_circuit_state: LLMCircuitState = field(default_factory=LLMCircuitState)
    http_client: Optional[httpx.AsyncClient] = None


app_state = AppState()

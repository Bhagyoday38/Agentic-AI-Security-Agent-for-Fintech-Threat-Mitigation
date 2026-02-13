# app/state.py
from dataclasses import dataclass, field
from typing import Optional, Dict, Deque, Any, List
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

    # Missing Attributes fixed here:
    monitored_websites: Dict[str, Any] = field(default_factory=dict)
    active_monitoring_tasks: Dict[str, Any] = field(default_factory=dict)
    website_health_history: Dict[str, List] = field(
        default_factory=lambda: defaultdict(list))
    website_incidents: List[Dict] = field(default_factory=list)

    http_client: Optional[httpx.AsyncClient] = None
    llm_circuit_state: LLMCircuitState = field(default_factory=LLMCircuitState)


app_state = AppState()

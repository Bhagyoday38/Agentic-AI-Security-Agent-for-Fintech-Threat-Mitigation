# ai-security-agent/app/state.py
import asyncio
import threading
from typing import Optional, Dict, List, Deque, Set, Any
from dataclasses import dataclass, field
from collections import deque, defaultdict
import httpx


@dataclass
class LLMCircuitState:
    is_open: bool = False
    last_failure_time: float = 0.0
    failure_count: int = 0
    last_error: str = ""


@dataclass
class AppState:
    # Detection state
    rate_limited_ips: Dict[str, float] = field(default_factory=dict)
    ip_threat_blacklist: Set[str] = field(default_factory=set)
    brute_force_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=20)))
    request_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=500))
    error_event_timestamps: Deque = field(
        default_factory=lambda: deque(maxlen=500))
    ip_request_log: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100)))
    attack_history: Deque = field(default_factory=lambda: deque(maxlen=1000))

    # Monitoring state
    dos_attack_in_progress: bool = False
    monitored_websites: Dict[str, Any] = field(default_factory=dict)
    website_incidents: Deque = field(default_factory=lambda: deque(maxlen=500))
    website_health_history: Dict[str, Deque] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=100)))

    # System state
    llm_circuit_state: LLMCircuitState = field(default_factory=LLMCircuitState)
    http_client: Optional[httpx.AsyncClient] = None
    log_lock: threading.Lock = field(default_factory=threading.Lock)


app_state = AppState()

# app/state.py
import asyncio
from typing import Optional, Dict, Deque, Set
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

    dos_attack_in_progress: bool = False
    llm_circuit_state: LLMCircuitState = field(default_factory=LLMCircuitState)
    http_client: Optional[httpx.AsyncClient] = None


app_state = AppState()

from collections import deque

class AppState:
    def __init__(self):
        self.request_timestamps = deque()
        self.error_event_timestamps = deque()
        self.attack_history = []
        self.rate_limited_ips = {}

        self.llm_circuit_state = type("obj", (), {
            "is_open": False,
            "failure_count": 0
        })()

        self.http_client = None

app_state = AppState()
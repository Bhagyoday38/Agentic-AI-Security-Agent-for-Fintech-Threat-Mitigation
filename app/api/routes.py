from fastapi import APIRouter, Request
import datetime
import random
import time

from ..state import app_state
from .websocket import broadcast_attack_event

router = APIRouter()


@router.post("/ingest")
async def ingest(request: Request):
    data = await request.json()

    # 🔥 Simulated ML prediction (replace with your model)
    prediction = random.choice(["Normal", "DDoS", "Phishing", "Malware"])
    severity = random.choice(["Low", "Medium", "High"])

    attack_event = {
        "timestamp": str(datetime.datetime.now()),
        "source_ip": data.get("ip", "Unknown"),
        "attack_type": data.get("attack", "Unknown"),
        "prediction": prediction,
        "severity": severity
    }

    # ✅ Store for metrics
    app_state.attack_history.append(attack_event)
    app_state.request_timestamps.append(time.time())

    print("🚨 Attack:", attack_event)

    # 🔥 REAL-TIME PUSH
    await broadcast_attack_event(attack_event)

    return {"status": "processed", "data": attack_event}
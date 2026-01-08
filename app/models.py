# app/models.py
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class EventData(BaseModel):
    event_type: str
    user_id: Optional[str] = None
    data: Dict[str, Any] = {}
    source_ip: Optional[str] = None


class RiskScore(BaseModel):
    score: float
    factors: List[str]
    severity: str


class ReportRequest(BaseModel):
    trend_chart_img: str  # Base64 string
    severity_chart_img: str  # Base64 string

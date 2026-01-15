# ai-security-agent/app/models.py
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class EventData(BaseModel):
    event_type: str
    user_id: Optional[str] = None
    data: Dict[str, Any] = {}
    source_ip: Optional[str] = None


class WebsiteMonitorConfig(BaseModel):
    url: str
    check_interval: int = 300
    check_ssl: bool = True


class WebsiteHealth(BaseModel):
    url: str
    status: str
    response_time: float
    last_check: float
    ssl_days_remaining: Optional[int] = None
    errors: List[str] = []


class RiskScore(BaseModel):
    score: float
    factors: List[str]
    severity: str


class ReportRequest(BaseModel):
    trend_chart_img: str  # Base64 string
    severity_chart_img: str  # Base64 string

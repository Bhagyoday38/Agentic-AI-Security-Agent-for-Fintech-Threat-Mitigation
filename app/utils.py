# app/utils.py
import json
import logging
import os
from .config import settings

logger = logging.getLogger("Runner." + __name__)

GEOLOCATION_ENABLED = False
try:
    from ip2geotools.databases.noncommercial import DbIpCity
    GEOLOCATION_ENABLED = True
except (ImportError, ModuleNotFoundError):
    logger.warning(
        "ip2geotools not detected in current path. Geolocation disabled.")


async def get_location_from_ip(ip: str):
    if not GEOLOCATION_ENABLED or ip in ["127.0.0.1", "localhost", "WEBSITE_MONITOR"]:
        return {"city": "Unknown", "country": "Local"}
    try:
        res = DbIpCity.get(ip, api_key='free')
        return {"city": res.city, "country": res.country}
    except Exception:
        return {"city": "Unknown", "country": "Unknown"}


def log_secure_attack_event(event_report: dict):
    file_path = settings.LOG_JSON_FILE
    try:
        logs = []
        if os.path.exists(file_path):
            with open(file_path, "r", encoding='utf-8') as f:
                content = f.read()
                if content:
                    logs = json.loads(content)

        logs.append(event_report)
        # Keep last 1000 logs to prevent file bloat
        with open(file_path, "w", encoding='utf-8') as f:
            json.dump(logs[-1000:], f, indent=2)
    except Exception as e:
        logger.error(f"Failed to write to log file: {e}")

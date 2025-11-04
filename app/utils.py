# app/utils.py
import json
import hashlib
import logging
import asyncio
import os
from datetime import datetime, timezone
from typing import Dict, Set
import ipaddress
import re

from .config import settings
from .state import app_state

# --- FIX: Pylance errors for unbound imports ---
try:
    from ip2geotools.databases.noncommercial import DbIpCity
    from ip2geotools.errors import RateLimited, InvalidRequest, IpAddressNotFoundError
    IP2GEOTOOLS_AVAILABLE = True
except ImportError:
    IP2GEOTOOLS_AVAILABLE = False
    logging.warning(
        "ip2geotools not installed. IP geolocation will be disabled.")
    # Define dummy classes to satisfy Pylance

    class DbIpCity:
        pass

    class RateLimited(Exception):
        pass

    class InvalidRequest(Exception):
        pass

    class IpAddressNotFoundError(Exception):
        pass
# --- END FIX ---

logger = logging.getLogger("Runner." + __name__)

_geolocation_error_cache: Set[str] = set()


def mask_pii(data: Dict) -> Dict:
    if not isinstance(data, dict):
        return data
    masked_data = data.copy()
    for field_name in masked_data.keys():
        if field_name in settings.PII_FIELDS:
            masked_data[field_name] = "[MASKED]"
        elif field_name == "card_number" and isinstance(masked_data.get(field_name), str) and len(masked_data[field_name]) > 4:
            masked_data[field_name] = f"XXXX-XXXX-XXXX-{masked_data[field_name][-4:]}"
        elif field_name in settings.PAYMENT_FIELDS and isinstance(masked_data.get(field_name), str) and len(masked_data[field_name]) > 8:
            masked_data[field_name] = f"{masked_data[field_name][:4]}...[MASKED]"
    return masked_data


async def get_location_from_ip(ip: str) -> dict:
    default_location = {"city": "Unknown",
                        "country": "Unknown", "lat": 0.0, "lon": 0.0}
    local_location = {"city": "Local",
                      "country": "Local", "lat": 0.0, "lon": 0.0}

    if not ip or not isinstance(ip, str) or ip in ["unknown"]:
        return default_location
    if ip in ["localhost", "127.0.0.1", "::1"]:
        return local_location

    # --- FIX: Check if IP is private ---
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            # logger.debug(f"Skipping geolocation for private/loopback IP: {ip}")
            return {"city": "Private IP", "country": "N/A", "lat": 0.0, "lon": 0.0}
    except ValueError:
        logger.warning(f"Skipping geolocation for invalid IP format: {ip}")
        return default_location
    # --- END FIX ---

    if not IP2GEOTOOLS_AVAILABLE:
        return default_location

    try:
        # --- FIX: Use the correctly imported DbIpCity ---
        res = await asyncio.to_thread(DbIpCity.get, ip, api_key="free")
        lat = float(res.latitude) if res.latitude is not None else 0.0
        lon = float(res.longitude) if res.longitude is not None else 0.0
        return {"city": res.city or "Unknown", "country": res.country or "Unknown", "lat": lat, "lon": lon}

    # --- FIX: Use correct exception names ---
    except (RateLimited, InvalidRequest) as e:
        if ip not in _geolocation_error_cache:
            logger.warning(
                f"IP Geolocation for {ip} failed: service limits/request issue ({type(e).__name__}).")
            _geolocation_error_cache.add(ip)
        return default_location
    # --- END FIX ---
    except (ConnectionError, IpAddressNotFoundError) as e:  # Catch connection errors & not found
        logger.warning(f"IP Geolocation for {ip} failed: {type(e).__name__}")
        return default_location
    except Exception as e:
        logger.warning(
            f"IP Geolocation for {ip} failed unexpectedly: {type(e).__name__} - {e}")
        return default_location


def log_secure_attack_event(event: dict):
    if "timestamp" not in event:
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
    log_entry = event.copy()
    if "data" in log_entry and isinstance(log_entry["data"], dict):
        log_entry["data"] = mask_pii(log_entry["data"])
    log_entry = mask_pii(log_entry)
    try:
        log_data_bytes = json.dumps(
            log_entry, sort_keys=True, default=str).encode('utf-8')
        log_entry["integrity_hash"] = hashlib.sha256(
            log_data_bytes).hexdigest()
    except Exception as e:
        logger.error(f"Failed to create integrity hash: {e}")
        log_entry["integrity_hash"] = "hash_error"
    log_file = settings.LOG_JSON_FILE
    with app_state.log_lock:
        try:
            attack_log = []
            if os.path.exists(log_file):
                with open(log_file, "r", encoding='utf-8') as f:
                    content = f.read()
                if content:
                    try:
                        attack_log = json.loads(content)
                    except json.JSONDecodeError:
                        logger.warning(f"Log {log_file} corrupt, resetting.")
                        attack_log = []
                if not isinstance(attack_log, list):
                    logger.warning(f"Log {log_file} not list, resetting.")
                    attack_log = []
            attack_log.append(log_entry)
            with open(log_file, "w", encoding='utf-8') as f:
                json.dump(attack_log, f, indent=2, default=str)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed write attack log {log_file}: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error writing attack log {log_file}: {e}", exc_info=True)

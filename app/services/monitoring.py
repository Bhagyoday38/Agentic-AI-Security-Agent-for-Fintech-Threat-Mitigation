# app/services/monitoring.py
# (Keep the code exactly as it was)
import asyncio
import time
import logging
import ssl
import socket
from datetime import datetime, timezone
import httpx
import random
import traceback
from typing import Optional

from ..config import settings
from ..state import app_state
from ..models import WebsiteMonitorConfig, WebsiteHealth
from ..utils import log_secure_attack_event
from .notifications import notify_alerts
from ..api.websocket import manager

logger = logging.getLogger(__name__)


class AdvancedWebsiteMonitorManager:
    """Manages website health checks."""

    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        ]

    def get_random_headers(self):
        return {'User-Agent': random.choice(self.user_agents), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9', 'Connection': 'keep-alive', }

    async def check_website_health(self, config: WebsiteMonitorConfig) -> WebsiteHealth:
        health = WebsiteHealth(
            url=config.url, status="PENDING", response_time=-1, last_check=time.time())
        if not app_state.http_client:
            health.status = "ERROR"
            health.errors.append("HTTP Client unavailable.")
            logger.error("Monitor check failed: HTTP client missing.")
            return health

        try:
            start_time = time.time()
            response = await app_state.http_client.get(config.url, headers=self.get_random_headers(), timeout=20.0, follow_redirects=True)
            health.response_time = (time.time() - start_time) * 1000
            response.raise_for_status()
            health.status = "HEALTHY"
        except httpx.TimeoutException:
            health.status = "TIMEOUT"
            health.errors.append("Request timed out (20s).")
            logger.warning(f"Monitor {config.url}: TIMEOUT")
        except httpx.ConnectError as e:
            health.status = "CONNECTION_ERROR"
            health.errors.append(f"Connection failed: {e}")
            logger.warning(f"Monitor {config.url}: CONNECTION_ERROR - {e}")
        except httpx.HTTPStatusError as e:
            health.status = f"HTTP_{e.response.status_code}"
            health.errors.append(f"HTTP error: {e.response.status_code}")
            logger.warning(
                f"Monitor {config.url}: HTTP_{e.response.status_code}")
        except httpx.RequestError as e:
            health.status = "REQUEST_ERROR"
            health.errors.append(f"Request failed: {e}")
            logger.error(f"Monitor {config.url}: REQUEST_ERROR - {e}")
        except Exception as e:
            health.status = "MONITORING_ERROR"
            health.errors.append(f"Unexpected error: {e}")
            logger.error(f"Monitor error {config.url}: {e}", exc_info=True)

        if config.url.startswith('https://') and config.check_ssl and health.status not in ["CONNECTION_ERROR", "REQUEST_ERROR", "MONITORING_ERROR"]:
            try:
                await asyncio.to_thread(self.analyze_ssl_cert, health, config)
            except Exception as e:
                health.errors.append(f"SSL check thread failed: {e}")
                logger.error(f"SSL check thread fail {config.url}: {e}")
        health.last_check = time.time()
        return health

    def analyze_ssl_cert(self, health: WebsiteHealth, config: WebsiteMonitorConfig):
        try:
            hostname = config.url.split('/')[2]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert and 'notAfter' in cert:
                        expiry_date = datetime.strptime(
                            str(cert['notAfter']), '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        days_remaining = (
                            expiry_date - datetime.now(timezone.utc)).days
                        health.ssl_days_remaining = days_remaining
                        if days_remaining < 0:
                            health.errors.append("SSL certificate EXPIRED.")
                            logger.warning(f"SSL {config.url}: EXPIRED")
                        elif days_remaining < settings.SSL_EXPIRY_WARNING:
                            health.errors.append(
                                f"SSL expires in {days_remaining} days.")
                            logger.warning(
                                f"SSL {config.url}: Expires soon ({days_remaining} days)")
                    else:
                        health.errors.append(
                            "Could not retrieve SSL cert details.")
                        logger.warning(f"SSL {config.url}: No cert details.")
        except socket.timeout:
            health.errors.append("SSL check timed out.")
            logger.warning(f"SSL {config.url}: Timeout")
        except ssl.SSLError as e:
            health.errors.append(f"SSL error: {e}")
            logger.warning(f"SSL {config.url}: SSLError - {e}")
        except socket.gaierror as e:
            health.errors.append(f"DNS resolution failed for SSL: {e}")
            logger.warning(f"SSL {config.url}: DNS Error - {e}")
        except Exception as e:
            health.errors.append(f"SSL analysis failed: {e}")
            logger.error(f"SSL Check error {config.url}: {e}", exc_info=True)

    def analyze_website_anomalies(self, health: WebsiteHealth) -> Optional[dict]:
        anomalies = []
        if health.status != "HEALTHY":
            reason = health.errors[0] if health.errors else f"Status: {health.status}"
            severity = "CRITICAL" if "5" in health.status or "TIMEOUT" in health.status or "CONNECTION" in health.status else "HIGH"
            anomalies.append(
                {"type": "AVAILABILITY", "reason": reason, "severity": severity})
        if health.ssl_days_remaining is not None:
            if health.ssl_days_remaining < 0:
                anomalies.append(
                    {"type": "SSL_EXPIRED", "reason": "SSL expired.", "severity": "CRITICAL"})
            elif health.ssl_days_remaining < 7:
                anomalies.append({"type": "SSL_EXPIRING_CRITICAL",
                                 "reason": f"SSL expires in {health.ssl_days_remaining} days.", "severity": "CRITICAL"})
            elif health.ssl_days_remaining < settings.SSL_EXPIRY_WARNING:
                anomalies.append(
                    {"type": "SSL_EXPIRING_WARN", "reason": f"SSL expires in {health.ssl_days_remaining} days.", "severity": "HIGH"})
        if any("SSL error" in e for e in health.errors):
            anomalies.append(
                {"type": "SSL_CONFIG_ERROR", "reason": "SSL config issue.", "severity": "HIGH"})
        if not anomalies:
            return None
        highest_anomaly = max(
            anomalies, key=lambda x: settings.SEVERITY_WEIGHTS.get(x['severity'], 0))
        logger.warning(
            f"Anomaly {health.url}: {highest_anomaly['type']} ({highest_anomaly['severity']}) - {highest_anomaly['reason']}")
        return {"is_attack": True, "attack_type": f"WEBSITE_{highest_anomaly['type']}", "reason": highest_anomaly['reason'], "severity": highest_anomaly['severity'], "confidence": 0.95}


website_monitor_manager = AdvancedWebsiteMonitorManager()


async def monitor_website_task(url: str, config: WebsiteMonitorConfig):
    logger.info(
        f"Starting monitor task: {url} (Interval: {config.check_interval}s)")
    while url in app_state.monitored_websites:
        try:
            health = await website_monitor_manager.check_website_health(config)
            app_state.website_health_history[url].append(health)
            await manager.broadcast({"type": "website_update", "website": {"url": url, "current_health": health.model_dump() if hasattr(health, 'model_dump') else health.dict()}})
            incident_info = website_monitor_manager.analyze_website_anomalies(
                health)
            if incident_info:
                incident_report = {**incident_info, "url": url, "ip": "WEBSITE_MONITOR",
                                   "timestamp": datetime.now(timezone.utc).isoformat()}
                log_secure_attack_event(incident_report)
                app_state.website_incidents.append(incident_report)
                await notify_alerts(incident_report)
                await manager.broadcast({"type": "attack_detected", **incident_report})
            await asyncio.sleep(max(15, config.check_interval))
        except asyncio.CancelledError:
            logger.info(f"Monitor task cancelled: {url}")
            break
        except Exception as e:
            logger.error(
                f"Monitor loop error {url}: {e}\n{traceback.format_exc()}")
            await asyncio.sleep(60)
    logger.info(f"Stopping monitor task: {url}")


async def start_website_monitoring(url: str, config: WebsiteMonitorConfig):
    if url in app_state.active_monitoring_tasks:
        logger.info(f"Restarting monitor: {url}")
        await stop_website_monitoring(url)
    app_state.monitored_websites[url] = config
    task = asyncio.create_task(monitor_website_task(
        url, config), name=f"monitor_{url}")
    app_state.active_monitoring_tasks[url] = task
    logger.info(f"Scheduled monitor: {url}")
    return {"status": "monitoring_started", "url": url}


async def stop_website_monitoring(url: str):
    task = app_state.active_monitoring_tasks.pop(url, None)
    app_state.monitored_websites.pop(url, None)
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=5.0)
            logger.info(f"Monitor task cancelled: {url}")
        except asyncio.CancelledError:
            logger.info(f"Monitor task already cancelled: {url}")
        except asyncio.TimeoutError:
            logger.warning(f"Monitor task {url} did not cancel promptly.")
        except Exception as e:
            logger.error(f"Error cancelling task {url}: {e}")
    return {"status": "monitoring_stopped", "url": url}


async def stop_all_monitoring():
    urls_to_stop = list(app_state.active_monitoring_tasks.keys())
    logger.info(f"Stopping all {len(urls_to_stop)} monitors...")
    await asyncio.gather(*(stop_website_monitoring(url) for url in urls_to_stop))
    logger.info("All monitors stopped.")

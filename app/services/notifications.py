# app/services/notifications.py
import asyncio
import logging
from datetime import datetime, timezone
import httpx
from typing import Dict

# Import necessary components
from ..config import settings
from ..state import app_state


async def notify_alerts(attack_info: Dict):
    """Sends notifications for high/critical alerts."""
    severity = attack_info.get('severity')
    if severity not in ['CRITICAL', 'HIGH']:
        return  # Only notify for significant events

    # Run notification tasks concurrently
    tasks = []
    if settings.SLACK_WEBHOOK_URL:
        tasks.append(send_slack_alert(attack_info))
    if settings.DISCORD_WEBHOOK_URL:
        tasks.append(send_discord_alert(attack_info))
    # Add other notification channels here

    if tasks:
        await asyncio.gather(*tasks)


async def send_slack_alert(attack_info: Dict):
    """Sends a formatted alert to Slack."""
    if not app_state.http_client:
        logging.warning("Slack alert skipped: HTTP client not ready.")
        return

    # Create richer Slack message using blocks
    message = {
        # Fallback text
        "text": f"Security Alert: {attack_info.get('attack_type', 'Unknown')} ({attack_info.get('severity', 'N/A')})",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f":warning: Security Alert: {attack_info.get('severity', 'N/A')}", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn",
                        "text": f"*Type:*\n`{attack_info.get('attack_type', 'Unknown')}`"},
                    {"type": "mrkdwn",
                        "text": f"*Source IP:*\n{attack_info.get('ip', 'N/A')}"},
                    {"type": "mrkdwn",
                        "text": f"*Timestamp (UTC):*\n{attack_info.get('timestamp', 'N/A')}"},
                    {"type": "mrkdwn",
                        "text": f"*URL (if applicable):*\n{attack_info.get('url', 'N/A')}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Reason:*\n_{attack_info.get('reason', 'No specific reason provided.')}_"}
            },
            {"type": "divider"}
        ]
    }
    try:
        response = await app_state.http_client.post(settings.SLACK_WEBHOOK_URL, json=message, timeout=10.0)
        response.raise_for_status()
        logging.info(f"Slack alert sent for {attack_info.get('attack_type')}")
    except httpx.RequestError as e:
        logging.error(f"Failed to send Slack alert: {e}")
    except Exception as e:
        # Keep log concise
        logging.error(
            f"Unexpected error sending Slack alert: {e}", exc_info=False)


async def send_discord_alert(attack_info: Dict):
    """Sends a formatted alert to Discord using embeds."""
    if not app_state.http_client:
        logging.warning("Discord alert skipped: HTTP client not ready.")
        return

    # Map severity to color
    color_map = {"CRITICAL": 15158332, "HIGH": 15844367,
                 "MEDIUM": 16776960, "LOW": 5763719}
    severity = attack_info.get('severity', 'UNKNOWN')
    # Default to grey if unknown
    embed_color = color_map.get(severity, 10070709)

    embed = {
        "title": f":warning: Security Alert: {attack_info.get('severity', 'N/A')}",
        "description": f"**Type:** `{attack_info.get('attack_type', 'Unknown')}`",
        "color": embed_color,
        "fields": [
            {"name": "Source IP", "value": attack_info.get(
                'ip', 'N/A'), "inline": True},
            {"name": "Location",
                "value": f"{attack_info.get('city', 'N/A')}, {attack_info.get('country', 'N/A')}", "inline": True},
            {"name": "URL", "value": attack_info.get(
                # Only inline if URL exists
                'url', 'N/A'), "inline": True if attack_info.get('url') else False},
            {"name": "Reason", "value": attack_info.get(
                'reason', 'No specific reason provided.'), "inline": False},
        ],
        # Use event timestamp or now
        "timestamp": attack_info.get('timestamp', datetime.now(timezone.utc).isoformat())
    }
    message = {"embeds": [embed]}

    try:
        response = await app_state.http_client.post(settings.DISCORD_WEBHOOK_URL, json=message, timeout=10.0)
        response.raise_for_status()
        logging.info(
            f"Discord alert sent for {attack_info.get('attack_type')}")
    except httpx.RequestError as e:
        logging.error(f"Failed to send Discord alert: {e}")
    except Exception as e:
        # Keep log concise
        logging.error(
            f"Unexpected error sending Discord alert: {e}", exc_info=False)

"""Notification service for alerts and updates."""
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    SMS = "sms"


class NotificationPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Notification:
    """Notification message."""
    id: str
    title: str
    message: str
    priority: NotificationPriority
    channels: List[NotificationChannel]
    source: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict = field(default_factory=dict)
    read: bool = False


class NotificationService:
    """Multi-channel notification service."""
    
    def __init__(self):
        self._channels: Dict[NotificationChannel, Dict] = {}
        self._history: List[Notification] = []
        self._max_history = 1000
        self._handlers: Dict[NotificationChannel, Callable] = {}
        
        self._register_default_handlers()
    
    def register_channel(self, channel: NotificationChannel, config: Dict):
        """Register a notification channel with configuration."""
        self._channels[channel] = config
        logger.info(f"Registered notification channel: {channel.value}")
    
    async def send(self, title: str, message: str, priority: NotificationPriority = NotificationPriority.MEDIUM,
                   channels: Optional[List[NotificationChannel]] = None,
                   source: str = "platform", metadata: Optional[Dict] = None) -> Dict:
        """Send a notification through specified channels."""
        import uuid
        
        notification = Notification(
            id=str(uuid.uuid4()),
            title=title,
            message=message,
            priority=priority,
            channels=channels or list(self._channels.keys()),
            source=source,
            metadata=metadata or {},
        )
        
        results = {}
        for channel in notification.channels:
            if channel in self._channels:
                try:
                    handler = self._handlers.get(channel)
                    if handler:
                        result = await handler(self._channels[channel], notification)
                        results[channel.value] = {"sent": True, "result": result}
                    else:
                        results[channel.value] = {"sent": False, "error": "No handler registered"}
                except Exception as e:
                    logger.error(f"Failed to send notification via {channel.value}: {e}")
                    results[channel.value] = {"sent": False, "error": str(e)}
            else:
                results[channel.value] = {"sent": False, "error": "Channel not configured"}
        
        # Add to history
        self._history.append(notification)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
        
        return {
            "notification_id": notification.id,
            "priority": priority.value,
            "channels": results,
            "all_sent": all(r.get("sent") for r in results.values()),
        }
    
    async def send_alert(self, finding: Dict, priority: Optional[NotificationPriority] = None) -> Dict:
        """Send an alert for a security finding."""
        severity_str = finding.get("severity", "medium").lower()
        priority_map = {
            "critical": NotificationPriority.CRITICAL,
            "high": NotificationPriority.HIGH,
            "medium": NotificationPriority.MEDIUM,
            "low": NotificationPriority.LOW,
        }
        alert_priority = priority or priority_map.get(severity_str, NotificationPriority.MEDIUM)
        
        return await self.send(
            title=f"Security Alert: {finding.get('title', 'Unknown Finding')}",
            message=f"Severity: {severity_str.upper()}\nTarget: {finding.get('target', 'Unknown')}\n{finding.get('description', '')[:500]}",
            priority=alert_priority,
            channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL] if alert_priority in (NotificationPriority.CRITICAL, NotificationPriority.HIGH) else [NotificationChannel.SLACK],
            source="security_scan",
            metadata={"finding_id": finding.get("id"), "target": finding.get("target")},
        )
    
    def _register_default_handlers(self):
        """Register default channel handlers."""
        self._handlers[NotificationChannel.EMAIL] = self._handle_email
        self._handlers[NotificationChannel.SLACK] = self._handle_slack
        self._handlers[NotificationChannel.TEAMS] = self._handle_teams
        self._handlers[NotificationChannel.DISCORD] = self._handle_discord
        self._handlers[NotificationChannel.PAGERDUTY] = self._handle_pagerduty
        self._handlers[NotificationChannel.WEBHOOK] = self._handle_webhook
        self._handlers[NotificationChannel.SMS] = self._handle_sms
    
    async def _handle_email(self, config: Dict, notification: Notification) -> Dict:
        """Send email notification via SMTP."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        smtp_host = config.get("host", "localhost")
        smtp_port = config.get("port", 587)
        username = config.get("username", "")
        password = config.get("password", "")
        use_tls = config.get("use_tls", True)
        from_addr = config.get("from", "noreply@cybersecurity-platform.local")
        to_addrs = config.get("to", [])
        
        if not to_addrs:
            return {"sent": False, "error": "No recipients configured"}
        
        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = f"[{notification.priority.value.upper()}] {notification.title}"
        
        body = f"""
Priority: {notification.priority.value.upper()}
Source: {notification.source}
Time: {notification.timestamp.isoformat()}

{notification.message}

---
Cybersecurity Platform Notification
"""
        
        msg.attach(MIMEText(body, "plain"))
        
        try:
            server = smtplib.SMTP(smtp_host, smtp_port)
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.send_message(msg)
            server.quit()
            return {"sent": True, "recipients": len(to_addrs)}
        except Exception as e:
            raise Exception(f"SMTP error: {e}")
    
    async def _handle_slack(self, config: Dict, notification: Notification) -> Dict:
        """Send Slack notification via webhook."""
        import httpx
        
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            return {"sent": False, "error": "No webhook URL configured"}
        
        # Determine color based on priority
        color_map = {
            NotificationPriority.CRITICAL: "#FF0000",
            NotificationPriority.HIGH: "#FF6600",
            NotificationPriority.MEDIUM: "#FFCC00",
            NotificationPriority.LOW: "#808080",
        }
        
        payload = {
            "attachments": [
                {
                    "color": color_map.get(notification.priority, "#808080"),
                    "title": notification.title,
                    "text": notification.message,
                    "fields": [
                        {"title": "Priority", "value": notification.priority.value.upper(), "short": True},
                        {"title": "Source", "value": notification.source, "short": True},
                        {"title": "Time", "value": notification.timestamp.isoformat(), "short": False},
                    ],
                    "footer": "Cybersecurity Platform",
                    "ts": notification.timestamp.timestamp(),
                }
            ]
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(webhook_url, json=payload)
            if response.status_code not in (200, 201, 204):
                raise Exception(f"Slack returned {response.status_code}")
        
        return {"sent": True, "channel": config.get("channel", "webhook")}
    
    async def _handle_teams(self, config: Dict, notification: Notification) -> Dict:
        """Send Microsoft Teams notification via webhook."""
        import httpx
        
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            return {"sent": False, "error": "No webhook URL configured"}
        
        color_map = {
            NotificationPriority.CRITICAL: "ff0000",
            NotificationPriority.HIGH: "ff6600",
            NotificationPriority.MEDIUM: "ffcc00",
            NotificationPriority.LOW: "808080",
        }
        
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_map.get(notification.priority, "808080"),
            "summary": notification.title,
            "sections": [
                {
                    "activityTitle": notification.title,
                    "activitySubtitle": f"Priority: {notification.priority.value.upper()} | Source: {notification.source}",
                    "text": notification.message,
                    "facts": [
                        {"name": "Priority", "value": notification.priority.value.upper()},
                        {"name": "Source", "value": notification.source},
                        {"name": "Time", "value": notification.timestamp.isoformat()},
                    ],
                }
            ],
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(webhook_url, json=payload)
            if response.status_code not in (200, 201, 204):
                raise Exception(f"Teams returned {response.status_code}")
        
        return {"sent": True}
    
    async def _handle_discord(self, config: Dict, notification: Notification) -> Dict:
        """Send Discord notification via webhook."""
        import httpx
        
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            return {"sent": False, "error": "No webhook URL configured"}
        
        color_map = {
            NotificationPriority.CRITICAL: 0xFF0000,
            NotificationPriority.HIGH: 0xFF6600,
            NotificationPriority.MEDIUM: 0xFFCC00,
            NotificationPriority.LOW: 0x808080,
        }
        
        payload = {
            "embeds": [
                {
                    "title": notification.title,
                    "description": notification.message,
                    "color": color_map.get(notification.priority, 0x808080),
                    "fields": [
                        {"name": "Priority", "value": notification.priority.value.upper(), "inline": True},
                        {"name": "Source", "value": notification.source, "inline": True},
                    ],
                    "footer": {"text": f"Cybersecurity Platform • {notification.timestamp.isoformat()}"},
                }
            ]
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(webhook_url, json=payload)
            if response.status_code not in (200, 201, 204):
                raise Exception(f"Discord returned {response.status_code}")
        
        return {"sent": True}
    
    async def _handle_pagerduty(self, config: Dict, notification: Notification) -> Dict:
        """Send PagerDuty alert via API."""
        import httpx
        
        api_key = config.get("api_key", "")
        service_id = config.get("service_id", "")
        routing_key = config.get("routing_key", "")
        
        if not routing_key:
            return {"sent": False, "error": "No routing key configured"}
        
        severity_map = {
            NotificationPriority.CRITICAL: "critical",
            NotificationPriority.HIGH: "error",
            NotificationPriority.MEDIUM: "warning",
            NotificationPriority.LOW: "info",
        }
        
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": notification.title[:1024],
                "severity": severity_map.get(notification.priority, "info"),
                "source": notification.source,
                "custom_details": {
                    "message": notification.message,
                    "priority": notification.priority.value,
                    "notification_id": notification.id,
                },
            },
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                headers={"Authorization": f"Token token={api_key}"} if api_key else {},
            )
            if response.status_code not in (200, 201, 202):
                raise Exception(f"PagerDuty returned {response.status_code}")
        
        return {"sent": True, "dedup_key": response.json().get("dedup_key", "")}
    
    async def _handle_webhook(self, config: Dict, notification: Notification) -> Dict:
        """Send generic webhook notification."""
        import httpx
        
        url = config.get("url", "")
        headers = config.get("headers", {})
        
        payload = {
            "id": notification.id,
            "title": notification.title,
            "message": notification.message,
            "priority": notification.priority.value,
            "source": notification.source,
            "timestamp": notification.timestamp.isoformat(),
            "metadata": notification.metadata,
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code not in (200, 201, 202, 204):
                raise Exception(f"Webhook returned {response.status_code}")
        
        return {"sent": True}
    
    async def _handle_sms(self, config: Dict, notification: Notification) -> Dict:
        """Send SMS notification via Twilio-like API."""
        import httpx
        
        account_sid = config.get("account_sid", "")
        auth_token = config.get("auth_token", "")
        from_number = config.get("from_number", "")
        to_numbers = config.get("to_numbers", [])
        
        if not to_numbers:
            return {"sent": False, "error": "No recipients configured"}
        
        sent_count = 0
        for to_number in to_numbers:
            try:
                payload = {
                    "From": from_number,
                    "To": to_number,
                    "Body": f"[{notification.priority.value.upper()}] {notification.title[:100]}: {notification.message[:150]}",
                }
                
                async with httpx.AsyncClient(timeout=15.0) as client:
                    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
                    response = await client.post(url, data=payload, auth=(account_sid, auth_token))
                    if response.status_code == 201:
                        sent_count += 1
            except Exception as e:
                logger.error(f"Failed to send SMS to {to_number}: {e}")
        
        return {"sent": sent_count > 0, "recipients": sent_count}
    
    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get notification history."""
        return [n.__dict__ for n in self._history[-limit:]]
    
    def mark_read(self, notification_id: str) -> bool:
        """Mark a notification as read."""
        for notification in self._history:
            if notification.id == notification_id:
                notification.read = True
                return True
        return False

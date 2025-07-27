# =============================================================================
# NOTIFICATION ENGINE MODULE
# =============================================================================
"""
Advanced notification engine for the Cyber Threat Monitoring System.
Handles email, Slack, and webhook notifications with alerting logic.
"""

import asyncio
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from ctms.core.config import settings
from ctms.core.logger import get_logger
from ctms.database.models import Alert, SeverityLevel, AlertStatus
from ctms.database.connection import get_database

logger = get_logger(__name__)


# =============================================================================
# NOTIFICATION TYPES AND CONFIGURATIONS
# =============================================================================
class NotificationType(str, Enum):
    """Types of notifications."""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"


@dataclass
class NotificationChannel:
    """Notification channel configuration."""
    name: str
    type: NotificationType
    enabled: bool
    config: Dict[str, Any]
    severity_filter: List[SeverityLevel] = None
    
    def __post_init__(self):
        if self.severity_filter is None:
            self.severity_filter = list(SeverityLevel)


@dataclass
class NotificationMessage:
    """Notification message structure."""
    title: str
    content: str
    severity: SeverityLevel
    alert_id: str
    timestamp: datetime
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


# =============================================================================
# EMAIL NOTIFICATION HANDLER
# =============================================================================
class EmailNotificationHandler:
    """
    Handles email notifications with SMTP support.
    Supports HTML and plain text emails with attachments.
    """
    
    def __init__(self):
        """Initialize email handler."""
        self.smtp_server = settings.smtp_server
        self.smtp_port = settings.smtp_port
        self.username = settings.smtp_username
        self.password = settings.smtp_password
        self.from_email = settings.alert_from_email or settings.smtp_username
        
    async def send_notification(
        self,
        message: NotificationMessage,
        channel: NotificationChannel
    ) -> bool:
        """
        Send email notification.
        
        Args:
            message: Notification message
            channel: Email channel configuration
            
        Returns:
            bool: True if successful
        """
        try:
            # Get recipient configuration
            recipients = channel.config.get("recipients", [])
            if not recipients:
                logger.warning("No email recipients configured")
                return False
            
            # Create email message
            email_msg = self._create_email_message(message, recipients)
            
            # Send email
            await self._send_email(email_msg, recipients)
            
            logger.info(f"✅ Email notification sent for alert {message.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send email notification: {e}")
            return False
    
    def _create_email_message(
        self,
        message: NotificationMessage,
        recipients: List[str]
    ) -> MIMEMultipart:
        """
        Create formatted email message.
        
        Args:
            message: Notification message
            recipients: Email recipients
            
        Returns:
            MIMEMultipart: Email message
        """
        # Create multipart message
        msg = MIMEMultipart('alternative')
        
        # Email headers
        msg['From'] = self.from_email
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = f"[CTMS Alert] {message.title}"
        
        # Create HTML content
        html_content = self._generate_html_content(message)
        
        # Create plain text content
        text_content = self._generate_text_content(message)
        
        # Attach content
        text_part = MIMEText(text_content, 'plain')
        html_part = MIMEText(html_content, 'html')
        
        msg.attach(text_part)
        msg.attach(html_part)
        
        return msg
    
    def _generate_html_content(self, message: NotificationMessage) -> str:
        """Generate HTML email content."""
        severity_colors = {
            SeverityLevel.CRITICAL: "#D32F2F",
            SeverityLevel.HIGH: "#F57C00",
            SeverityLevel.MEDIUM: "#FBC02D",
            SeverityLevel.LOW: "#388E3C"
        }
        
        severity_color = severity_colors.get(message.severity, "#666666")
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                .header {{ background-color: {severity_color}; color: white; padding: 20px; }}
                .content {{ padding: 20px; background-color: #f9f9f9; }}
                .footer {{ padding: 10px; font-size: 12px; color: #666; }}
                .severity {{ 
                    display: inline-block; 
                    padding: 5px 10px; 
                    background-color: {severity_color}; 
                    color: white; 
                    border-radius: 5px; 
                    font-weight: bold; 
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Cyber Threat Monitoring System</h1>
                <h2>{message.title}</h2>
            </div>
            
            <div class="content">
                <p><strong>Severity:</strong> <span class="severity">{message.severity.upper()}</span></p>
                <p><strong>Alert ID:</strong> {message.alert_id}</p>
                <p><strong>Timestamp:</strong> {message.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                
                <h3>Details:</h3>
                <p>{message.content}</p>
                
                {self._generate_metadata_html(message.metadata)}
            </div>
            
            <div class="footer">
                <p>This is an automated alert from the Cyber Threat Monitoring System.</p>
                <p>Please do not reply to this email.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _generate_text_content(self, message: NotificationMessage) -> str:
        """Generate plain text email content."""
        content = f"""
CYBER THREAT MONITORING SYSTEM ALERT

Title: {message.title}
Severity: {message.severity.upper()}
Alert ID: {message.alert_id}
Timestamp: {message.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

Details:
{message.content}

{self._generate_metadata_text(message.metadata)}

---
This is an automated alert from the Cyber Threat Monitoring System.
Please do not reply to this email.
        """
        
        return content.strip()
    
    def _generate_metadata_html(self, metadata: Dict[str, Any]) -> str:
        """Generate HTML for metadata."""
        if not metadata:
            return ""
        
        html = "<h3>Additional Information:</h3><ul>"
        for key, value in metadata.items():
            html += f"<li><strong>{key}:</strong> {value}</li>"
        html += "</ul>"
        
        return html
    
    def _generate_metadata_text(self, metadata: Dict[str, Any]) -> str:
        """Generate plain text for metadata."""
        if not metadata:
            return ""
        
        text = "\nAdditional Information:\n"
        for key, value in metadata.items():
            text += f"- {key}: {value}\n"
        
        return text
    
    async def _send_email(self, message: MIMEMultipart, recipients: List[str]) -> None:
        """
        Send email using SMTP.
        
        Args:
            message: Email message
            recipients: Email recipients
        """
        # Run in thread to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_email_sync, message, recipients)
    
    def _send_email_sync(self, message: MIMEMultipart, recipients: List[str]) -> None:
        """Synchronous email sending."""
        context = ssl.create_default_context()
        
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls(context=context)
            server.login(self.username, self.password)
            server.send_message(message, to_addrs=recipients)


# =============================================================================
# SLACK NOTIFICATION HANDLER
# =============================================================================
class SlackNotificationHandler:
    """
    Handles Slack notifications using webhooks.
    Supports rich formatting and attachments.
    """
    
    async def send_notification(
        self,
        message: NotificationMessage,
        channel: NotificationChannel
    ) -> bool:
        """
        Send Slack notification.
        
        Args:
            message: Notification message
            channel: Slack channel configuration
            
        Returns:
            bool: True if successful
        """
        try:
            webhook_url = channel.config.get("webhook_url") or settings.slack_webhook_url
            
            if not webhook_url:
                logger.warning("No Slack webhook URL configured")
                return False
            
            # Create Slack message payload
            payload = self._create_slack_payload(message)
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"✅ Slack notification sent for alert {message.alert_id}")
                        return True
                    else:
                        logger.error(f"❌ Slack notification failed: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"❌ Failed to send Slack notification: {e}")
            return False
    
    def _create_slack_payload(self, message: NotificationMessage) -> Dict[str, Any]:
        """
        Create Slack message payload.
        
        Args:
            message: Notification message
            
        Returns:
            Dict[str, Any]: Slack payload
        """
        # Severity colors for Slack
        severity_colors = {
            SeverityLevel.CRITICAL: "#D32F2F",
            SeverityLevel.HIGH: "#F57C00",
            SeverityLevel.MEDIUM: "#FBC02D",
            SeverityLevel.LOW: "#388E3C"
        }
        
        color = severity_colors.get(message.severity, "#666666")
        
        # Create attachment
        attachment = {
            "color": color,
            "title": f"🚨 {message.title}",
            "text": message.content,
            "fields": [
                {
                    "title": "Severity",
                    "value": message.severity.upper(),
                    "short": True
                },
                {
                    "title": "Alert ID",
                    "value": message.alert_id,
                    "short": True
                },
                {
                    "title": "Timestamp",
                    "value": message.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "short": False
                }
            ],
            "footer": "Cyber Threat Monitoring System",
            "footer_icon": "🛡️",
            "ts": int(message.timestamp.timestamp())
        }
        
        # Add metadata fields
        if message.metadata:
            for key, value in message.metadata.items():
                attachment["fields"].append({
                    "title": key,
                    "value": str(value),
                    "short": True
                })
        
        payload = {
            "text": f"New alert from Cyber Threat Monitoring System",
            "attachments": [attachment]
        }
        
        return payload


# =============================================================================
# WEBHOOK NOTIFICATION HANDLER
# =============================================================================
class WebhookNotificationHandler:
    """
    Handles generic webhook notifications.
    Supports custom payloads and authentication.
    """
    
    async def send_notification(
        self,
        message: NotificationMessage,
        channel: NotificationChannel
    ) -> bool:
        """
        Send webhook notification.
        
        Args:
            message: Notification message
            channel: Webhook channel configuration
            
        Returns:
            bool: True if successful
        """
        try:
            webhook_url = channel.config.get("url")
            if not webhook_url:
                logger.warning("No webhook URL configured")
                return False
            
            # Create payload
            payload = self._create_webhook_payload(message, channel.config)
            
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            auth_headers = channel.config.get("headers", {})
            headers.update(auth_headers)
            
            # Send webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if 200 <= response.status < 300:
                        logger.info(f"✅ Webhook notification sent for alert {message.alert_id}")
                        return True
                    else:
                        logger.error(f"❌ Webhook notification failed: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"❌ Failed to send webhook notification: {e}")
            return False
    
    def _create_webhook_payload(
        self,
        message: NotificationMessage,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create webhook payload."""
        # Use custom payload template if provided
        template = config.get("payload_template")
        
        if template:
            # Replace placeholders in template
            payload_str = json.dumps(template)
            payload_str = payload_str.replace("{{title}}", message.title)
            payload_str = payload_str.replace("{{content}}", message.content)
            payload_str = payload_str.replace("{{severity}}", message.severity)
            payload_str = payload_str.replace("{{alert_id}}", message.alert_id)
            payload_str = payload_str.replace("{{timestamp}}", message.timestamp.isoformat())
            
            return json.loads(payload_str)
        
        # Default payload format
        payload = {
            "alert": {
                "id": message.alert_id,
                "title": message.title,
                "content": message.content,
                "severity": message.severity,
                "timestamp": message.timestamp.isoformat(),
                "metadata": message.metadata
            },
            "source": "Cyber Threat Monitoring System"
        }
        
        return payload


# =============================================================================
# MAIN NOTIFICATION ENGINE
# =============================================================================
class NotificationEngine:
    """
    Main notification engine that orchestrates all notification channels.
    Handles alert processing, routing, and delivery tracking.
    """
    
    def __init__(self):
        """Initialize notification engine."""
        self.handlers = {
            NotificationType.EMAIL: EmailNotificationHandler(),
            NotificationType.SLACK: SlackNotificationHandler(),
            NotificationType.WEBHOOK: WebhookNotificationHandler()
        }
        
        # Default notification channels
        self.channels = self._load_default_channels()
        
        logger.info("🔔 Notification engine initialized")
    
    def _load_default_channels(self) -> List[NotificationChannel]:
        """Load default notification channels."""
        channels = []
        
        # Email channel
        if settings.smtp_server and settings.smtp_username:
            email_channel = NotificationChannel(
                name="default_email",
                type=NotificationType.EMAIL,
                enabled=True,
                config={
                    "recipients": ["admin@example.com"]  # Configure in production
                },
                severity_filter=[SeverityLevel.HIGH, SeverityLevel.CRITICAL]
            )
            channels.append(email_channel)
        
        # Slack channel
        if settings.slack_webhook_url:
            slack_channel = NotificationChannel(
                name="default_slack",
                type=NotificationType.SLACK,
                enabled=True,
                config={
                    "webhook_url": settings.slack_webhook_url
                },
                severity_filter=[SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
            )
            channels.append(slack_channel)
        
        return channels
    
    async def send_alert_notification(self, alert: Alert) -> Dict[str, bool]:
        """
        Send notifications for an alert.
        
        Args:
            alert: Alert to send notifications for
            
        Returns:
            Dict[str, bool]: Results by channel name
        """
        # Create notification message
        message = NotificationMessage(
            title=alert.title,
            content=alert.description,
            severity=alert.severity,
            alert_id=str(alert.id),
            timestamp=alert.created_at,
            metadata={
                "alert_type": alert.alert_type,
                "risk_score": alert.risk_score,
                "confidence": alert.confidence,
                "tags": alert.tags
            }
        )
        
        # Send to all applicable channels
        results = {}
        
        for channel in self.channels:
            if not channel.enabled:
                continue
            
            # Check severity filter
            if message.severity not in channel.severity_filter:
                logger.debug(f"Skipping channel {channel.name}: severity filter")
                continue
            
            # Send notification
            handler = self.handlers.get(channel.type)
            if handler:
                try:
                    success = await handler.send_notification(message, channel)
                    results[channel.name] = success
                    
                    # Update alert with notification status
                    await self._update_alert_notifications(alert, channel.name, success)
                    
                except Exception as e:
                    logger.error(f"❌ Notification failed for channel {channel.name}: {e}")
                    results[channel.name] = False
            else:
                logger.warning(f"No handler for notification type: {channel.type}")
                results[channel.name] = False
        
        return results
    
    async def _update_alert_notifications(
        self,
        alert: Alert,
        channel_name: str,
        success: bool
    ) -> None:
        """
        Update alert with notification delivery status.
        
        Args:
            alert: Alert object
            channel_name: Name of notification channel
            success: Whether notification was successful
        """
        try:
            db = await get_database()
            
            update_data = {
                "updated_at": datetime.utcnow()
            }
            
            if success:
                # Add to successful notifications list
                update_data["$addToSet"] = {
                    "notifications_sent": channel_name
                }
            
            await db.alerts.update_one(
                {"_id": alert.id},
                update_data
            )
            
        except Exception as e:
            logger.error(f"❌ Failed to update alert notifications: {e}")
    
    def add_channel(self, channel: NotificationChannel) -> None:
        """
        Add a notification channel.
        
        Args:
            channel: Notification channel to add
        """
        self.channels.append(channel)
        logger.info(f"📢 Added notification channel: {channel.name}")
    
    def remove_channel(self, channel_name: str) -> bool:
        """
        Remove a notification channel.
        
        Args:
            channel_name: Name of channel to remove
            
        Returns:
            bool: True if removed
        """
        for i, channel in enumerate(self.channels):
            if channel.name == channel_name:
                del self.channels[i]
                logger.info(f"🗑️ Removed notification channel: {channel_name}")
                return True
        
        return False
    
    async def test_channel(self, channel_name: str) -> bool:
        """
        Test a notification channel.
        
        Args:
            channel_name: Name of channel to test
            
        Returns:
            bool: True if test successful
        """
        # Find channel
        channel = None
        for ch in self.channels:
            if ch.name == channel_name:
                channel = ch
                break
        
        if not channel:
            logger.error(f"Channel not found: {channel_name}")
            return False
        
        # Create test message
        test_message = NotificationMessage(
            title="Test Notification",
            content="This is a test notification from the Cyber Threat Monitoring System.",
            severity=SeverityLevel.LOW,
            alert_id="test",
            timestamp=datetime.utcnow(),
            metadata={"test": True}
        )
        
        # Send test notification
        handler = self.handlers.get(channel.type)
        if handler:
            try:
                success = await handler.send_notification(test_message, channel)
                logger.info(f"📧 Test notification sent to {channel_name}: {'✅' if success else '❌'}")
                return success
            except Exception as e:
                logger.error(f"❌ Test notification failed for {channel_name}: {e}")
                return False
        
        return False


# =============================================================================
# ALERT PROCESSING ENGINE
# =============================================================================
class AlertProcessor:
    """
    Processes alerts and triggers notifications based on rules and thresholds.
    """
    
    def __init__(self):
        """Initialize alert processor."""
        self.notification_engine = NotificationEngine()
        
        # Alert rules and thresholds
        self.alert_rules = {
            "high_severity_ioc": {
                "condition": "ioc_severity >= high",
                "cooldown": timedelta(minutes=15),
                "enabled": True
            },
            "critical_threat": {
                "condition": "threat_severity == critical",
                "cooldown": timedelta(minutes=5),
                "enabled": True
            },
            "multiple_iocs": {
                "condition": "ioc_count >= 10 in 1 hour",
                "cooldown": timedelta(hours=1),
                "enabled": True
            }
        }
        
        logger.info("⚡ Alert processor initialized")
    
    async def process_new_ioc(self, ioc_data: Dict[str, Any]) -> Optional[Alert]:
        """
        Process new IOC and create alert if needed.
        
        Args:
            ioc_data: IOC data dictionary
            
        Returns:
            Optional[Alert]: Created alert if conditions met
        """
        try:
            # Check if IOC meets alert criteria
            if ioc_data.get("severity") in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                
                # Create alert
                alert = Alert(
                    title=f"High Severity IOC Detected: {ioc_data.get('type', 'Unknown')}",
                    description=f"A {ioc_data.get('severity', 'unknown')} severity IOC has been detected:\n\n"
                               f"Type: {ioc_data.get('type', 'Unknown')}\n"
                               f"Value: {ioc_data.get('value', 'Unknown')}\n"
                               f"Source: {ioc_data.get('source', 'Unknown')}\n"
                               f"Confidence: {ioc_data.get('confidence', 0):.2f}",
                    alert_type="ioc_detection",
                    severity=ioc_data.get("severity", SeverityLevel.MEDIUM),
                    source_type="automated",
                    source_data=ioc_data,
                    confidence=ioc_data.get("confidence", 0.0),
                    risk_score=self._calculate_risk_score(ioc_data),
                    tags=["ioc", "automated", ioc_data.get("type", "unknown")]
                )
                
                # Save alert
                alert_doc = await self._save_alert(alert)
                
                # Send notifications
                await self.notification_engine.send_alert_notification(alert)
                
                return alert
                
        except Exception as e:
            logger.error(f"❌ Failed to process IOC alert: {e}")
        
        return None
    
    async def process_threat_intelligence(self, threat_data: Dict[str, Any]) -> Optional[Alert]:
        """
        Process threat intelligence and create alert if needed.
        
        Args:
            threat_data: Threat data dictionary
            
        Returns:
            Optional[Alert]: Created alert if conditions met
        """
        try:
            # Check if threat meets alert criteria
            if threat_data.get("severity") == SeverityLevel.CRITICAL:
                
                # Create alert
                alert = Alert(
                    title=f"Critical Threat Detected: {threat_data.get('threat_type', 'Unknown')}",
                    description=f"A critical threat has been identified:\n\n"
                               f"Title: {threat_data.get('title', 'Unknown')}\n"
                               f"Type: {threat_data.get('threat_type', 'Unknown')}\n"
                               f"Risk Score: {threat_data.get('risk_score', 0)}\n"
                               f"Source: {threat_data.get('source', 'Unknown')}\n\n"
                               f"Description:\n{threat_data.get('description', 'No description available')}",
                    alert_type="threat_intelligence",
                    severity=threat_data.get("severity", SeverityLevel.MEDIUM),
                    source_type="automated",
                    source_data=threat_data,
                    confidence=threat_data.get("confidence", 0.0),
                    risk_score=threat_data.get("risk_score", 0.0),
                    tags=["threat", "automated", threat_data.get("threat_type", "unknown")]
                )
                
                # Save alert
                alert_doc = await self._save_alert(alert)
                
                # Send notifications
                await self.notification_engine.send_alert_notification(alert)
                
                return alert
                
        except Exception as e:
            logger.error(f"❌ Failed to process threat alert: {e}")
        
        return None
    
    def _calculate_risk_score(self, data: Dict[str, Any]) -> float:
        """
        Calculate risk score based on data.
        
        Args:
            data: Data to analyze
            
        Returns:
            float: Risk score (0-10)
        """
        score = 0.0
        
        # Base score from severity
        severity = data.get("severity", SeverityLevel.LOW)
        severity_scores = {
            SeverityLevel.LOW: 2.0,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.CRITICAL: 10.0
        }
        score += severity_scores.get(severity, 2.0)
        
        # Adjust based on confidence
        confidence = data.get("confidence", 0.0)
        score = score * confidence
        
        return min(10.0, max(0.0, score))
    
    async def _save_alert(self, alert: Alert) -> Dict[str, Any]:
        """
        Save alert to database.
        
        Args:
            alert: Alert to save
            
        Returns:
            Dict[str, Any]: Saved alert document
        """
        try:
            db = await get_database()
            
            # Insert alert
            alert_doc = alert.dict()
            result = await db.alerts.insert_one(alert_doc)
            
            # Update alert with ID
            alert_doc["_id"] = str(result.inserted_id)
            alert.id = str(result.inserted_id)
            
            logger.info(f"💾 Alert saved: {alert.id}")
            return alert_doc
            
        except Exception as e:
            logger.error(f"❌ Failed to save alert: {e}")
            raise


# =============================================================================
# GLOBAL INSTANCES
# =============================================================================
# Create global instances for easy access
notification_engine = NotificationEngine()
alert_processor = AlertProcessor()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================
async def send_alert(alert_data: Dict[str, Any]) -> bool:
    """
    Convenience function to send an alert.
    
    Args:
        alert_data: Alert data dictionary
        
    Returns:
        bool: True if successful
    """
    try:
        alert = Alert(**alert_data)
        results = await notification_engine.send_alert_notification(alert)
        return any(results.values())
    except Exception as e:
        logger.error(f"❌ Failed to send alert: {e}")
        return False


async def test_notifications() -> Dict[str, bool]:
    """
    Test all notification channels.
    
    Returns:
        Dict[str, bool]: Test results by channel
    """
    results = {}
    
    for channel in notification_engine.channels:
        result = await notification_engine.test_channel(channel.name)
        results[channel.name] = result
    
    return results
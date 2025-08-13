"""
Hacker-Grade Threat Intelligence API Endpoints
Advanced threat monitoring and alerting system for academic cybersecurity research
Educational purposes only - Defensive security research
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Dict, Any, Optional
import asyncio
import json
import logging
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from pydantic import BaseModel
import re

# Import our modules
from ctms.database.production_db import db

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter(prefix="/api/v1/hacker-grade", tags=["Hacker-Grade Threat Intelligence"])

# Security
security = HTTPBearer()

# Cache for hacker-grade threat data
HACKER_GRADE_CACHE = {}
CACHE_DURATION = 300  # 5 minutes

# Alert configuration
ALERT_CONFIG = {
    'enabled': True,
    'high_severity_threshold': 0.8,
    'email_settings': {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'use_tls': True,
        'username': 'demo@example.com',  # Demo email for testing
        'password': 'demo_password',     # Demo password for testing
        'recipients': ['admin@example.com']  # Demo recipients
    },
    'webhook_settings': {
        'url': 'https://webhook.site/demo',  # Demo webhook URL
        'headers': {'Content-Type': 'application/json'}
    }
}

class AlertRequest(BaseModel):
    """Alert configuration request model"""
    email_recipients: List[str] = []
    webhook_url: Optional[str] = None
    threshold: float = 0.8
    enabled: bool = True

class ThreatFilterRequest(BaseModel):
    """Threat filtering request model"""
    min_score: float = 0.0
    max_score: float = 1.0
    threat_types: List[str] = []
    source_types: List[str] = []
    time_range_hours: int = 24

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    """Verify API token"""
    token = credentials.credentials
    # For development, accept demo token
    if token == "demo_token_for_development_12345":
        return True
    # In production, implement proper token verification
    return False

async def send_email_alert(recipients: List[str], subject: str, body: str):
    """Send email alert"""
    try:
        # Check if using demo credentials
        if ALERT_CONFIG['email_settings']['username'] == 'demo@example.com':
            # Log to file instead of console
            log_message = f"""
=== EMAIL ALERT LOG ===
Timestamp: {datetime.now().isoformat()}
Mode: DEMO (No actual email sent)
Recipients: {', '.join(recipients)}
Subject: {subject}
Body Preview: {body[:200]}...
========================
"""
            # Write to email alert log file
            with open('ctms/logs/email_alerts.log', 'a') as f:
                f.write(log_message + '\n')
            
            logger.info(f"DEMO MODE: Email alert logged to ctms/logs/email_alerts.log")
            return True
            
        if not ALERT_CONFIG['email_settings']['username'] or not ALERT_CONFIG['email_settings']['password']:
            logger.warning("Email credentials not configured")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = ALERT_CONFIG['email_settings']['username']
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(ALERT_CONFIG['email_settings']['smtp_server'], 
                            ALERT_CONFIG['email_settings']['smtp_port'])
        server.starttls()
        server.login(ALERT_CONFIG['email_settings']['username'], 
                    ALERT_CONFIG['email_settings']['password'])
        server.send_message(msg)
        server.quit()
        
        # Log successful email to file
        log_message = f"""
=== EMAIL ALERT LOG ===
Timestamp: {datetime.now().isoformat()}
Mode: PRODUCTION (Actual email sent)
Recipients: {', '.join(recipients)}
Subject: {subject}
Status: SUCCESS
========================
"""
        with open('ctms/logs/email_alerts.log', 'a') as f:
            f.write(log_message + '\n')
        
        logger.info(f"Email alert sent to {len(recipients)} recipients and logged")
        return True
        
    except Exception as e:
        # Log failed email to file
        log_message = f"""
=== EMAIL ALERT LOG ===
Timestamp: {datetime.now().isoformat()}
Mode: PRODUCTION (Email failed)
Recipients: {', '.join(recipients)}
Subject: {subject}
Error: {str(e)}
Status: FAILED
========================
"""
        with open('ctms/logs/email_alerts.log', 'a') as f:
            f.write(log_message + '\n')
        
        logger.error(f"Failed to send email alert: {str(e)}")
        return False

async def send_webhook_alert(webhook_url: str, data: Dict[str, Any]):
    """Send webhook alert"""
    try:
        response = requests.post(webhook_url, json=data, headers=ALERT_CONFIG['webhook_settings']['headers'])
        if response.status_code == 200:
            logger.info("Webhook alert sent successfully")
            return True
        else:
            logger.error(f"Webhook alert failed with status {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to send webhook alert: {str(e)}")
        return False

async def check_and_alert_high_severity_threats(articles: List[Dict[str, Any]]):
    """Check for high severity threats and send alerts"""
    if not ALERT_CONFIG['enabled']:
        return
        
    high_severity_threats = [
        article for article in articles 
        if article.get('threat_score', 0) >= ALERT_CONFIG['high_severity_threshold']
    ]
    
    if not high_severity_threats:
        return
        
    # Prepare alert data
    alert_data = {
        'timestamp': datetime.now().isoformat(),
        'high_severity_count': len(high_severity_threats),
        'threshold': ALERT_CONFIG['high_severity_threshold'],
        'threats': high_severity_threats[:5]  # Top 5 threats
    }
    
    # Send email alerts
    if ALERT_CONFIG['email_settings']['recipients']:
        subject = f"🚨 HACKER-GRADE THREAT ALERT - {len(high_severity_threats)} High-Severity Threats Detected"
        
        body = f"""
        <h2>🚨 Hacker-Grade Threat Alert</h2>
        <p><strong>Time:</strong> {alert_data['timestamp']}</p>
        <p><strong>High Severity Threats:</strong> {len(high_severity_threats)}</p>
        <p><strong>Threshold:</strong> {ALERT_CONFIG['high_severity_threshold']}</p>
        
        <h3>🔥 Top Threats:</h3>
        <ul>
        """
        
        for threat in high_severity_threats[:5]:
            body += f"""
            <li>
                <strong>{threat.get('title', 'Unknown')}</strong><br>
                Score: {threat.get('threat_score', 0):.2f}<br>
                Type: {threat.get('threat_type', 'Unknown')}<br>
                Source: {threat.get('source', 'Unknown')}<br>
                Source Type: {threat.get('source_type', 'Unknown')}
            </li>
            """
        
        body += "</ul>"
        
        await send_email_alert(ALERT_CONFIG['email_settings']['recipients'], subject, body)
    
    # Send webhook alerts
    if ALERT_CONFIG['webhook_settings']['url']:
        await send_webhook_alert(ALERT_CONFIG['webhook_settings']['url'], alert_data)

@router.get("/threats/intelligence")
async def get_hacker_grade_threat_intelligence_endpoint(
    force_refresh: bool = False,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get hacker-grade threat intelligence data from database"""
    try:
        # Get threats from database (fast)
        threats = await db.get_recent_threats(limit=100, hours=24)
        
        # Get system status
        system_status = await db.get_system_status()
        
        # Calculate summary metrics
        threat_scores = [threat.get('threat_score', 0) for threat in threats]
        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0
        
        # Get high severity threats
        high_severity_threats = [t for t in threats if t.get('threat_score', 0) > 0.8]
        
        # Get unique source types and threat types
        source_types = list(set(t.get('source_type', '') for t in threats))
        threat_types = list(set(t.get('threat_type', '') for t in threats))
        
        result = {
            'threat_articles': threats,
            'total_articles': len(threats),
            'high_severity_count': len(high_severity_threats),
            'source_types': source_types,
            'threat_types': threat_types,
            'avg_threat_score': round(avg_threat_score, 2),
            'collection_time': system_status.get('last_collection'),
            'next_collection': system_status.get('next_collection'),
            'system_health': system_status.get('system_health'),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error in hacker-grade threat intelligence endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/summary")
async def get_hacker_grade_threat_summary(
    force_refresh: bool = False,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get hacker-grade threat intelligence summary from database"""
    try:
        # Get summary from database (fast)
        summary = await db.get_threat_summary()
        
        return summary
        
    except Exception as e:
        logger.error(f"Error in hacker-grade threat summary endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/threats/filter")
async def filter_hacker_grade_threats(
    filter_request: ThreatFilterRequest,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Filter hacker-grade threats based on criteria"""
    try:
        # Get threat data
        threat_data = await get_hacker_grade_threat_intelligence_endpoint(force_refresh=True, token_verified=token_verified)
        articles = threat_data.get('threat_articles', [])
        
        # Apply filters
        filtered_articles = []
        cutoff_time = datetime.now() - timedelta(hours=filter_request.time_range_hours)
        
        for article in articles:
            # Score filter
            if not (filter_request.min_score <= article.get('threat_score', 0) <= filter_request.max_score):
                continue
                
            # Threat type filter
            if filter_request.threat_types and article.get('threat_type') not in filter_request.threat_types:
                continue
                
            # Source type filter
            if filter_request.source_types and article.get('source_type') not in filter_request.source_types:
                continue
                
            # Time filter
            try:
                published = article.get('published', '')
                if published:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    if pub_date < cutoff_time:
                        continue
            except:
                pass
                
            filtered_articles.append(article)
        
        return {
            'filtered_articles': filtered_articles,
            'total_filtered': len(filtered_articles),
            'filters_applied': filter_request.dict(),
            'filter_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in hacker-grade threat filter endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/zero-day")
async def get_zero_day_threats(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get zero-day specific threats"""
    try:
        # Get threat data
        threat_data = await get_hacker_grade_threat_intelligence_endpoint(force_refresh=True, token_verified=token_verified)
        articles = threat_data.get('threat_articles', [])
        
        # Filter for zero-day threats
        zero_day_threats = [
            article for article in articles 
            if article.get('threat_type') == 'zero_day' or 'zero-day' in article.get('title', '').lower()
        ]
        
        # Sort by threat score
        zero_day_threats.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
        
        return {
            'zero_day_threats': zero_day_threats,
            'total_zero_day': len(zero_day_threats),
            'high_severity_zero_day': len([t for t in zero_day_threats if t.get('threat_score', 0) > 0.8]),
            'collection_time': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in zero-day threats endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/ransomware")
async def get_ransomware_threats(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get ransomware-specific threats"""
    try:
        # Get threat data
        threat_data = await get_hacker_grade_threat_intelligence_endpoint(force_refresh=True, token_verified=token_verified)
        articles = threat_data.get('threat_articles', [])
        
        # Filter for ransomware threats
        ransomware_threats = [
            article for article in articles 
            if article.get('source_type') == 'ransomware_leak' or 'ransomware' in article.get('title', '').lower()
        ]
        
        # Sort by threat score
        ransomware_threats.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
        
        return {
            'ransomware_threats': ransomware_threats,
            'total_ransomware': len(ransomware_threats),
            'high_severity_ransomware': len([t for t in ransomware_threats if t.get('threat_score', 0) > 0.8]),
            'collection_time': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in ransomware threats endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/github")
async def get_github_exploits(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get GitHub exploit threats"""
    try:
        # Get threat data
        threat_data = await get_hacker_grade_threat_intelligence_endpoint(force_refresh=True, token_verified=token_verified)
        articles = threat_data.get('threat_articles', [])
        
        # Filter for GitHub threats
        github_threats = [
            article for article in articles 
            if article.get('source_type') == 'github'
        ]
        
        # Sort by threat score
        github_threats.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
        
        return {
            'github_threats': github_threats,
            'total_github': len(github_threats),
            'high_severity_github': len([t for t in github_threats if t.get('threat_score', 0) > 0.8]),
            'collection_time': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in GitHub exploits endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/indicators")
async def get_hacker_grade_indicators(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get extracted threat indicators from hacker-grade sources"""
    try:
        # Get threats directly from database
        threats = await db.get_recent_threats(limit=100, hours=24)
        
        # Collect all indicators
        all_indicators = {
            'cve_identifiers': set(),
            'company_names': set(),
            'github_repositories': set(),
            'ip_addresses': set(),
            'email_addresses': set(),
            'file_hashes': set(),
            'urls': set()
        }
        
        for threat in threats:
            indicators = threat.get('indicators', {})
            if isinstance(indicators, str):
                try:
                    indicators = json.loads(indicators)
                except:
                    indicators = {}
            
            for indicator_type, values in indicators.items():
                if indicator_type in all_indicators and isinstance(values, list):
                    all_indicators[indicator_type].update(values)
        
        # Convert sets to lists and filter out empty values
        result = {}
        for k, v in all_indicators.items():
            filtered_values = [val for val in v if val and len(str(val).strip()) > 0]
            result[k] = filtered_values
        
        result['total_indicators'] = sum(len(v) for v in result.values())
        result['extraction_timestamp'] = datetime.now().isoformat()
        
        return result
        
    except Exception as e:
        logger.error(f"Error in hacker-grade indicators endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/report")
async def get_hacker_grade_report(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get comprehensive hacker-grade threat intelligence report"""
    try:
        # Get threats from database
        threats = await db.get_recent_threats(limit=100, hours=24)
        
        # Generate comprehensive report
        report = {
            'report_generated': datetime.now().isoformat(),
            'total_threats': len(threats),
            'threat_summary': {
                'high_severity': len([t for t in threats if t.get('threat_score', 0) > 0.8]),
                'medium_severity': len([t for t in threats if 0.5 <= t.get('threat_score', 0) <= 0.8]),
                'low_severity': len([t for t in threats if t.get('threat_score', 0) < 0.5])
            },
            'source_breakdown': {},
            'threat_types': {},
            'top_threats': [],
            'recent_indicators': {
                'cve_identifiers': set(),
                'company_names': set(),
                'github_repositories': set(),
                'ip_addresses': set(),
                'email_addresses': set(),
                'file_hashes': set(),
                'urls': set()
            }
        }
        
        # Analyze threats
        for threat in threats:
            # Source breakdown
            source_type = threat.get('source_type', 'unknown')
            report['source_breakdown'][source_type] = report['source_breakdown'].get(source_type, 0) + 1
            
            # Threat type breakdown
            threat_type = threat.get('threat_type', 'unknown')
            report['threat_types'][threat_type] = report['threat_types'].get(threat_type, 0) + 1
            
            # Top threats (high severity)
            if threat.get('threat_score', 0) > 0.7:
                report['top_threats'].append({
                    'title': threat.get('title', 'Unknown'),
                    'score': threat.get('threat_score', 0),
                    'type': threat.get('threat_type', 'unknown'),
                    'source': threat.get('source_type', 'unknown'),
                    'published': threat.get('published_at', 'Unknown')
                })
            
            # Extract indicators
            indicators = threat.get('indicators', {})
            if isinstance(indicators, str):
                try:
                    indicators = json.loads(indicators)
                except:
                    indicators = {}
            
            for indicator_type, values in indicators.items():
                if indicator_type in report['recent_indicators'] and isinstance(values, list):
                    report['recent_indicators'][indicator_type].update(values)
        
        # Convert sets to lists
        for indicator_type in report['recent_indicators']:
            report['recent_indicators'][indicator_type] = list(report['recent_indicators'][indicator_type])
        
        # Sort top threats by score
        report['top_threats'].sort(key=lambda x: x['score'], reverse=True)
        report['top_threats'] = report['top_threats'][:10]  # Top 10
        
        # Add analysis insights
        report['insights'] = {
            'most_active_source': max(report['source_breakdown'].items(), key=lambda x: x[1])[0] if report['source_breakdown'] else 'None',
            'most_common_threat_type': max(report['threat_types'].items(), key=lambda x: x[1])[0] if report['threat_types'] else 'None',
            'total_indicators': sum(len(v) for v in report['recent_indicators'].values()),
            'avg_threat_score': round(sum(t.get('threat_score', 0) for t in threats) / len(threats), 2) if threats else 0
        }
        
        return report
        
    except Exception as e:
        logger.error(f"Error in hacker-grade report endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/alerts/configure")
async def configure_hacker_grade_alerts(
    alert_request: AlertRequest,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Configure hacker-grade alert settings"""
    try:
        global ALERT_CONFIG
        
        ALERT_CONFIG['enabled'] = alert_request.enabled
        ALERT_CONFIG['high_severity_threshold'] = alert_request.threshold
        
        if alert_request.email_recipients:
            ALERT_CONFIG['email_settings']['recipients'] = alert_request.email_recipients
            
        if alert_request.webhook_url:
            ALERT_CONFIG['webhook_settings']['url'] = alert_request.webhook_url
        
        return {
            'status': 'success',
            'message': 'Hacker-grade alert configuration updated',
            'config': ALERT_CONFIG,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error configuring hacker-grade alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/alerts/test")
async def test_hacker_grade_alerts(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Test hacker-grade alert configuration"""
    try:
        test_data = {
            'timestamp': datetime.now().isoformat(),
            'test_alert': True,
            'message': 'This is a test alert from the Hacker-Grade Threat Intelligence System'
        }
        
        success_count = 0
        demo_mode = False
        
        # Test email alerts
        if ALERT_CONFIG['email_settings']['recipients']:
            email_success = await send_email_alert(
                ALERT_CONFIG['email_settings']['recipients'],
                "🧪 TEST ALERT - Hacker-Grade Threat Intelligence System",
                "<h2>Test Alert</h2><p>This is a test alert to verify the hacker-grade alerting system is working correctly.</p>"
            )
            if email_success:
                success_count += 1
                if ALERT_CONFIG['email_settings']['username'] == 'demo@example.com':
                    demo_mode = True
        
        # Test webhook alerts
        if ALERT_CONFIG['webhook_settings']['url']:
            webhook_success = await send_webhook_alert(ALERT_CONFIG['webhook_settings']['url'], test_data)
            if webhook_success:
                success_count += 1
                if 'webhook.site/demo' in ALERT_CONFIG['webhook_settings']['url']:
                    demo_mode = True
        
        message = f'Hacker-grade test alerts sent. {success_count} successful.'
        if demo_mode:
            message += ' (Demo mode - configure real credentials for actual alerts)'
        
        return {
            'status': 'success',
            'message': message,
            'test_data': test_data,
            'timestamp': datetime.now().isoformat(),
            'demo_mode': demo_mode
        }
        
    except Exception as e:
        logger.error(f"Error testing hacker-grade alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/clear-cache")
async def clear_hacker_grade_cache(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Clear hacker-grade threat intelligence cache"""
    try:
        global HACKER_GRADE_CACHE
        HACKER_GRADE_CACHE.clear()
        
        return {
            'status': 'success',
            'message': 'Hacker-grade threat intelligence cache cleared',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error clearing hacker-grade cache: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/health")
async def hacker_grade_health_check(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Health check for hacker-grade threat intelligence system"""
    try:
        # Get system status from database
        system_status = await db.get_system_status()
        
        return {
            'status': 'healthy',
            'service': 'Hacker-Grade Threat Intelligence',
            'timestamp': datetime.now().isoformat(),
            'version': '3.0.0',
            'message': 'Hacker-grade threat intelligence system is operational',
            'system_status': system_status,
            'source_types': [
                'hacker_forums',
                'ransomware_leak_sites', 
                'paste_sites',
                'github_monitoring'
            ]
        }
        
    except Exception as e:
        logger.error(f"Error in hacker-grade health check: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@router.get("/system/status")
async def get_system_status(
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get detailed system status"""
    try:
        system_status = await db.get_system_status()
        collection_logs = await db.get_collection_logs(limit=10)
        
        return {
            'system_status': system_status,
            'recent_collections': collection_logs,
            'collection_frequency': '5 minutes',
            'data_sources': [
                'hacker_forums',
                'ransomware_leak_sites',
                'paste_sites',
                'github_monitoring'
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/search")
async def search_threats(
    query: str,
    limit: int = 50,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Search threats by query"""
    try:
        threats = await db.search_threats(query, limit)
        
        return {
            'query': query,
            'results': threats,
            'total_results': len(threats),
            'search_timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error searching threats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/by-type/{threat_type}")
async def get_threats_by_type(
    threat_type: str,
    limit: int = 50,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get threats by type"""
    try:
        threats = await db.get_threats_by_type(threat_type, limit)
        
        return {
            'threat_type': threat_type,
            'threats': threats,
            'total_threats': len(threats),
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting threats by type: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/by-source/{source_type}")
async def get_threats_by_source(
    source_type: str,
    limit: int = 50,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get threats by source type"""
    try:
        threats = await db.get_threats_by_source(source_type, limit)
        
        return {
            'source_type': source_type,
            'threats': threats,
            'total_threats': len(threats),
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting threats by source: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
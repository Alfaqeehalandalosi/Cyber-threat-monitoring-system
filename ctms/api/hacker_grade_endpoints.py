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
from ctms.scraping.hacker_grade_scraper import get_hacker_grade_threat_intelligence
from ctms.analysis.hacker_grade_analyzer import analyze_hacker_grade_articles

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
        'username': '',  # Set in environment
        'password': '',  # Set in environment
        'recipients': []  # Set in environment
    },
    'webhook_settings': {
        'url': '',  # Set in environment
        'headers': {}
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
        
        logger.info(f"Email alert sent to {len(recipients)} recipients")
        return True
        
    except Exception as e:
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
    """Get hacker-grade threat intelligence data"""
    try:
        current_time = datetime.now().timestamp()
        
        # Check cache
        if not force_refresh and HACKER_GRADE_CACHE.get('data') and \
           (current_time - HACKER_GRADE_CACHE.get('timestamp', 0)) < CACHE_DURATION:
            logger.info("Returning cached hacker-grade threat intelligence data")
            return HACKER_GRADE_CACHE['data']
        
        # Collect fresh data
        logger.info("Collecting fresh hacker-grade threat intelligence data")
        threat_data = await get_hacker_grade_threat_intelligence()
        
        # Analyze threats
        analysis_result = analyze_hacker_grade_articles(threat_data['threat_articles'])
        
        # Combine data
        result = {
            'threat_articles': analysis_result['enhanced_articles'],
            'total_articles': len(analysis_result['enhanced_articles']),
            'high_severity_count': len([a for a in analysis_result['enhanced_articles'] if a.get('threat_score', 0) > 0.8]),
            'source_types': list(set(a.get('source_type', '') for a in analysis_result['enhanced_articles'])),
            'threat_types': list(set(a.get('threat_type', '') for a in analysis_result['enhanced_articles'])),
            'collection_time': datetime.now().isoformat(),
            'threat_report': analysis_result['threat_report'],
            'analysis_timestamp': analysis_result['analysis_timestamp']
        }
        
        # Update cache
        HACKER_GRADE_CACHE['data'] = result
        HACKER_GRADE_CACHE['timestamp'] = current_time
        
        # Check for alerts in background
        asyncio.create_task(check_and_alert_high_severity_threats(analysis_result['enhanced_articles']))
        
        return result
        
    except Exception as e:
        logger.error(f"Error in hacker-grade threat intelligence endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/threats/summary")
async def get_hacker_grade_threat_summary(
    force_refresh: bool = False,
    token_verified: bool = Depends(verify_token)
) -> Dict[str, Any]:
    """Get hacker-grade threat intelligence summary"""
    try:
        # Get full threat data
        threat_data = await get_hacker_grade_threat_intelligence_endpoint(force_refresh, token_verified)
        
        # Extract summary information
        articles = threat_data.get('threat_articles', [])
        
        # Calculate summary metrics
        threat_scores = [article.get('threat_score', 0) for article in articles]
        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0
        
        # Get top threats
        top_threats = sorted(articles, key=lambda x: x.get('threat_score', 0), reverse=True)[:10]
        
        # Count threat types
        threat_type_counts = {}
        for article in articles:
            threat_type = article.get('threat_type', 'unknown')
            threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
        
        # Count source types
        source_type_counts = {}
        for article in articles:
            source_type = article.get('source_type', 'unknown')
            source_type_counts[source_type] = source_type_counts.get(source_type, 0) + 1
        
        # Count by source category
        source_categories = {
            'hacker_forums': len([a for a in articles if a.get('source_type') == 'hacker_forum']),
            'ransomware_leaks': len([a for a in articles if a.get('source_type') == 'ransomware_leak']),
            'paste_sites': len([a for a in articles if a.get('source_type') == 'paste_site']),
            'github': len([a for a in articles if a.get('source_type') == 'github'])
        }
        
        return {
            'total_articles': len(articles),
            'sources_used': len(source_type_counts),
            'avg_threat_score': round(avg_threat_score, 2),
            'high_severity_count': len([a for a in articles if a.get('threat_score', 0) > 0.8]),
            'collection_time': threat_data.get('collection_time'),
            'top_threats': [
                {
                    'title': threat.get('title', 'Unknown'),
                    'threat_score': threat.get('threat_score', 0),
                    'threat_type': threat.get('threat_type', 'unknown'),
                    'source': threat.get('source', 'Unknown'),
                    'source_type': threat.get('source_type', 'Unknown')
                }
                for threat in top_threats
            ],
            'threat_categories': threat_type_counts,
            'source_distribution': source_type_counts,
            'source_categories': source_categories
        }
        
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
        # Get threat data
        threat_data = await get_hacker_grade_threat_intelligence_endpoint(force_refresh=True, token_verified=token_verified)
        articles = threat_data.get('threat_articles', [])
        
        # Collect all indicators
        all_indicators = {
            'cve_ids': set(),
            'ip_addresses': set(),
            'domains': set(),
            'email_addresses': set(),
            'hashes': set(),
            'urls': set(),
            'file_paths': set(),
            'commands': set(),
            'github_repos': set(),
            'company_names': set()
        }
        
        for article in articles:
            indicators = article.get('indicators', {})
            for indicator_type, values in indicators.items():
                if indicator_type in all_indicators:
                    all_indicators[indicator_type].update(values)
            
            # Extract additional indicators from content
            content = f"{article.get('title', '')} {article.get('content', '')}"
            
            # Extract company names
            company_matches = re.findall(r'\b[A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company|Corporation)\b', content)
            all_indicators['company_names'].update(company_matches)
            
            # Extract GitHub repos
            github_matches = re.findall(r'github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+', content)
            all_indicators['github_repos'].update(github_matches)
        
        # Convert sets to lists
        result = {k: list(v) for k, v in all_indicators.items()}
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
        # Get threat data
        threat_data = await get_hacker_grade_threat_intelligence_endpoint(force_refresh=True, token_verified=token_verified)
        
        # Return the threat report
        return threat_data.get('threat_report', {})
        
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
        
        # Test email alerts
        if ALERT_CONFIG['email_settings']['recipients']:
            email_success = await send_email_alert(
                ALERT_CONFIG['email_settings']['recipients'],
                "🧪 TEST ALERT - Hacker-Grade Threat Intelligence System",
                "<h2>Test Alert</h2><p>This is a test alert to verify the hacker-grade alerting system is working correctly.</p>"
            )
            if email_success:
                success_count += 1
        
        # Test webhook alerts
        if ALERT_CONFIG['webhook_settings']['url']:
            webhook_success = await send_webhook_alert(ALERT_CONFIG['webhook_settings']['url'], test_data)
            if webhook_success:
                success_count += 1
        
        return {
            'status': 'success',
            'message': f'Hacker-grade test alerts sent. {success_count} successful.',
            'test_data': test_data,
            'timestamp': datetime.now().isoformat()
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
        return {
            'status': 'healthy',
            'service': 'Hacker-Grade Threat Intelligence',
            'timestamp': datetime.now().isoformat(),
            'version': '3.0.0',
            'message': 'Hacker-grade threat intelligence system is operational',
            'cache_status': {
                'has_cached_data': bool(HACKER_GRADE_CACHE.get('data')),
                'cache_age_seconds': datetime.now().timestamp() - HACKER_GRADE_CACHE.get('timestamp', 0) if HACKER_GRADE_CACHE.get('timestamp') else 0
            },
            'alert_status': {
                'enabled': ALERT_CONFIG['enabled'],
                'threshold': ALERT_CONFIG['high_severity_threshold'],
                'email_configured': bool(ALERT_CONFIG['email_settings']['recipients']),
                'webhook_configured': bool(ALERT_CONFIG['webhook_settings']['url'])
            },
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
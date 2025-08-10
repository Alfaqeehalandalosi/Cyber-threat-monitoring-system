# =============================================================================
# DEMO API MODULE
# =============================================================================
"""
Demo API endpoints for the Cyber Threat Monitoring System.
This version works without database connections for demonstration purposes.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import os
from pathlib import Path

# Demo data
DEMO_DATA = {
    "iocs": [
        {
            "id": "demo_ioc_1",
            "type": "ip",
            "value": "192.168.1.100",
            "severity": "high",
            "description": "Demo malicious IP address",
            "created_at": "2024-01-15T10:30:00Z",
            "source": "demo_scraper",
            "tags": ["malware", "c2"]
        },
        {
            "id": "demo_ioc_2", 
            "type": "domain",
            "value": "malicious.example.com",
            "severity": "medium",
            "description": "Demo malicious domain",
            "created_at": "2024-01-15T11:00:00Z",
            "source": "demo_scraper",
            "tags": ["phishing"]
        },
        {
            "id": "demo_ioc_3",
            "type": "url",
            "value": "https://malicious.example.com/payload.exe",
            "severity": "critical",
            "description": "Demo malicious URL",
            "created_at": "2024-01-15T11:30:00Z",
            "source": "demo_scraper",
            "tags": ["malware", "download"]
        }
    ],
    "threats": [
        {
            "id": "demo_threat_1",
            "type": "malware",
            "title": "Demo Ransomware Campaign",
            "description": "Demo ransomware threat targeting healthcare sector",
            "severity": "critical",
            "created_at": "2024-01-15T09:00:00Z",
            "source": "demo_intel",
            "tags": ["ransomware", "healthcare"]
        },
        {
            "id": "demo_threat_2",
            "type": "phishing",
            "title": "Demo Phishing Campaign",
            "description": "Demo phishing campaign targeting financial institutions",
            "severity": "high",
            "created_at": "2024-01-15T08:30:00Z",
            "source": "demo_intel",
            "tags": ["phishing", "financial"]
        }
    ],
    "alerts": [
        {
            "id": "demo_alert_1",
            "title": "Demo Security Alert",
            "description": "Demo alert for suspicious activity",
            "severity": "high",
            "status": "new",
            "created_at": "2024-01-15T12:00:00Z",
            "tags": ["suspicious", "network"]
        },
        {
            "id": "demo_alert_2",
            "title": "Demo Threat Detected",
            "description": "Demo threat detection alert",
            "severity": "critical",
            "status": "acknowledged",
            "created_at": "2024-01-15T11:45:00Z",
            "tags": ["threat", "detection"]
        }
    ]
}

# Security
security = HTTPBearer()

# =============================================================================
# FASTAPI APPLICATION SETUP
# =============================================================================
app = FastAPI(
    title="Cyber Threat Monitoring System API - Demo Mode",
    description="Advanced threat intelligence and monitoring platform (Demo Version)",
    version="1.0.0-demo",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8501", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# AUTHENTICATION AND AUTHORIZATION
# =============================================================================
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Verify JWT token and return user information (Demo mode).
    """
    # In demo mode, accept any token
    return {
        "user_id": "demo_user",
        "username": "demo_user",
        "role": "admin"
    }

# =============================================================================
# SYSTEM ENDPOINTS
# =============================================================================
@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint.
    """
    return {
        "status": "healthy",
        "mode": "demo",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0-demo",
        "services": {
            "api": "running",
            "database": "demo_mode",
            "elasticsearch": "demo_mode"
        }
    }

@app.get("/stats", tags=["System"])
async def system_stats(user: dict = Depends(verify_token)) -> Dict[str, Any]:
    """
    Get system statistics.
    """
    return {
        "total_iocs": len(DEMO_DATA["iocs"]),
        "total_threats": len(DEMO_DATA["threats"]),
        "total_alerts": len(DEMO_DATA["alerts"]),
        "severity_distribution": {
            "critical": len([i for i in DEMO_DATA["iocs"] + DEMO_DATA["threats"] + DEMO_DATA["alerts"] if i.get("severity") == "critical"]),
            "high": len([i for i in DEMO_DATA["iocs"] + DEMO_DATA["threats"] + DEMO_DATA["alerts"] if i.get("severity") == "high"]),
            "medium": len([i for i in DEMO_DATA["iocs"] + DEMO_DATA["threats"] + DEMO_DATA["alerts"] if i.get("severity") == "medium"]),
            "low": len([i for i in DEMO_DATA["iocs"] + DEMO_DATA["threats"] + DEMO_DATA["alerts"] if i.get("severity") == "low"])
        },
        "last_updated": datetime.now().isoformat()
    }

# =============================================================================
# IOC ENDPOINTS
# =============================================================================
@app.get("/api/v1/iocs", tags=["IOCs"], response_model=List[dict])
async def get_iocs(
    limit: int = 100,
    skip: int = 0,
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    user: dict = Depends(verify_token)
) -> List[dict]:
    """
    Get IOCs with optional filtering.
    """
    iocs = DEMO_DATA["iocs"]
    
    # Apply filters
    if ioc_type:
        iocs = [i for i in iocs if i.get("type") == ioc_type]
    if severity:
        iocs = [i for i in iocs if i.get("severity") == severity]
    
    # Apply pagination
    iocs = iocs[skip:skip + limit]
    
    return iocs

@app.get("/api/v1/iocs/{ioc_id}", tags=["IOCs"], response_model=dict)
async def get_ioc(
    ioc_id: str,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Get a specific IOC by ID.
    """
    for ioc in DEMO_DATA["iocs"]:
        if ioc["id"] == ioc_id:
            return ioc
    
    raise HTTPException(status_code=404, detail="IOC not found")

# =============================================================================
# THREAT ENDPOINTS
# =============================================================================
@app.get("/api/v1/threats", tags=["Threats"], response_model=List[dict])
async def get_threats(
    limit: int = 100,
    skip: int = 0,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    user: dict = Depends(verify_token)
) -> List[dict]:
    """
    Get threats with optional filtering.
    """
    threats = DEMO_DATA["threats"]
    
    # Apply filters
    if threat_type:
        threats = [t for t in threats if t.get("type") == threat_type]
    if severity:
        threats = [t for t in threats if t.get("severity") == severity]
    
    # Apply pagination
    threats = threats[skip:skip + limit]
    
    return threats

@app.get("/api/v1/threats/{threat_id}", tags=["Threats"], response_model=dict)
async def get_threat(
    threat_id: str,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Get a specific threat by ID.
    """
    for threat in DEMO_DATA["threats"]:
        if threat["id"] == threat_id:
            return threat
    
    raise HTTPException(status_code=404, detail="Threat not found")

# =============================================================================
# ALERT ENDPOINTS
# =============================================================================
@app.get("/api/v1/alerts", tags=["Alerts"], response_model=List[dict])
async def get_alerts(
    limit: int = 100,
    skip: int = 0,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    user: dict = Depends(verify_token)
) -> List[dict]:
    """
    Get alerts with optional filtering.
    """
    alerts = DEMO_DATA["alerts"]
    
    # Apply filters
    if status:
        alerts = [a for a in alerts if a.get("status") == status]
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    
    # Apply pagination
    alerts = alerts[skip:skip + limit]
    
    return alerts

@app.get("/api/v1/alerts/{alert_id}", tags=["Alerts"], response_model=dict)
async def get_alert(
    alert_id: str,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Get a specific alert by ID.
    """
    for alert in DEMO_DATA["alerts"]:
        if alert["id"] == alert_id:
            return alert
    
    raise HTTPException(status_code=404, detail="Alert not found")

# =============================================================================
# ANALYSIS ENDPOINTS
# =============================================================================
@app.post("/api/v1/analysis/text", tags=["Analysis"], response_model=dict)
async def analyze_text(
    text_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Analyze text for threat indicators.
    """
    text = text_data.get("text", "")
    
    # Demo analysis - look for common patterns
    analysis_result = {
        "text": text,
        "indicators_found": [],
        "threat_score": 0.0,
        "confidence": 0.8,
        "analysis_time": datetime.now().isoformat()
    }
    
    # Simple pattern matching for demo
    import re
    
    # IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    for ip in ips:
        analysis_result["indicators_found"].append({
            "type": "ip",
            "value": ip,
            "confidence": 0.9
        })
    
    # Domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, text)
    for domain in domains:
        if "malicious" in domain.lower() or "evil" in domain.lower():
            analysis_result["indicators_found"].append({
                "type": "domain",
                "value": domain,
                "confidence": 0.8
            })
    
    # URLs
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, text)
    for url in urls:
        analysis_result["indicators_found"].append({
            "type": "url",
            "value": url,
            "confidence": 0.7
        })
    
    # Calculate threat score
    analysis_result["threat_score"] = min(1.0, len(analysis_result["indicators_found"]) * 0.3)
    
    return analysis_result

# =============================================================================
# SEARCH ENDPOINTS
# =============================================================================
@app.get("/api/v1/search", tags=["Search"], response_model=dict)
async def search_intelligence(
    q: str,
    limit: int = 50,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Search across all threat intelligence data.
    """
    results = {
        "query": q,
        "total_results": 0,
        "results": {
            "iocs": [],
            "threats": [],
            "alerts": []
        }
    }
    
    # Simple text search
    query_lower = q.lower()
    
    # Search in IOCs
    for ioc in DEMO_DATA["iocs"]:
        if (query_lower in ioc.get("value", "").lower() or
            query_lower in ioc.get("description", "").lower()):
            results["results"]["iocs"].append(ioc)
    
    # Search in threats
    for threat in DEMO_DATA["threats"]:
        if (query_lower in threat.get("title", "").lower() or
            query_lower in threat.get("description", "").lower()):
            results["results"]["threats"].append(threat)
    
    # Search in alerts
    for alert in DEMO_DATA["alerts"]:
        if (query_lower in alert.get("title", "").lower() or
            query_lower in alert.get("description", "").lower()):
            results["results"]["alerts"].append(alert)
    
    # Calculate total results
    results["total_results"] = (
        len(results["results"]["iocs"]) +
        len(results["results"]["threats"]) +
        len(results["results"]["alerts"])
    )
    
    return results

# =============================================================================
# ERROR HANDLERS
# =============================================================================
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle general exceptions."""
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500}
    )
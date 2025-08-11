# =============================================================================
# MAIN FASTAPI APPLICATION
# =============================================================================
"""
Main FastAPI application for the Cyber Threat Monitoring System.
Provides REST API endpoints for all system functionality.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import uvicorn

from ctms.core.config import settings
from ctms.core.logger import get_logger
from ctms.database.connection import initialize_databases, close_databases, database_health
from ctms.database.models import (
    IndicatorOfCompromise, ThreatIntelligence, Alert, ScrapingSource,
    ScrapedContent, User, ThreatType, SeverityLevel, AlertStatus
)

logger = get_logger(__name__)

# Security
security = HTTPBearer()


# =============================================================================
# APPLICATION LIFECYCLE
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup and shutdown tasks.
    """
    # Startup
    logger.info("🚀 Starting Cyber Threat Monitoring System API")
    
    try:
        # Initialize databases
        await initialize_databases()
        logger.info("✅ API startup completed successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"❌ API startup failed: {e}")
        raise
    
    finally:
        # Shutdown
        logger.info("🛑 Shutting down API")
        await close_databases()
        logger.info("✅ API shutdown completed")


# =============================================================================
# FASTAPI APPLICATION SETUP
# =============================================================================
app = FastAPI(
    title="Cyber Threat Monitoring System API",
    description="Advanced threat intelligence and monitoring platform",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8501"],  # Add your frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# AUTHENTICATION AND AUTHORIZATION
# =============================================================================
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Verify JWT token and return user information.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        dict: User information
        
    Raises:
        HTTPException: If token is invalid
    """
    # Simple token verification (in production, use proper JWT validation)
    token = credentials.credentials
    
    # For development, accept any non-empty token
    if not token or len(token) < 10:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # TODO: Implement proper JWT token validation
    # For now, return a basic user structure
    # In production, decode JWT and get real user from database
    return {
        "user_id": "admin",
        "username": "admin",
        "roles": ["admin", "analyst"],
        "permissions": ["read", "write", "admin"]
    }


# =============================================================================
# HEALTH AND STATUS ENDPOINTS
# =============================================================================
@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """
    System health check endpoint.
    
    Returns:
        Dict[str, Any]: System health status
    """
    try:
        # Check database health
        db_health = await database_health()
        
        health_status = {
            "status": "healthy" if db_health["overall_status"] == "healthy" else "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "databases": db_health,
            "uptime": "running"
        }
        
        return health_status
        
    except Exception as e:
        logger.error(f"❌ Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@app.get("/stats", tags=["System"])
async def system_stats(user: dict = Depends(verify_token)) -> Dict[str, Any]:
    """
    Get system statistics and metrics.
    
    Args:
        user: Authenticated user information
        
    Returns:
        Dict[str, Any]: System statistics
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Get collection counts
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "collections": {
                "iocs": await db.iocs.count_documents({}),
                "threats": await db.threats.count_documents({}),
                "alerts": await db.alerts.count_documents({}),
                "scraped_content": await db.scraped_content.count_documents({}),
                "scraping_sources": await db.scraping_sources.count_documents({})
            },
            "recent_activity": {
                "new_iocs_24h": await db.iocs.count_documents({
                    "created_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}
                }),
                "new_alerts_24h": await db.alerts.count_documents({
                    "created_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}
                }),
                "processed_content_24h": await db.scraped_content.count_documents({
                    "processed": True,
                    "updated_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}
                })
            }
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"❌ Failed to get system stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system statistics")


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
    Get indicators of compromise with filtering and pagination.
    
    Args:
        limit: Maximum number of IOCs to return
        skip: Number of IOCs to skip
        ioc_type: Filter by IOC type
        severity: Filter by severity level
        user: Authenticated user information
        
    Returns:
        List[dict]: List of IOCs
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Build query filter
        query_filter = {}
        if ioc_type:
            query_filter["type"] = ioc_type
        if severity:
            query_filter["severity"] = severity
        
        # Execute query
        cursor = db.iocs.find(query_filter).skip(skip).limit(limit).sort("created_at", -1)
        iocs = []
        
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            iocs.append(doc)
        
        logger.api_request("GET", "/api/v1/iocs", 200, count=len(iocs))
        return iocs
        
    except Exception as e:
        logger.error(f"❌ Failed to get IOCs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve IOCs")


@app.post("/api/v1/iocs", tags=["IOCs"], response_model=dict)
async def create_ioc(
    ioc_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new indicator of compromise.
    
    Args:
        ioc_data: IOC data dictionary
        user: Authenticated user information
        
    Returns:
        dict: Created IOC with ID
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Create IOC document
        ioc = IndicatorOfCompromise(**ioc_data)
        
        # Insert into database
        result = await db.iocs.insert_one(ioc.dict())
        
        # Return created IOC
        created_ioc = ioc.dict()
        created_ioc["_id"] = str(result.inserted_id)
        
        logger.api_request("POST", "/api/v1/iocs", 201)
        return created_ioc
        
    except Exception as e:
        logger.error(f"❌ Failed to create IOC: {e}")
        raise HTTPException(status_code=500, detail="Failed to create IOC")


@app.get("/api/v1/iocs/{ioc_id}", tags=["IOCs"], response_model=dict)
async def get_ioc(
    ioc_id: str,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Get a specific IOC by ID.
    
    Args:
        ioc_id: IOC identifier
        user: Authenticated user information
        
    Returns:
        dict: IOC data
    """
    try:
        from ctms.database.connection import get_database
        from bson import ObjectId
        
        db = await get_database()
        
        # Find IOC
        ioc = await db.iocs.find_one({"_id": ObjectId(ioc_id)})
        
        if not ioc:
            raise HTTPException(status_code=404, detail="IOC not found")
        
        ioc["_id"] = str(ioc["_id"])
        
        logger.api_request("GET", f"/api/v1/iocs/{ioc_id}", 200)
        return ioc
        
    except Exception as e:
        logger.error(f"❌ Failed to get IOC {ioc_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve IOC")


# =============================================================================
# THREAT INTELLIGENCE ENDPOINTS
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
    Get threat intelligence with filtering and pagination.
    
    Args:
        limit: Maximum number of threats to return
        skip: Number of threats to skip
        threat_type: Filter by threat type
        severity: Filter by severity level
        user: Authenticated user information
        
    Returns:
        List[dict]: List of threats
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Build query filter
        query_filter = {}
        if threat_type:
            query_filter["threat_type"] = threat_type
        if severity:
            query_filter["severity"] = severity
        
        # Execute query
        cursor = db.threats.find(query_filter).skip(skip).limit(limit).sort("created_at", -1)
        threats = []
        
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            threats.append(doc)
        
        logger.api_request("GET", "/api/v1/threats", 200, count=len(threats))
        return threats
        
    except Exception as e:
        logger.error(f"❌ Failed to get threats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve threats")


@app.post("/api/v1/threats", tags=["Threats"], response_model=dict)
async def create_threat(
    threat_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new threat intelligence record.
    
    Args:
        threat_data: Threat data dictionary
        user: Authenticated user information
        
    Returns:
        dict: Created threat with ID
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Create threat document
        threat = ThreatIntelligence(**threat_data)
        
        # Insert into database
        result = await db.threats.insert_one(threat.dict())
        
        # Return created threat
        created_threat = threat.dict()
        created_threat["_id"] = str(result.inserted_id)
        
        logger.api_request("POST", "/api/v1/threats", 201)
        return created_threat
        
    except Exception as e:
        logger.error(f"❌ Failed to create threat: {e}")
        raise HTTPException(status_code=500, detail="Failed to create threat")


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
    Get alerts with filtering and pagination.
    
    Args:
        limit: Maximum number of alerts to return
        skip: Number of alerts to skip
        status: Filter by alert status
        severity: Filter by severity level
        user: Authenticated user information
        
    Returns:
        List[dict]: List of alerts
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Build query filter
        query_filter = {}
        if status:
            query_filter["status"] = status
        if severity:
            query_filter["severity"] = severity
        
        # Execute query
        cursor = db.alerts.find(query_filter).skip(skip).limit(limit).sort("created_at", -1)
        alerts = []
        
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            alerts.append(doc)
        
        logger.api_request("GET", "/api/v1/alerts", 200, count=len(alerts))
        return alerts
        
    except Exception as e:
        logger.error(f"❌ Failed to get alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


@app.post("/api/v1/alerts", tags=["Alerts"], response_model=dict)
async def create_alert(
    alert_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new alert.
    
    Args:
        alert_data: Alert data dictionary
        user: Authenticated user information
        
    Returns:
        dict: Created alert with ID
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Create alert document
        alert = Alert(**alert_data)
        
        # Insert into database
        result = await db.alerts.insert_one(alert.dict())
        
        # Return created alert
        created_alert = alert.dict()
        created_alert["_id"] = str(result.inserted_id)
        
        logger.api_request("POST", "/api/v1/alerts", 201)
        return created_alert
        
    except Exception as e:
        logger.error(f"❌ Failed to create alert: {e}")
        raise HTTPException(status_code=500, detail="Failed to create alert")


@app.put("/api/v1/alerts/{alert_id}/acknowledge", tags=["Alerts"], response_model=dict)
async def acknowledge_alert(
    alert_id: str,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Acknowledge an alert.
    
    Args:
        alert_id: Alert identifier
        user: Authenticated user information
        
    Returns:
        dict: Updated alert
    """
    try:
        from ctms.database.connection import get_database
        from bson import ObjectId
        
        db = await get_database()
        
        # Update alert
        result = await db.alerts.update_one(
            {"_id": ObjectId(alert_id)},
            {
                "$set": {
                    "status": AlertStatus.ACKNOWLEDGED,
                    "acknowledged_at": datetime.utcnow(),
                    "assigned_to": user["username"],
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Return updated alert
        updated_alert = await db.alerts.find_one({"_id": ObjectId(alert_id)})
        updated_alert["_id"] = str(updated_alert["_id"])
        
        logger.api_request("PUT", f"/api/v1/alerts/{alert_id}/acknowledge", 200)
        return updated_alert
        
    except Exception as e:
        logger.error(f"❌ Failed to acknowledge alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to acknowledge alert")


# =============================================================================
# SCRAPING ENDPOINTS
# =============================================================================
@app.get("/api/v1/scraping/sources", tags=["Scraping"], response_model=List[dict])
async def get_scraping_sources(
    user: dict = Depends(verify_token)
) -> List[dict]:
    """
    Get all scraping sources.
    
    Args:
        user: Authenticated user information
        
    Returns:
        List[dict]: List of scraping sources
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Get all scraping sources
        cursor = db.scraping_sources.find({}).sort("name", 1)
        sources = []
        
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            sources.append(doc)
        
        logger.api_request("GET", "/api/v1/scraping/sources", 200, count=len(sources))
        return sources
        
    except Exception as e:
        logger.error(f"❌ Failed to get scraping sources: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scraping sources")


@app.post("/api/v1/scraping/sources", tags=["Scraping"], response_model=dict)
async def create_scraping_source(
    source_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new scraping source.
    
    Args:
        source_data: Source configuration data
        user: Authenticated user information
        
    Returns:
        dict: Created source with ID
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Create source document
        source = ScrapingSource(**source_data)
        
        # Insert into database
        result = await db.scraping_sources.insert_one(source.dict())
        
        # Return created source
        created_source = source.dict()
        created_source["_id"] = str(result.inserted_id)
        
        logger.api_request("POST", "/api/v1/scraping/sources", 201)
        return created_source
        
    except Exception as e:
        logger.error(f"❌ Failed to create scraping source: {e}")
        raise HTTPException(status_code=500, detail="Failed to create scraping source")


@app.post("/api/v1/scraping/run", tags=["Scraping"], response_model=dict)
async def run_scraping_cycle(
    user: dict = Depends(verify_token)
) -> dict:
    """
    Trigger a manual scraping cycle.
    
    Args:
        user: Authenticated user information
        
    Returns:
        dict: Scraping results
    """
    try:
        from ctms.scraping.tor_scraper import ScrapingOrchestrator
        
        # Create and run orchestrator
        orchestrator = ScrapingOrchestrator()
        await orchestrator.initialize()
        
        try:
            results = await orchestrator.run_scraping_cycle()
            logger.api_request("POST", "/api/v1/scraping/run", 200)
            return {
                "status": "completed",
                "timestamp": datetime.utcnow().isoformat(),
                "results": results
            }
        finally:
            await orchestrator.close()
        
    except Exception as e:
        logger.error(f"❌ Failed to run scraping cycle: {e}")
        raise HTTPException(status_code=500, detail="Failed to run scraping cycle")


# =============================================================================
# ANALYSIS ENDPOINTS
# =============================================================================
@app.post("/api/v1/analysis/content/{content_id}", tags=["Analysis"], response_model=dict)
async def analyze_content(
    content_id: str,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Analyze scraped content for threats and IOCs.
    
    Args:
        content_id: Content identifier
        user: Authenticated user information
        
    Returns:
        dict: Analysis results
    """
    try:
        from ctms.database.connection import get_database
        from ctms.nlp.threat_analyzer import ThreatAnalyzer
        from bson import ObjectId
        
        db = await get_database()
        
        # Get content
        content_doc = await db.scraped_content.find_one({"_id": ObjectId(content_id)})
        if not content_doc:
            raise HTTPException(status_code=404, detail="Content not found")
        
        # Create content object
        content = ScrapedContent(**content_doc)
        
        # Analyze content
        analyzer = ThreatAnalyzer()
        analysis = await analyzer.analyze_content(content)
        
        # Save analysis
        analysis_doc = analysis.dict()
        await db.nlp_analysis.insert_one(analysis_doc)
        
        logger.api_request("POST", f"/api/v1/analysis/content/{content_id}", 200)
        return {
            "status": "completed",
            "analysis_id": str(analysis_doc["_id"]),
            "results": analysis_doc
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to analyze content {content_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze content")


@app.post("/api/v1/analysis/text", tags=["Analysis"], response_model=dict)
async def analyze_text(
    text_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Analyze raw text for threats and IOCs.
    
    Args:
        text_data: Dictionary containing 'text' field
        user: Authenticated user information
        
    Returns:
        dict: Analysis results
    """
    try:
        from ctms.nlp.threat_analyzer import extract_iocs_from_text, ThreatClassifier
        
        text = text_data.get("text", "")
        if not text:
            raise HTTPException(status_code=400, detail="Text field is required")
        
        # Extract IOCs
        iocs = await extract_iocs_from_text(text)
        
        # Classify threats
        classifier = ThreatClassifier()
        classification = classifier.classify_content(text)
        
        results = {
            "iocs": iocs,
            "classification": classification,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
        logger.api_request("POST", "/api/v1/analysis/text", 200)
        return results
        
    except Exception as e:
        logger.error(f"❌ Failed to analyze text: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze text")


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
    
    Args:
        q: Search query
        limit: Maximum results to return
        user: Authenticated user information
        
    Returns:
        dict: Search results
    """
    try:
        from ctms.database.connection import get_elasticsearch
        
        es = await get_elasticsearch()
        
        # Search across multiple indices
        search_body = {
            "query": {
                "multi_match": {
                    "query": q,
                    "fields": ["title", "description", "content", "value"],
                    "fuzziness": "AUTO"
                }
            },
            "size": limit,
            "sort": [{"_score": {"order": "desc"}}]
        }
        
        # Search in IOCs, threats, and content
        indices = ["ctms_iocs", "ctms_threats", "ctms_content"]
        
        results = {}
        for index in indices:
            try:
                response = await es.search(index=index, body=search_body)
                results[index] = [hit["_source"] for hit in response["hits"]["hits"]]
            except Exception as index_error:
                logger.warning(f"⚠️ Search failed for index {index}: {index_error}")
                results[index] = []
        
        logger.api_request("GET", "/api/v1/search", 200, query=q)
        return {
            "query": q,
            "total_results": sum(len(r) for r in results.values()),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"❌ Search failed: {e}")
        raise HTTPException(status_code=500, detail="Search failed")


# =============================================================================
# ERROR HANDLERS
# =============================================================================
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Handle HTTP exceptions."""
    logger.error(f"HTTP {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500}
    )


# =============================================================================
# DEVELOPMENT SERVER
# =============================================================================
if __name__ == "__main__":
    uvicorn.run(
        "ctms.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="info"
    )
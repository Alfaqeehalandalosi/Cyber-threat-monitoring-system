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
    
    # For development, accept demo token
    if token == "demo_token_for_development_12345":
        return {
            "user_id": "demo_user",
            "username": "demo",
            "role": "admin",
            "permissions": ["read", "write", "admin"]
        }
    
    # In production, validate JWT token here
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token"
    )


# =============================================================================
# SYSTEM ENDPOINTS
# =============================================================================
@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """
    System health check endpoint.
    
    Returns:
        Dict[str, Any]: Health status
    """
    try:
        # Check database health
        db_health = await database_health()
        
        health_status = {
            "status": "healthy" if db_health["status"] == "healthy" else "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "services": {
                "database": db_health,
                "api": {"status": "healthy", "uptime": "running"}
            }
        }
        
        status_code = 200 if health_status["status"] == "healthy" else 503
        logger.api_request("GET", "/health", status_code)
        
        return health_status
        
    except Exception as e:
        logger.error(f"❌ Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Health check failed")


@app.get("/stats", tags=["System"])
async def system_stats(user: dict = Depends(verify_token)) -> Dict[str, Any]:
    """
    Get system statistics.
    
    Args:
        user: Authenticated user information
        
    Returns:
        Dict[str, Any]: System statistics
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Get counts
        ioc_count = await db.iocs.count_documents({})
        threat_count = await db.threat_intelligence.count_documents({})
        alert_count = await db.alerts.count_documents({})
        content_count = await db.scraped_content.count_documents({})
        source_count = await db.scraping_sources.count_documents({})
        
        # Get recent activity
        recent_content = await db.scraped_content.count_documents({
            "scraped_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}
        })
        
        recent_alerts = await db.alerts.count_documents({
            "created_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}
        })
        
        stats = {
            "total_iocs": ioc_count,
            "total_threats": threat_count,
            "total_alerts": alert_count,
            "total_content": content_count,
            "total_sources": source_count,
            "recent_content_24h": recent_content,
            "recent_alerts_24h": recent_alerts,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.api_request("GET", "/stats", 200)
        return stats
        
    except Exception as e:
        logger.error(f"❌ Failed to get system stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system statistics")


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
    Get indicators of compromise.
    
    Args:
        limit: Maximum number of results
        skip: Number of results to skip
        ioc_type: Filter by IOC type
        severity: Filter by severity
        user: Authenticated user information
        
    Returns:
        List[dict]: List of IOCs
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Build filter
        filter_query = {}
        if ioc_type:
            filter_query["type"] = ioc_type
        if severity:
            filter_query["severity"] = severity
        
        # Get IOCs
        cursor = db.iocs.find(filter_query).skip(skip).limit(limit).sort("first_seen", -1)
        iocs = await cursor.to_list(length=limit)
        
        # Convert ObjectIds to strings
        for ioc in iocs:
            ioc["id"] = str(ioc["_id"])
            del ioc["_id"]
        
        logger.api_request("GET", "/api/v1/iocs", 200)
        return iocs
        
    except Exception as e:
        logger.error(f"❌ Failed to get IOCs: {e}")
        raise HTTPException(status_code=500, detail="Failed to get IOCs")


@app.post("/api/v1/iocs", tags=["IOCs"], response_model=dict)
async def create_ioc(
    ioc_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new indicator of compromise.
    
    Args:
        ioc_data: IOC data
        user: Authenticated user information
        
    Returns:
        dict: Created IOC
    """
    try:
        from ctms.database.connection import get_database
        from bson import ObjectId
        
        db = await get_database()
        
        # Add metadata
        ioc_data["created_at"] = datetime.utcnow()
        ioc_data["created_by"] = user["user_id"]
        ioc_data["first_seen"] = datetime.utcnow()
        ioc_data["last_seen"] = datetime.utcnow()
        
        # Insert IOC
        result = await db.iocs.insert_one(ioc_data)
        
        # Get created IOC
        created_ioc = await db.iocs.find_one({"_id": result.inserted_id})
        created_ioc["id"] = str(created_ioc["_id"])
        del created_ioc["_id"]
        
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
    Get a specific indicator of compromise.
    
    Args:
        ioc_id: IOC identifier
        user: Authenticated user information
        
    Returns:
        dict: IOC details
    """
    try:
        from ctms.database.connection import get_database
        from bson import ObjectId
        
        db = await get_database()
        
        # Get IOC
        ioc = await db.iocs.find_one({"_id": ObjectId(ioc_id)})
        if not ioc:
            raise HTTPException(status_code=404, detail="IOC not found")
        
        ioc["id"] = str(ioc["_id"])
        del ioc["_id"]
        
        logger.api_request("GET", f"/api/v1/iocs/{ioc_id}", 200)
        return ioc
        
    except Exception as e:
        logger.error(f"❌ Failed to get IOC {ioc_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get IOC")


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
    Get threat intelligence data.
    
    Args:
        limit: Maximum number of results
        skip: Number of results to skip
        threat_type: Filter by threat type
        severity: Filter by severity
        user: Authenticated user information
        
    Returns:
        List[dict]: List of threats
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Build filter
        filter_query = {}
        if threat_type:
            filter_query["threat_type"] = threat_type
        if severity:
            filter_query["severity"] = severity
        
        # Get threats
        cursor = db.threat_intelligence.find(filter_query).skip(skip).limit(limit).sort("created_at", -1)
        threats = await cursor.to_list(length=limit)
        
        # Convert ObjectIds to strings
        for threat in threats:
            threat["id"] = str(threat["_id"])
            del threat["_id"]
        
        logger.api_request("GET", "/api/v1/threats", 200)
        return threats
        
    except Exception as e:
        logger.error(f"❌ Failed to get threats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get threats")


@app.post("/api/v1/threats", tags=["Threats"], response_model=dict)
async def create_threat(
    threat_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new threat intelligence record.
    
    Args:
        threat_data: Threat data
        user: Authenticated user information
        
    Returns:
        dict: Created threat
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Add metadata
        threat_data["created_at"] = datetime.utcnow()
        threat_data["created_by"] = user["user_id"]
        
        # Insert threat
        result = await db.threat_intelligence.insert_one(threat_data)
        
        # Get created threat
        created_threat = await db.threat_intelligence.find_one({"_id": result.inserted_id})
        created_threat["id"] = str(created_threat["_id"])
        del created_threat["_id"]
        
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
    Get alerts.
    
    Args:
        limit: Maximum number of results
        skip: Number of results to skip
        status: Filter by alert status
        severity: Filter by severity
        user: Authenticated user information
        
    Returns:
        List[dict]: List of alerts
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Build filter
        filter_query = {}
        if status:
            filter_query["status"] = status
        if severity:
            filter_query["severity"] = severity
        
        # Get alerts
        cursor = db.alerts.find(filter_query).skip(skip).limit(limit).sort("created_at", -1)
        alerts = await cursor.to_list(length=limit)
        
        # Convert ObjectIds to strings
        for alert in alerts:
            alert["id"] = str(alert["_id"])
            del alert["_id"]
        
        logger.api_request("GET", "/api/v1/alerts", 200)
        return alerts
        
    except Exception as e:
        logger.error(f"❌ Failed to get alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")


@app.post("/api/v1/alerts", tags=["Alerts"], response_model=dict)
async def create_alert(
    alert_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new alert.
    
    Args:
        alert_data: Alert data
        user: Authenticated user information
        
    Returns:
        dict: Created alert
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Add metadata
        alert_data["created_at"] = datetime.utcnow()
        alert_data["created_by"] = user["user_id"]
        alert_data["status"] = AlertStatus.ACTIVE
        
        # Insert alert
        result = await db.alerts.insert_one(alert_data)
        
        # Get created alert
        created_alert = await db.alerts.find_one({"_id": result.inserted_id})
        created_alert["id"] = str(created_alert["_id"])
        del created_alert["_id"]
        
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
                    "acknowledged_by": user["user_id"]
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Get updated alert
        updated_alert = await db.alerts.find_one({"_id": ObjectId(alert_id)})
        updated_alert["id"] = str(updated_alert["_id"])
        del updated_alert["_id"]
        
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
    Get scraping sources.
    
    Args:
        user: Authenticated user information
        
    Returns:
        List[dict]: List of scraping sources
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Get sources
        cursor = db.scraping_sources.find({}).sort("name", 1)
        sources = await cursor.to_list(length=None)
        
        # Convert ObjectIds to strings
        for source in sources:
            source["id"] = str(source["_id"])
            del source["_id"]
        
        logger.api_request("GET", "/api/v1/scraping/sources", 200)
        return sources
        
    except Exception as e:
        logger.error(f"❌ Failed to get scraping sources: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scraping sources")


@app.post("/api/v1/scraping/sources", tags=["Scraping"], response_model=dict)
async def create_scraping_source(
    source_data: dict,
    user: dict = Depends(verify_token)
) -> dict:
    """
    Create a new scraping source.
    
    Args:
        source_data: Source data
        user: Authenticated user information
        
    Returns:
        dict: Created source
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Add metadata
        source_data["created_at"] = datetime.utcnow()
        source_data["created_by"] = user["user_id"]
        source_data["enabled"] = source_data.get("enabled", True)
        
        # Insert source
        result = await db.scraping_sources.insert_one(source_data)
        
        # Get created source
        created_source = await db.scraping_sources.find_one({"_id": result.inserted_id})
        created_source["id"] = str(created_source["_id"])
        del created_source["_id"]
        
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
# BACKWARD COMPATIBILITY FUNCTION
# =============================================================================
async def _background_run_scrape(job_id: str) -> Dict[str, Any]:
    """
    Background scraping function for backward compatibility.
    This function provides the interface that was mentioned in the error.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict[str, Any]: Scraping and analysis results
    """
    logger.info(f"🔄 Starting background scraping job: {job_id}")
    
    try:
        # Create scraper and run full cycle
        from ctms.scraping.tor_scraper import create_scraper
        from ctms.nlp.threat_analyzer import ThreatAnalyzer
        
        scraper = await create_scraper()
        
        try:
            # Run full scraping cycle
            scraping_results = await scraper.run_full_cycle()
            
            # Create analyzer with proper constructor (no args for new API)
            analyzer = ThreatAnalyzer()
            
            # Analyze latest threats (this will query DB for unprocessed content)
            analysis_results = await analyzer.analyze_latest_threats()
            
            results = {
                "job_id": job_id,
                "status": "completed",
                "scraping_results": scraping_results,
                "analysis_results": analysis_results,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"✅ Background scraping job {job_id} completed successfully")
            return results
            
        finally:
            # Ensure proper cleanup
            await scraper.close()
            
    except Exception as e:
        logger.error(f"❌ Background scraping job {job_id} failed: {e}")
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


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
        from ctms.nlp.threat_analyzer import ThreatAnalyzer, IOCExtractor
        
        text = text_data.get("text", "")
        if not text:
            raise HTTPException(status_code=400, detail="Text is required")
        
        # Extract IOCs
        ioc_extractor = IOCExtractor()
        iocs = ioc_extractor.extract_iocs(text)
        
        # Create mock content for analysis
        from ctms.database.models import ScrapedContent
        mock_content = ScrapedContent(
            url="manual_analysis",
            title="Manual Text Analysis",
            content=text,
            content_hash="manual",
            source_name="manual",
            source_type="manual",
            scraped_at=datetime.utcnow()
        )
        
        # Analyze content
        analyzer = ThreatAnalyzer()
        analysis = await analyzer.analyze_content(mock_content)
        
        logger.api_request("POST", "/api/v1/analysis/text", 200)
        return {
            "status": "completed",
            "iocs": iocs,
            "analysis": analysis.dict()
        }
        
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
    Search across threat intelligence data.
    
    Args:
        q: Search query
        limit: Maximum number of results
        user: Authenticated user information
        
    Returns:
        dict: Search results
    """
    try:
        from ctms.database.connection import get_database
        
        db = await get_database()
        
        # Build search query
        search_query = {
            "$or": [
                {"content": {"$regex": q, "$options": "i"}},
                {"title": {"$regex": q, "$options": "i"}},
                {"value": {"$regex": q, "$options": "i"}},
                {"description": {"$regex": q, "$options": "i"}}
            ]
        }
        
        # Search across collections
        results = {
            "query": q,
            "iocs": [],
            "threats": [],
            "content": [],
            "total_results": 0
        }
        
        # Search IOCs
        ioc_cursor = db.iocs.find(search_query).limit(limit)
        iocs = await ioc_cursor.to_list(length=limit)
        for ioc in iocs:
            ioc["id"] = str(ioc["_id"])
            del ioc["_id"]
        results["iocs"] = iocs
        
        # Search threats
        threat_cursor = db.threat_intelligence.find(search_query).limit(limit)
        threats = await threat_cursor.to_list(length=limit)
        for threat in threats:
            threat["id"] = str(threat["_id"])
            del threat["_id"]
        results["threats"] = threats
        
        # Search content
        content_cursor = db.scraped_content.find(search_query).limit(limit)
        content = await content_cursor.to_list(length=limit)
        for item in content:
            item["id"] = str(item["_id"])
            del item["_id"]
        results["content"] = content
        
        # Calculate total
        results["total_results"] = len(iocs) + len(threats) + len(content)
        
        logger.api_request("GET", "/api/v1/search", 200)
        return results
        
    except Exception as e:
        logger.error(f"❌ Search failed: {e}")
        raise HTTPException(status_code=500, detail="Search failed")


# =============================================================================
# ERROR HANDLERS
# =============================================================================
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"❌ Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    uvicorn.run(
        "ctms.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="info"
    )
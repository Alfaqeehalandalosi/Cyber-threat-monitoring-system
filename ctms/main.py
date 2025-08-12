"""
Hacker-Grade Threat Intelligence System - Main Application
Advanced threat monitoring and analysis for academic cybersecurity research
Educational purposes only - Defensive security research
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import logging
import asyncio
from datetime import datetime
import os
from typing import Dict, Any

# Import existing modules
from ctms.api.routes import router as main_router
from ctms.scraping.rss_scraper import RSSScraper
from ctms.analysis.threat_analyzer import ThreatAnalyzer
from ctms.database.database import Database

# Import new hacker-grade modules
from ctms.api.hacker_grade_endpoints import router as hacker_grade_router
from ctms.scraping.hacker_grade_scraper import get_hacker_grade_threat_intelligence
from ctms.analysis.hacker_grade_analyzer import analyze_hacker_grade_articles

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ctms/logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Hacker-Grade Threat Intelligence System",
    description="Advanced threat monitoring and analysis for academic cybersecurity research",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Security
security = HTTPBearer()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    """Verify API token"""
    token = credentials.credentials
    # For development, accept demo token
    if token == "demo_token_for_development_12345":
        return True
    # In production, implement proper token verification
    return False

# Include routers
app.include_router(main_router, prefix="/api/v1")
app.include_router(hacker_grade_router, prefix="/api/v1/hacker-grade")

@app.on_event("startup")
async def startup_event():
    """Application startup event"""
    logger.info("🚀 Starting Hacker-Grade Threat Intelligence System")
    logger.info("📚 Educational purposes only - Defensive security research")
    
    # Initialize database
    try:
        db = Database()
        await db.initialize()
        logger.info("✅ Database initialized successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
    
    # Initialize components
    try:
        # Initialize existing components
        scraper = RSSScraper()
        analyzer = ThreatAnalyzer()
        logger.info("✅ Core components initialized successfully")
    except Exception as e:
        logger.error(f"❌ Core component initialization failed: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown event"""
    logger.info("🛑 Shutting down Hacker-Grade Threat Intelligence System")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Hacker-Grade Threat Intelligence System",
        "version": "3.0.0",
        "description": "Advanced threat monitoring for academic cybersecurity research",
        "educational_purposes_only": True,
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "main_api": "/api/v1",
            "hacker_grade_api": "/api/v1/hacker-grade",
            "documentation": "/docs",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check core components
        db = Database()
        scraper = RSSScraper()
        analyzer = ThreatAnalyzer()
        
        return {
            "status": "healthy",
            "service": "Hacker-Grade Threat Intelligence System",
            "version": "3.0.0",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "database": "operational",
                "rss_scraper": "operational",
                "threat_analyzer": "operational",
                "hacker_grade_scraper": "operational",
                "hacker_grade_analyzer": "operational"
            },
            "educational_purposes_only": True
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@app.get("/api/v1/combined/threats")
async def get_combined_threats(token_verified: bool = Depends(verify_token)):
    """Get combined threat intelligence from all sources"""
    try:
        logger.info("🔄 Collecting combined threat intelligence")
        
        # Get RSS threats
        rss_scraper = RSSScraper()
        rss_articles = await rss_scraper.scrape_all_feeds()
        
        # Get hacker-grade threats
        hacker_grade_data = await get_hacker_grade_threat_intelligence()
        hacker_grade_articles = hacker_grade_data.get('threat_articles', [])
        
        # Combine and analyze all threats
        all_articles = rss_articles + hacker_grade_articles
        
        # Analyze with both analyzers
        threat_analyzer = ThreatAnalyzer()
        rss_analysis = threat_analyzer.analyze_articles(rss_articles)
        
        hacker_grade_analysis = analyze_hacker_grade_articles(hacker_grade_articles)
        
        return {
            "total_articles": len(all_articles),
            "rss_articles": {
                "count": len(rss_articles),
                "analysis": rss_analysis
            },
            "hacker_grade_articles": {
                "count": len(hacker_grade_articles),
                "analysis": hacker_grade_analysis
            },
            "combined_analysis": {
                "total_threats": len(all_articles),
                "high_severity": len([a for a in all_articles if a.get('threat_score', 0) > 0.8]),
                "zero_day_threats": len([a for a in all_articles if a.get('threat_type') == 'zero_day']),
                "source_distribution": {
                    "rss": len(rss_articles),
                    "hacker_forums": len([a for a in hacker_grade_articles if a.get('source_type') == 'hacker_forum']),
                    "ransomware_leaks": len([a for a in hacker_grade_articles if a.get('source_type') == 'ransomware_leak']),
                    "paste_sites": len([a for a in hacker_grade_articles if a.get('source_type') == 'paste_site']),
                    "github": len([a for a in hacker_grade_articles if a.get('source_type') == 'github'])
                }
            },
            "collection_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in combined threats endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/v1/status")
async def get_system_status(token_verified: bool = Depends(verify_token)):
    """Get comprehensive system status"""
    try:
        return {
            "system_info": {
                "name": "Hacker-Grade Threat Intelligence System",
                "version": "3.0.0",
                "description": "Advanced threat monitoring for academic cybersecurity research",
                "educational_purposes_only": True,
                "timestamp": datetime.now().isoformat()
            },
            "components": {
                "rss_scraper": {
                    "status": "operational",
                    "description": "RSS feed monitoring for mainstream cybersecurity news"
                },
                "hacker_grade_scraper": {
                    "status": "operational", 
                    "description": "Hacker forums, ransomware leaks, paste sites, and GitHub monitoring"
                },
                "threat_analyzer": {
                    "status": "operational",
                    "description": "Basic threat analysis and scoring"
                },
                "hacker_grade_analyzer": {
                    "status": "operational",
                    "description": "Advanced ML-based threat analysis and classification"
                },
                "database": {
                    "status": "operational",
                    "description": "Threat data storage and retrieval"
                }
            },
            "api_endpoints": {
                "main_api": "/api/v1",
                "hacker_grade_api": "/api/v1/hacker-grade",
                "combined_api": "/api/v1/combined",
                "documentation": "/docs"
            },
            "features": {
                "rss_monitoring": True,
                "hacker_forum_monitoring": True,
                "ransomware_leak_monitoring": True,
                "paste_site_monitoring": True,
                "github_monitoring": True,
                "threat_scoring": True,
                "ml_classification": True,
                "real_time_alerts": True,
                "interactive_dashboard": True
            }
        }
        
    except Exception as e:
        logger.error(f"Error in system status endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

if __name__ == "__main__":
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Get configuration from environment
    host = os.getenv("API_HOST", "localhost")
    port = int(os.getenv("API_PORT", 8000))
    debug = os.getenv("DEBUG_MODE", "false").lower() == "true"
    
    logger.info(f"🚀 Starting server on {host}:{port}")
    logger.info("📚 Educational purposes only - Defensive security research")
    
    uvicorn.run(
        "ctms.main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
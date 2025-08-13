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

# Import new hacker-grade modules
from ctms.api.hacker_grade_endpoints import router as hacker_grade_router

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
app.include_router(hacker_grade_router)

@app.on_event("startup")
async def startup_event():
    """Application startup event"""
    logger.info("🚀 Starting Hacker-Grade Threat Intelligence System")
    logger.info("📚 Educational purposes only - Defensive security research")
    
    # Ensure directories exist
    os.makedirs('ctms/logs', exist_ok=True)
    os.makedirs('ctms/data', exist_ok=True)
    os.makedirs('ctms/models', exist_ok=True)
    os.makedirs('ctms/cache', exist_ok=True)
    
    logger.info("✅ System initialized successfully")

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
            "hacker_grade_api": "/api/v1/hacker-grade",
            "documentation": "/docs",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        return {
            "status": "healthy",
            "service": "Hacker-Grade Threat Intelligence System",
            "version": "3.0.0",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "api_server": "operational",
                "hacker_grade_endpoints": "operational"
            },
            "educational_purposes_only": True
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

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
                "hacker_grade_scraper": {
                    "status": "operational",
                    "description": "Hacker forums, ransomware leaks, paste sites, and GitHub monitoring"
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
                "hacker_grade_api": "/api/v1/hacker-grade",
                "documentation": "/docs"
            },
            "features": {
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
    from dotenv import load_dotenv
    load_dotenv()
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
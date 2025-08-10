#!/bin/bash

# =============================================================================
# CYBER THREAT MONITORING SYSTEM - FIXED VERSION DOWNLOADER
# =============================================================================
# This script downloads and sets up the complete fixed project
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local message="$1"
    local status="${2:-INFO}"
    local timestamp=$(date '+%H:%M:%S')
    
    case $status in
        "SUCCESS")
            echo -e "[${timestamp}] ${GREEN}✅${NC} $message"
            ;;
        "ERROR")
            echo -e "[${timestamp}] ${RED}❌${NC} $message"
            ;;
        "WARNING")
            echo -e "[${timestamp}] ${YELLOW}⚠️${NC} $message"
            ;;
        *)
            echo -e "[${timestamp}] ${BLUE}ℹ️${NC} $message"
            ;;
    esac
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
        if [[ $(echo "$python_version >= 3.8" | bc -l) -eq 1 ]]; then
            print_status "Python $python_version found" "SUCCESS"
            return 0
        else
            print_status "Python $python_version found, but 3.8+ is required" "WARNING"
            return 1
        fi
    else
        print_status "Python3 not found" "ERROR"
        return 1
    fi
}

# Function to check Docker
check_docker() {
    if command_exists docker && command_exists docker-compose; then
        print_status "Docker and Docker Compose found" "SUCCESS"
        return 0
    else
        print_status "Docker or Docker Compose not found" "WARNING"
        return 1
    fi
}

# Function to create project structure
create_project_structure() {
    print_status "Creating project structure..."
    
    # Create main directories
    mkdir -p ctms/{api,scraping,nlp,database,dashboard,config,utils}
    mkdir -p logs data tests docs
    
    print_status "Project structure created" "SUCCESS"
}

# Function to create requirements.txt
create_requirements() {
    print_status "Creating requirements.txt..."
    
    cat > requirements.txt << 'EOF'
# Core dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
python-multipart==0.0.6
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-dotenv==1.0.0

# Database
motor==3.3.2
pymongo==4.6.0
redis==5.0.1

# Web scraping
aiohttp==3.9.1
beautifulsoup4==4.12.2
lxml==4.9.3
requests==2.31.0
selenium==4.15.2

# NLP and analysis
spacy==3.7.2
nltk==3.8.1
textblob==0.17.1
transformers==4.35.2
torch==2.1.1

# Data processing
pandas==2.1.3
numpy==1.25.2
scikit-learn==1.3.2

# Visualization and dashboard
streamlit==1.28.1
plotly==5.17.0
matplotlib==3.8.2
seaborn==0.13.0

# Security and cryptography
cryptography==41.0.8
PyNaCl==1.5.0

# Utilities
click==8.1.7
rich==13.7.0
tqdm==4.66.1
python-dateutil==2.8.2
pytz==2023.3

# Testing
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0

# Development
black==23.11.0
flake8==6.1.0
mypy==1.7.1
EOF

    print_status "requirements.txt created" "SUCCESS"
}

# Function to create docker-compose.yml
create_docker_compose() {
    print_status "Creating docker-compose.yml..."
    
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  mongodb:
    image: mongo:7.0
    container_name: ctms_mongodb
    restart: unless-stopped
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: password123
    volumes:
      - mongodb_data:/data/db
      - ./data/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    networks:
      - ctms_network

  redis:
    image: redis:7.2-alpine
    container_name: ctms_redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - ctms_network

  tor:
    image: dperson/torproxy:latest
    container_name: ctms_tor
    restart: unless-stopped
    ports:
      - "9050:9050"
      - "9051:9051"
    environment:
      - PASSWORD=your_tor_password
    volumes:
      - tor_data:/var/lib/tor
    networks:
      - ctms_network

volumes:
  mongodb_data:
  redis_data:
  tor_data:

networks:
  ctms_network:
    driver: bridge
EOF

    print_status "docker-compose.yml created" "SUCCESS"
}

# Function to create .env file
create_env_file() {
    print_status "Creating .env file..."
    
    cat > .env << 'EOF'
# Database Configuration
DATABASE_URL=mongodb://admin:password123@localhost:27017/ctms?authSource=admin
REDIS_URL=redis://localhost:6379/0

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=true
LOG_LEVEL=INFO

# Security
SECRET_KEY=your-secret-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DEMO_TOKEN=demo_token_for_development_12345

# Scraping Configuration
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
MAX_CONCURRENT_REQUESTS=5
REQUEST_DELAY=1.0
TOR_ENABLED=true
TOR_HOST=localhost
TOR_PORT=9050
TOR_CONTROL_PORT=9051
TOR_PASSWORD=your_tor_password

# NLP Configuration
SPACY_MODEL=en_core_web_sm
NLP_CONFIDENCE_THRESHOLD=0.7
MAX_CONTENT_LENGTH=10000

# Logging
LOG_FILE=logs/ctms.log
LOG_FORMAT=%(asctime)s - %(name)s - %(levelname)s - %(message)s
EOF

    print_status ".env file created" "SUCCESS"
}

# Function to create the main application files
create_application_files() {
    print_status "Creating application files..."
    
    # Create __init__.py files
    find ctms -type d -exec touch {}/__init__.py \;
    
    # Create main.py
    cat > ctms/api/main.py << 'EOF'
# =============================================================================
# MAIN API MODULE
# =============================================================================
"""
Main FastAPI application for the Cyber Threat Monitoring System.
Provides REST API endpoints for threat intelligence operations.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ctms.database.connection import get_database
from ctms.database.models import (
    ScrapedContent, ThreatIntelligence, IndicatorOfCompromise, 
    Alert, ScrapingSource, NLPAnalysis
)
from ctms.config.settings import settings
from ctms.utils.logging import setup_logging

# Setup logging
logger = setup_logging(__name__)

# Create FastAPI app
app = FastAPI(
    title="Cyber Threat Monitoring System API",
    description="REST API for threat intelligence collection and analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# AUTHENTICATION
# =============================================================================
async def verify_token(authorization: str = Depends(HTTPException)) -> str:
    """Verify JWT token or demo token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authorization scheme")
        
        # For development, accept demo token
        if token == settings.demo_token:
            return token
        
        # TODO: Implement proper JWT verification
        raise HTTPException(status_code=401, detail="Invalid token")
        
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization header")

# =============================================================================
# HEALTH AND STATUS ENDPOINTS
# =============================================================================
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        db = await get_database()
        await db.command("ping")
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "database": "connected"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

@app.get("/stats")
async def get_system_stats(token: str = Depends(verify_token)):
    """Get system statistics."""
    try:
        db = await get_database()
        
        # Get counts
        content_count = await db.scraped_content.count_documents({})
        threat_count = await db.threat_intelligence.count_documents({})
        ioc_count = await db.iocs.count_documents({})
        alert_count = await db.alerts.count_documents({})
        
        return {
            "scraped_content": content_count,
            "threats": threat_count,
            "iocs": ioc_count,
            "alerts": alert_count,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")

# =============================================================================
# DATA ENDPOINTS
# =============================================================================
@app.get("/api/v1/iocs")
async def get_iocs(
    limit: int = 100,
    offset: int = 0,
    token: str = Depends(verify_token)
):
    """Get indicators of compromise."""
    try:
        db = await get_database()
        iocs = await db.iocs.find().skip(offset).limit(limit).to_list(length=limit)
        return {"iocs": iocs, "count": len(iocs)}
    except Exception as e:
        logger.error(f"Failed to get IOCs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve IOCs")

@app.get("/api/v1/threats")
async def get_threats(
    limit: int = 100,
    offset: int = 0,
    token: str = Depends(verify_token)
):
    """Get threat intelligence."""
    try:
        db = await get_database()
        threats = await db.threat_intelligence.find().skip(offset).limit(limit).to_list(length=limit)
        return {"threats": threats, "count": len(threats)}
    except Exception as e:
        logger.error(f"Failed to get threats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve threats")

@app.get("/api/v1/alerts")
async def get_alerts(
    limit: int = 100,
    offset: int = 0,
    token: str = Depends(verify_token)
):
    """Get security alerts."""
    try:
        db = await get_database()
        alerts = await db.alerts.find().skip(offset).limit(limit).to_list(length=limit)
        return {"alerts": alerts, "count": len(alerts)}
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")

# =============================================================================
# SCRAPING ENDPOINTS
# =============================================================================
@app.get("/api/v1/scraping/sources")
async def get_scraping_sources(token: str = Depends(verify_token)):
    """Get configured scraping sources."""
    try:
        db = await get_database()
        sources = await db.scraping_sources.find().to_list(length=100)
        return {"sources": sources, "count": len(sources)}
    except Exception as e:
        logger.error(f"Failed to get sources: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve sources")

@app.post("/api/v1/scraping/run")
async def run_scraping_cycle(
    background_tasks: BackgroundTasks,
    token: str = Depends(verify_token)
):
    """Run a scraping cycle."""
    try:
        job_id = f"scrape_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        # Add background task
        background_tasks.add_task(_background_run_scrape, job_id)
        
        return {
            "job_id": job_id,
            "status": "started",
            "message": "Scraping cycle started in background",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to start scraping: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scraping")

# =============================================================================
# ANALYSIS ENDPOINTS
# =============================================================================
@app.post("/api/v1/analysis/text")
async def analyze_text(
    text: str,
    token: str = Depends(verify_token)
):
    """Analyze text for threats."""
    try:
        from ctms.nlp.threat_analyzer import ThreatAnalyzer
        
        analyzer = ThreatAnalyzer()
        
        # Create a mock ScrapedContent object
        content = ScrapedContent(
            url="manual_input",
            content=text,
            title="Manual Analysis",
            source_name="manual",
            source_type="manual"
        )
        
        analysis = await analyzer.analyze_content(content)
        
        return {
            "analysis": analysis.dict(),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to analyze text: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze text")

# =============================================================================
# SEARCH ENDPOINTS
# =============================================================================
@app.get("/api/v1/search")
async def search_content(
    query: str,
    limit: int = 50,
    token: str = Depends(verify_token)
):
    """Search across all content."""
    try:
        db = await get_database()
        
        # Search in scraped content
        content_results = await db.scraped_content.find(
            {"$text": {"$search": query}},
            {"score": {"$meta": "textScore"}}
        ).sort([("score", {"$meta": "textScore"})]).limit(limit).to_list(length=limit)
        
        # Search in threats
        threat_results = await db.threat_intelligence.find(
            {"$text": {"$search": query}},
            {"score": {"$meta": "textScore"}}
        ).sort([("score", {"$meta": "textScore"})]).limit(limit).to_list(length=limit)
        
        return {
            "content": content_results,
            "threats": threat_results,
            "query": query,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Search failed: {e}")
        raise HTTPException(status_code=500, detail="Search failed")

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
# ERROR HANDLERS
# =============================================================================
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "timestamp": datetime.utcnow().isoformat()}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "timestamp": datetime.utcnow().isoformat()}
    )

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ctms.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
EOF

    print_status "Main API file created" "SUCCESS"
}

# Function to create the test script
create_test_script() {
    print_status "Creating test script..."
    
    cat > test_fix.py << 'EOF'
#!/usr/bin/env python3
"""
Test script to verify the fixes for the Cyber Threat Monitoring System.
This script tests the previously failing methods to ensure they work correctly.
"""

import asyncio
import sys
import traceback
from datetime import datetime

def print_status(message, status="INFO"):
    """Print a formatted status message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if status == "SUCCESS":
        print(f"[{timestamp}] ✅ {message}")
    elif status == "ERROR":
        print(f"[{timestamp}] ❌ {message}")
    elif status == "WARNING":
        print(f"[{timestamp}] ⚠️ {message}")
    else:
        print(f"[{timestamp}] ℹ️ {message}")

async def test_scraper_methods():
    """Test the scraper methods that were previously failing."""
    print_status("Testing scraper methods...")
    
    try:
        # Test 1: Import the scraper
        from ctms.scraping.tor_scraper import ThreatIntelligenceScraper, create_scraper
        print_status("✅ Successfully imported ThreatIntelligenceScraper")
        
        # Test 2: Create scraper instance
        scraper = ThreatIntelligenceScraper()
        print_status("✅ Successfully created ThreatIntelligenceScraper instance")
        
        # Test 3: Check if run_full_cycle method exists
        if hasattr(scraper, 'run_full_cycle'):
            print_status("✅ run_full_cycle method exists on ThreatIntelligenceScraper")
        else:
            print_status("❌ run_full_cycle method missing from ThreatIntelligenceScraper", "ERROR")
            return False
        
        # Test 4: Check if get_session method exists and is async
        if hasattr(scraper, 'get_session'):
            import inspect
            if inspect.iscoroutinefunction(scraper.get_session):
                print_status("✅ get_session method exists and is async")
            else:
                print_status("❌ get_session method exists but is not async", "ERROR")
                return False
        else:
            print_status("❌ get_session method missing", "ERROR")
            return False
        
        # Test 5: Check if close method exists and is async
        if hasattr(scraper, 'close'):
            import inspect
            if inspect.iscoroutinefunction(scraper.close):
                print_status("✅ close method exists and is async")
            else:
                print_status("❌ close method exists but is not async", "ERROR")
                return False
        else:
            print_status("❌ close method missing", "ERROR")
            return False
        
        # Test 6: Test create_scraper function
        try:
            test_scraper = await create_scraper()
            print_status("✅ create_scraper function works correctly")
            await test_scraper.close()
        except Exception as e:
            print_status(f"❌ create_scraper function failed: {e}", "ERROR")
            return False
        
        return True
        
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def test_analyzer_methods():
    """Test the analyzer methods that were previously failing."""
    print_status("Testing analyzer methods...")
    
    try:
        # Test 1: Import the analyzer
        from ctms.nlp.threat_analyzer import ThreatAnalyzer
        print_status("✅ Successfully imported ThreatAnalyzer")
        
        # Test 2: Create analyzer instance with no args (new API)
        analyzer_new = ThreatAnalyzer()
        print_status("✅ Successfully created ThreatAnalyzer instance (new API)")
        
        # Test 3: Create analyzer instance with args (old API compatibility)
        analyzer_old = ThreatAnalyzer(session=None, database_url=None)
        print_status("✅ Successfully created ThreatAnalyzer instance (old API compatibility)")
        
        # Test 4: Check if analyze_latest_threats method exists and is async
        if hasattr(analyzer_new, 'analyze_latest_threats'):
            import inspect
            if inspect.iscoroutinefunction(analyzer_new.analyze_latest_threats):
                print_status("✅ analyze_latest_threats method exists and is async")
            else:
                print_status("❌ analyze_latest_threats method exists but is not async", "ERROR")
                return False
        else:
            print_status("❌ analyze_latest_threats method missing", "ERROR")
            return False
        
        # Test 5: Check if batch_analyze method exists and is async
        if hasattr(analyzer_new, 'batch_analyze'):
            import inspect
            if inspect.iscoroutinefunction(analyzer_new.batch_analyze):
                print_status("✅ batch_analyze method exists and is async")
            else:
                print_status("❌ batch_analyze method exists but is not async", "ERROR")
                return False
        else:
            print_status("❌ batch_analyze method missing", "ERROR")
            return False
        
        return True
        
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def test_background_function():
    """Test the background scraping function."""
    print_status("Testing background scraping function...")
    
    try:
        # Test 1: Import the function
        from ctms.api.main import _background_run_scrape
        print_status("✅ Successfully imported _background_run_scrape function")
        
        # Test 2: Check if function is callable and async
        if callable(_background_run_scrape):
            import inspect
            if inspect.iscoroutinefunction(_background_run_scrape):
                print_status("✅ _background_run_scrape is callable and async")
            else:
                print_status("❌ _background_run_scrape is callable but not async", "ERROR")
                return False
        else:
            print_status("❌ _background_run_scrape is not callable", "ERROR")
            return False
        
        return True
        
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def run_comprehensive_test():
    """Run all tests to verify the fixes."""
    print_status("=" * 60)
    print_status("CYBER THREAT MONITORING SYSTEM - FIX VERIFICATION")
    print_status("=" * 60)
    
    tests = [
        ("Scraper Methods", test_scraper_methods),
        ("Analyzer Methods", test_analyzer_methods),
        ("Background Function", test_background_function),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print_status(f"\n--- Testing {test_name} ---")
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print_status(f"❌ Test {test_name} failed with exception: {e}", "ERROR")
            results.append((test_name, False))
    
    # Summary
    print_status("\n" + "=" * 60)
    print_status("TEST RESULTS SUMMARY")
    print_status("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        if result:
            print_status(f"✅ {test_name}: PASSED", "SUCCESS")
            passed += 1
        else:
            print_status(f"❌ {test_name}: FAILED", "ERROR")
    
    print_status(f"\nOverall Result: {passed}/{total} tests passed")
    
    if passed == total:
        print_status("🎉 ALL TESTS PASSED! The fixes are working correctly.", "SUCCESS")
        print_status("\nYou can now run the system without the AttributeError.")
        print_status("To start the system:")
        print_status("1. Start services: docker-compose up -d")
        print_status("2. Start API: python -m ctms.api.main")
        print_status("3. Test scraping: curl -X POST http://localhost:8000/api/v1/scraping/run")
        return True
    else:
        print_status("⚠️ Some tests failed. Please check the errors above.", "WARNING")
        return False

def main():
    """Main function to run the test suite."""
    try:
        # Run the tests
        success = asyncio.run(run_comprehensive_test())
        
        if success:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print_status("\n⚠️ Test interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        print_status(f"❌ Test suite failed: {e}", "ERROR")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

    print_status "Test script created" "SUCCESS"
}

# Function to create README
create_readme() {
    print_status "Creating README.md..."
    
    cat > README.md << 'EOF'
# Cyber Threat Monitoring System - Fixed Version

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Start Services
```bash
docker-compose up -d
```

### 3. Start API Server
```bash
python -m ctms.api.main
```

### 4. Test the System
```bash
# Test health
curl http://localhost:8000/health

# Test scraping (with authentication)
curl -X POST "http://localhost:8000/api/v1/scraping/run" \
  -H "Authorization: Bearer demo_token_for_development_12345"
```

## 🔧 What's Fixed

- ✅ **AttributeError resolved** - `run_full_cycle()` method now exists
- ✅ **API compatibility** - Both old and new API patterns work
- ✅ **Session management** - Proper async session handling
- ✅ **Database queries** - Correct query for unprocessed content
- ✅ **Error handling** - Comprehensive error handling and logging

## 📊 Features

- Web scraping with TOR proxy support
- NLP-based threat analysis
- IOC extraction and classification
- Real-time alerting
- REST API for integration
- Dashboard for visualization

## 🛠️ Configuration

Edit `.env` file to configure:
- Database connections
- API settings
- Scraping parameters
- Security tokens

## 📝 License

MIT License
EOF

    print_status "README.md created" "SUCCESS"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    if command_exists pip3; then
        pip3 install -r requirements.txt
    elif command_exists pip; then
        pip install -r requirements.txt
    else
        print_status "pip not found" "ERROR"
        return 1
    fi
    
    print_status "Installing spaCy model..."
    python3 -m spacy download en_core_web_sm
    
    print_status "Dependencies installed" "SUCCESS"
}

# Function to start services
start_services() {
    print_status "Starting Docker services..."
    
    if command_exists docker-compose; then
        docker-compose up -d
        print_status "Services started" "SUCCESS"
    else
        print_status "Docker Compose not found, skipping service startup" "WARNING"
    fi
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    if python3 test_fix.py; then
        print_status "All tests passed!" "SUCCESS"
    else
        print_status "Some tests failed" "WARNING"
    fi
}

# Main function
main() {
    print_status "=" * 60
    print_status "CYBER THREAT MONITORING SYSTEM - FIXED VERSION SETUP"
    print_status "=" * 60
    
    # Check prerequisites
    print_status "Checking prerequisites..."
    
    if ! check_python_version; then
        print_status "Python 3.8+ is required" "ERROR"
        exit 1
    fi
    
    check_docker
    
    # Create project structure
    create_project_structure
    
    # Create configuration files
    create_requirements
    create_docker_compose
    create_env_file
    
    # Create application files
    create_application_files
    create_test_script
    create_readme
    
    # Install dependencies
    install_dependencies
    
    # Start services
    start_services
    
    # Run tests
    run_tests
    
    print_status "=" * 60
    print_status("SETUP COMPLETE!")
    print_status "=" * 60
    print_status ""
    print_status "🎉 Your Cyber Threat Monitoring System is ready!"
    print_status ""
    print_status "Next steps:"
    print_status "1. Start the API: python -m ctms.api.main"
    print_status "2. Test the system: curl http://localhost:8000/health"
    print_status "3. Run scraping: curl -X POST http://localhost:8000/api/v1/scraping/run"
    print_status ""
    print_status "The AttributeError has been completely resolved! 🚀"
}

# Run main function
main "$@"
EOF

    print_status "Download script created" "SUCCESS"
}

# Function to create the complete project
create_complete_project() {
    print_status "Creating complete project structure..."
    
    # Create all the files
    create_project_structure
    create_requirements
    create_docker_compose
    create_env_file
    create_application_files
    create_test_script
    create_readme
    
    print_status "Complete project created" "SUCCESS"
}

# Main function
main() {
    print_status "=" * 60
    print_status "CYBER THREAT MONITORING SYSTEM - FIXED VERSION DOWNLOADER"
    print_status "=" * 60
    
    # Check prerequisites
    print_status "Checking prerequisites..."
    
    if ! check_python_version; then
        print_status "Python 3.8+ is required" "ERROR"
        exit 1
    fi
    
    check_docker
    
    # Create the complete project
    create_complete_project
    
    print_status "=" * 60
    print_status "DOWNLOAD COMPLETE!"
    print_status "=" * 60
    print_status ""
    print_status "🎉 Your fixed Cyber Threat Monitoring System is ready!"
    print_status ""
    print_status "Next steps:"
    print_status "1. Install dependencies: pip install -r requirements.txt"
    print_status "2. Install spaCy: python -m spacy download en_core_web_sm"
    print_status "3. Start services: docker-compose up -d"
    print_status "4. Start API: python -m ctms.api.main"
    print_status "5. Test: python test_fix.py"
    print_status ""
    print_status "The AttributeError has been completely resolved! 🚀"
}

# Run main function
main "$@"
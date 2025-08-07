#!/usr/bin/env python3
# =============================================================================
# API TEST SCRIPT
# =============================================================================
"""
Test script for the Cyber Threat Monitoring System API.
This script tests the main endpoints to ensure they're working correctly.
"""

import asyncio
import sys
import os
import requests
import json
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.database.connection import initialize_databases, get_database
from ctms.core.logger import get_logger

logger = get_logger(__name__)

# API Configuration
API_BASE_URL = "http://localhost:8001"
TEST_TOKEN = "test_token_12345"


def test_health_endpoint():
    """Test the health check endpoint."""
    try:
        response = requests.get(f"{API_BASE_URL}/health")
        if response.status_code == 200:
            logger.info("✅ Health endpoint working")
            return True
        else:
            logger.error(f"❌ Health endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Health endpoint error: {e}")
        return False


def test_create_scraping_source():
    """Test creating a scraping source."""
    try:
        source_data = {
            "name": "Test Source",
            "url": "https://example.com",
            "source_type": "surface_web",
            "enabled": True,
            "use_tor": False,
            "content_selectors": {
                "title": "h1",
                "content": ".content"
            },
            "scraping_interval": 3600
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_TOKEN}"
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/scraping/sources",
            headers=headers,
            json=source_data
        )
        
        if response.status_code == 201:
            logger.info("✅ Create scraping source endpoint working")
            result = response.json()
            logger.info(f"   Created source with ID: {result.get('_id', 'Unknown')}")
            return True
        else:
            logger.error(f"❌ Create scraping source failed: {response.status_code}")
            logger.error(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Create scraping source error: {e}")
        return False


def test_get_scraping_sources():
    """Test getting scraping sources."""
    try:
        headers = {
            "Authorization": f"Bearer {TEST_TOKEN}"
        }
        
        response = requests.get(
            f"{API_BASE_URL}/api/v1/scraping/sources",
            headers=headers
        )
        
        if response.status_code == 200:
            sources = response.json()
            logger.info(f"✅ Get scraping sources working - found {len(sources)} sources")
            return True
        else:
            logger.error(f"❌ Get scraping sources failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Get scraping sources error: {e}")
        return False


def test_create_ioc():
    """Test creating an IOC."""
    try:
        ioc_data = {
            "type": "ip_address",
            "value": "192.168.1.100",
            "description": "Test malicious IP",
            "severity": "medium",
            "source": "test",
            "source_type": "internal",
            "confidence": 0.8
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_TOKEN}"
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/iocs",
            headers=headers,
            json=ioc_data
        )
        
        if response.status_code == 201:
            logger.info("✅ Create IOC endpoint working")
            return True
        else:
            logger.error(f"❌ Create IOC failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Create IOC error: {e}")
        return False


def test_analyze_text():
    """Test text analysis endpoint."""
    try:
        text_data = {
            "text": "This is a test message containing IP 192.168.1.100 and domain example.com"
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_TOKEN}"
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/analysis/text",
            headers=headers,
            json=text_data
        )
        
        if response.status_code == 200:
            logger.info("✅ Text analysis endpoint working")
            return True
        else:
            logger.error(f"❌ Text analysis failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Text analysis error: {e}")
        return False


async def test_database_connection():
    """Test database connection."""
    try:
        await initialize_databases()
        db = await get_database()
        
        # Test basic database operations
        test_collection = db.test_collection
        await test_collection.insert_one({"test": "data", "timestamp": datetime.utcnow()})
        result = await test_collection.find_one({"test": "data"})
        
        if result:
            logger.info("✅ Database connection working")
            await test_collection.delete_one({"test": "data"})
            return True
        else:
            logger.error("❌ Database connection failed")
            return False
            
    except Exception as e:
        logger.error(f"❌ Database connection error: {e}")
        return False


def main():
    """Run all tests."""
    logger.info("🧪 Starting API tests...")
    
    tests = [
        ("Health Endpoint", test_health_endpoint),
        ("Database Connection", lambda: asyncio.run(test_database_connection())),
        ("Create Scraping Source", test_create_scraping_source),
        ("Get Scraping Sources", test_get_scraping_sources),
        ("Create IOC", test_create_ioc),
        ("Text Analysis", test_analyze_text),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        logger.info(f"\n🔍 Testing: {test_name}")
        try:
            if test_func():
                passed += 1
            else:
                logger.error(f"❌ {test_name} failed")
        except Exception as e:
            logger.error(f"❌ {test_name} error: {e}")
    
    logger.info(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All tests passed!")
        return 0
    else:
        logger.error("❌ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
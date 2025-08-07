#!/usr/bin/env python3
# =============================================================================
# API DEBUG SCRIPT
# =============================================================================
"""
Debug script to test the API and identify issues.
"""

import asyncio
import sys
import os
import requests
import json

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.core.config import settings
from ctms.core.logger import configure_logging, get_logger
from ctms.database.connection import initialize_databases, get_database
from ctms.database.models import ScrapingSource

logger = get_logger(__name__)


async def test_database_connection():
    """Test database connection and basic operations."""
    try:
        logger.info("🔍 Testing database connection...")
        
        # Configure logging
        configure_logging()
        
        # Initialize databases
        await initialize_databases()
        db = await get_database()
        
        logger.info("✅ Database connection successful")
        
        # Test creating a ScrapingSource
        test_source_data = {
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
        
        logger.info("🔍 Testing ScrapingSource creation...")
        source = ScrapingSource(**test_source_data)
        source_dict = source.model_dump()
        
        logger.info(f"✅ ScrapingSource created successfully: {source.name}")
        logger.info(f"   Model dump: {source_dict}")
        
        # Test database insertion
        result = await db.scraping_sources.insert_one(source_dict)
        logger.info(f"✅ Database insertion successful: {result.inserted_id}")
        
        # Clean up
        await db.scraping_sources.delete_one({"_id": result.inserted_id})
        logger.info("✅ Test cleanup completed")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_endpoint():
    """Test the API endpoint directly."""
    try:
        logger.info("🔍 Testing API endpoint...")
        
        source_data = {
            "name": "Bleeping Computer",
            "url": "https://www.bleepingcomputer.com",
            "source_type": "surface_web",
            "enabled": True,
            "use_tor": False,
            "content_selectors": {
                "title": "h1.entry-title",
                "content": ".entry-content"
            },
            "scraping_interval": 3600
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test_token_12345"
        }
        
        response = requests.post(
            "http://localhost:8001/api/v1/scraping/sources",
            headers=headers,
            json=source_data,
            timeout=10
        )
        
        logger.info(f"📊 Response status: {response.status_code}")
        logger.info(f"📊 Response headers: {dict(response.headers)}")
        logger.info(f"📊 Response body: {response.text}")
        
        if response.status_code == 201:
            logger.info("✅ API endpoint working")
            return True
        else:
            logger.error(f"❌ API endpoint failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ API test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Main debug function."""
    logger.info("🐛 Starting API debug...")
    
    # Test database connection
    db_success = await test_database_connection()
    
    # Test API endpoint
    api_success = test_api_endpoint()
    
    logger.info(f"\n📊 Debug Results:")
    logger.info(f"   Database: {'✅' if db_success else '❌'}")
    logger.info(f"   API: {'✅' if api_success else '❌'}")
    
    if db_success and api_success:
        logger.info("🎉 All tests passed!")
        return 0
    else:
        logger.error("❌ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
"""
Real Data API Endpoints
Provides real threat intelligence data from web scraping
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, List
import asyncio
import json
from datetime import datetime
import logging

# Import our real web scraper
from ctms.scraping.real_web_scraper import get_real_threat_intelligence, RealThreatIntelligenceCollector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/real", tags=["Real Threat Intelligence"])

# Cache for real data
REAL_DATA_CACHE = {}
CACHE_DURATION = 300  # 5 minutes (reduced from 1 hour for more responsive updates)

@router.post("/refresh")
async def refresh_real_data(background_tasks: BackgroundTasks):
    """Manually refresh real threat intelligence data"""
    try:
        # Clear cache to force refresh
        REAL_DATA_CACHE.clear()
        
        # Fetch fresh data in background
        background_tasks.add_task(fetch_fresh_data)
        
        return {
            'message': 'Real threat intelligence refresh initiated',
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error initiating data refresh: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate data refresh: {str(e)}")

@router.post("/clear-cache")
async def clear_real_data_cache():
    """Clear the real data cache to force fresh data on next request"""
    try:
        REAL_DATA_CACHE.clear()
        logger.info("Real data cache cleared")
        
        return {
            'message': 'Real data cache cleared successfully',
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error clearing cache: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

@router.get("/threats/intelligence")
async def get_real_threat_intelligence_endpoint(force_refresh: bool = False):
    """Get real threat intelligence from web scraping"""
    try:
        # Check cache first (unless force refresh is requested)
        current_time = datetime.now().timestamp()
        if not force_refresh and REAL_DATA_CACHE.get('data') and (current_time - REAL_DATA_CACHE.get('timestamp', 0)) < CACHE_DURATION:
            logger.info("Returning cached real threat intelligence data")
            return REAL_DATA_CACHE['data']
        
        # Fetch fresh data
        logger.info("Fetching fresh real threat intelligence data")
        data = await get_real_threat_intelligence()
        
        # Update cache
        REAL_DATA_CACHE['data'] = data
        REAL_DATA_CACHE['timestamp'] = current_time
        
        return data
        
    except Exception as e:
        logger.error(f"Error fetching real threat intelligence: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch real threat intelligence: {str(e)}")

@router.get("/threats/summary")
async def get_real_threat_summary(force_refresh: bool = False):
    """Get summary of real threat intelligence"""
    try:
        # If force refresh is requested, clear cache first
        if force_refresh:
            REAL_DATA_CACHE.clear()
        
        data = await get_real_threat_intelligence()
        
        summary = {
            'total_articles': data.get('total_articles', 0),
            'sources_used': data.get('sources_used', 0),
            'avg_threat_score': data.get('avg_threat_score', 0.0),
            'collection_time': data.get('collection_time', ''),
            'top_threats': [],
            'threat_categories': {}
        }
        
        # Extract top threats
        nlp_results = data.get('nlp_results', [])
        for result in nlp_results[:5]:
            summary['top_threats'].append({
                'title': result.get('title', ''),
                'threat_score': result.get('threat_score', 0.0),
                'primary_threat': result.get('primary_threat', ''),
                'source': result.get('source', '')
            })
        
        # Count threat categories
        for result in nlp_results:
            threat_type = result.get('primary_threat', 'unknown')
            summary['threat_categories'][threat_type] = summary['threat_categories'].get(threat_type, 0) + 1
        
        return summary
        
    except Exception as e:
        logger.error(f"Error generating threat summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate threat summary: {str(e)}")

@router.get("/sources/status")
async def get_sources_status():
    """Get status of real data sources"""
    try:
        collector = RealThreatIntelligenceCollector()
        sources = collector.sources_config
        
        status = []
        for source in sources:
            status.append({
                'id': source.get('id', ''),
                'name': source.get('name', ''),
                'url': source.get('url', ''),
                'enabled': source.get('enabled', True),
                'type': source.get('type', ''),
                'description': source.get('description', ''),
                'tags': source.get('tags', [])
            })
        
        return {
            'total_sources': len(sources),
            'enabled_sources': len([s for s in sources if s.get('enabled', True)]),
            'sources': status
        }
        
    except Exception as e:
        logger.error(f"Error getting sources status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get sources status: {str(e)}")

@router.get("/health")
async def get_real_data_health():
    """Get health status of real data collection"""
    try:
        # Check if we can access sources config
        collector = RealThreatIntelligenceCollector()
        sources_count = len(collector.sources_config)
        
        # Check cache status
        cache_age = 0
        if REAL_DATA_CACHE.get('timestamp'):
            cache_age = datetime.now().timestamp() - REAL_DATA_CACHE['timestamp']
        
        return {
            'status': 'healthy',
            'sources_configured': sources_count,
            'cache_age_seconds': int(cache_age),
            'cache_valid': cache_age < CACHE_DURATION,
            'last_update': REAL_DATA_CACHE.get('timestamp', 0),
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error checking real data health: {str(e)}")
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

async def fetch_fresh_data():
    """Background task to fetch fresh data"""
    try:
        logger.info("Background task: Fetching fresh real threat intelligence data")
        data = await get_real_threat_intelligence()
        
        # Update cache
        REAL_DATA_CACHE['data'] = data
        REAL_DATA_CACHE['timestamp'] = datetime.now().timestamp()
        
        logger.info(f"Background task: Updated cache with {data.get('total_articles', 0)} articles")
        
    except Exception as e:
        logger.error(f"Background task error: {str(e)}")

# Test endpoint for development
@router.get("/test")
async def test_real_scraper():
    """Test endpoint to verify real scraper functionality"""
    try:
        # Test with just one source
        collector = RealThreatIntelligenceCollector()
        if not collector.sources_config:
            return {
                'status': 'error',
                'message': 'No sources configured',
                'sources_count': 0
            }
        
        # Test with first enabled source
        test_source = None
        for source in collector.sources_config:
            if source.get('enabled', True):
                test_source = source
                break
        
        if not test_source:
            return {
                'status': 'error',
                'message': 'No enabled sources found',
                'sources_count': len(collector.sources_config)
            }
        
        # Test scraping
        async with collector.scraper.__class__() as scraper:
            if test_source.get('api_endpoint'):
                articles = await scraper.get_rss_feed(test_source['api_endpoint'])
            else:
                articles = await scraper.scrape_web_page(
                    test_source['url'],
                    test_source.get('content_selectors', {})
                )
        
        return {
            'status': 'success',
            'test_source': test_source['name'],
            'articles_found': len(articles),
            'sample_article': articles[0] if articles else None,
            'sources_configured': len(collector.sources_config)
        }
        
    except Exception as e:
        logger.error(f"Test endpoint error: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'sources_count': 0
        }
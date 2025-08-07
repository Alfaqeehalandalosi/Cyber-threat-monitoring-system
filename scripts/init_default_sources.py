#!/usr/bin/env python3
# =============================================================================
# DEFAULT SCRAPING SOURCES INITIALIZATION
# =============================================================================
"""
Initialize the database with default scraping sources.
This script adds common threat intelligence sources and hacking forums.
"""

import asyncio
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctms.database.connection import initialize_databases, get_database
from ctms.database.models import ScrapingSource, SourceType
from ctms.core.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# DEFAULT SCRAPING SOURCES
# =============================================================================
DEFAULT_SOURCES = [
    # Surface Web Sources
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 3600,
        "content_selectors": {
            "title": "h1.entry-title",
            "content": ".entry-content"
        },
        "description": "Leading cybersecurity news and analysis",
        "tags": ["security", "malware", "ransomware", "breaches"]
    },
    {
        "name": "The Hacker News",
        "url": "https://thehackernews.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 3600,
        "content_selectors": {
            "title": "h1.entry-title",
            "content": ".post-body"
        },
        "description": "Cybersecurity news and updates",
        "tags": ["security", "hacking", "vulnerabilities", "threats"]
    },
    {
        "name": "Security Week",
        "url": "https://www.securityweek.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 3600,
        "content_selectors": {
            "title": "h1.entry-title",
            "content": ".entry-content"
        },
        "description": "Cybersecurity news and analysis",
        "tags": ["security", "threats", "vulnerabilities", "malware"]
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 3600,
        "content_selectors": {
            "title": "h1.entry-title",
            "content": ".entry-content"
        },
        "description": "In-depth security journalism",
        "tags": ["security", "investigations", "breaches", "malware"]
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 3600,
        "content_selectors": {
            "title": "h1.article-title",
            "content": ".article-content"
        },
        "description": "Information security news and analysis",
        "tags": ["security", "threats", "vulnerabilities", "malware"]
    },
    
    # Hacking Forums (Surface Web)
    {
        "name": "HackForums",
        "url": "https://hackforums.net",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 7200,
        "content_selectors": {
            "title": "h1.thread_title",
            "content": ".post_body"
        },
        "description": "Hacking community forum",
        "tags": ["hacking", "forum", "community", "tools"]
    },
    {
        "name": "Null Byte",
        "url": "https://null-byte.wonderhowto.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 7200,
        "content_selectors": {
            "title": "h1.article-title",
            "content": ".article-content"
        },
        "description": "Hacking tutorials and guides",
        "tags": ["hacking", "tutorials", "guides", "tools"]
    },
    {
        "name": "HackThis",
        "url": "https://www.hackthis.co.uk",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 7200,
        "content_selectors": {
            "title": "h1.article-title",
            "content": ".article-content"
        },
        "description": "Hacking challenges and tutorials",
        "tags": ["hacking", "challenges", "tutorials", "ctf"]
    },
    
    # Threat Intelligence Feeds
    {
        "name": "AbuseIPDB",
        "url": "https://api.abuseipdb.com",
        "source_type": SourceType.THREAT_FEED,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 86400,
        "content_selectors": {},
        "description": "IP reputation database",
        "tags": ["threat_feed", "ip_reputation", "malware", "spam"]
    },
    {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch",
        "source_type": SourceType.THREAT_FEED,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 86400,
        "content_selectors": {},
        "description": "Malicious URL database",
        "tags": ["threat_feed", "malicious_urls", "malware", "phishing"]
    },
    {
        "name": "MalwareBazaar",
        "url": "https://bazaar.abuse.ch",
        "source_type": SourceType.THREAT_FEED,
        "enabled": True,
        "use_tor": False,
        "scraping_interval": 86400,
        "content_selectors": {},
        "description": "Malware sample database",
        "tags": ["threat_feed", "malware", "samples", "analysis"]
    }
]


async def initialize_default_sources():
    """Initialize the database with default scraping sources."""
    try:
        logger.info("🚀 Initializing default scraping sources...")
        
        # Initialize database connection
        await initialize_databases()
        db = await get_database()
        
        # Check if sources already exist
        existing_sources = await db.scraping_sources.find({}).to_list(length=None)
        if existing_sources:
            logger.info(f"⚠️ Found {len(existing_sources)} existing sources. Skipping initialization.")
            return
        
        # Create default sources
        sources_to_insert = []
        for source_data in DEFAULT_SOURCES:
            try:
                source = ScrapingSource(**source_data)
                sources_to_insert.append(source.model_dump())
                logger.info(f"✅ Added source: {source.name}")
            except Exception as e:
                logger.error(f"❌ Failed to create source {source_data.get('name', 'Unknown')}: {e}")
        
        if sources_to_insert:
            # Insert all sources
            result = await db.scraping_sources.insert_many(sources_to_insert)
            logger.info(f"✅ Successfully initialized {len(result.inserted_ids)} default sources")
        else:
            logger.warning("⚠️ No sources were created")
            
    except Exception as e:
        logger.error(f"❌ Failed to initialize default sources: {e}")
        raise


async def main():
    """Main function."""
    try:
        await initialize_default_sources()
        logger.info("✅ Default sources initialization completed successfully!")
    except Exception as e:
        logger.error(f"❌ Initialization failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
from typing import List, Dict

from ctms.core.logger import get_logger
from ctms.database.connection import get_database
from ctms.database.models import ScrapingSource, SourceType

logger = get_logger(__name__)

# Curated default sources (surface web and placeholders for dark web forums)
DEFAULT_SOURCES: List[Dict] = [
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "content_selectors": {
            "title": "h1.entry-title",
            "content": ".entry-content"
        },
        "scraping_interval": 3600,
        "tags": ["news", "breaches", "malware"]
    },
    {
        "name": "The Hacker News",
        "url": "https://thehackernews.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "content_selectors": {
            "title": "h1.post-title",
            "content": "div.articlebody"
        },
        "scraping_interval": 3600,
        "tags": ["news", "vulnerabilities"]
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "content_selectors": {
            "title": "h2.entry-title",
            "content": "div.entry-content"
        },
        "scraping_interval": 3600,
        "tags": ["investigations", "breaches"]
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "content_selectors": {
            "title": "h1.entry-title",
            "content": "div.entry-content"
        },
        "scraping_interval": 3600,
        "tags": ["news", "vulnerabilities", "malware"]
    },
    {
        "name": "VX Underground",
        "url": "https://vx-underground.org",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": True,
        "use_tor": False,
        "content_selectors": {
            "title": "h1",
            "content": "main"
        },
        "scraping_interval": 7200,
        "tags": ["malware", "research"]
    },
    {
        "name": "Reddit r/netsec",
        "url": "https://www.reddit.com/r/netsec",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": False,
        "use_tor": False,
        "content_selectors": {},
        "scraping_interval": 1800,
        "tags": ["community", "threads"]
    },
    {
        "name": "Reddit r/cybersecurity",
        "url": "https://www.reddit.com/r/cybersecurity",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": False,
        "use_tor": False,
        "content_selectors": {},
        "scraping_interval": 1800,
        "tags": ["community", "threads"]
    },
    {
        "name": "Hack Forums",
        "url": "https://hackforums.net",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": False,
        "use_tor": False,
        "content_selectors": {},
        "scraping_interval": 7200,
        "tags": ["forum", "hacking"]
    },
    {
        "name": "XSS Forum",
        "url": "https://xss.is/",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": False,
        "use_tor": False,
        "content_selectors": {},
        "scraping_interval": 10800,
        "tags": ["forum", "hacking"]
    },
    {
        "name": "Exploit.in",
        "url": "https://exploit.in/",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": False,
        "use_tor": False,
        "content_selectors": {},
        "scraping_interval": 10800,
        "tags": ["forum", "hacking"]
    },
    {
        "name": "BreachForums (placeholder)",
        "url": "https://breachforums.st/",
        "source_type": SourceType.SURFACE_WEB,
        "enabled": False,
        "use_tor": False,
        "content_selectors": {},
        "scraping_interval": 10800,
        "tags": ["forum", "data_breaches"]
    },
    # Dark web forum placeholders (disabled by default)
    {
        "name": "Dark Web Forum Placeholder 1",
        "url": "http://exampleforum1.onion",
        "source_type": SourceType.DARK_WEB,
        "enabled": False,
        "use_tor": True,
        "content_selectors": {},
        "scraping_interval": 7200,
        "tags": ["forum", "dark_web"]
    },
    {
        "name": "Dark Web Forum Placeholder 2",
        "url": "http://exampleforum2.onion",
        "source_type": SourceType.DARK_WEB,
        "enabled": False,
        "use_tor": True,
        "content_selectors": {},
        "scraping_interval": 7200,
        "tags": ["forum", "dark_web"]
    },
]


async def seed_default_sources() -> None:
    """Insert default sources if they do not already exist by name."""
    db = await get_database()

    inserted_count = 0
    for raw in DEFAULT_SOURCES:
        try:
            # Check by unique name
            existing = await db.scraping_sources.find_one({"name": raw["name"]})
            if existing:
                continue

            model = ScrapingSource(**raw)
            doc = model.model_dump(by_alias=True, exclude_none=True)
            await db.scraping_sources.insert_one(doc)
            inserted_count += 1
        except Exception as e:
            logger.warning(f"Failed to seed source {raw.get('name')}: {e}")

    if inserted_count:
        logger.info(f"Seeded {inserted_count} default scraping sources")
    else:
        logger.info("No new default scraping sources seeded")
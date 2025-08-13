"""
RSS Scraper Module
Basic RSS feed scraping functionality
"""

import feedparser
import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class RSSScraper:
    """Basic RSS feed scraper"""
    
    def __init__(self):
        self.feeds = [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.schneier.com/feed/",
            "https://www.darkreading.com/rss.xml"
        ]
    
    async def scrape_all_feeds(self) -> List[Dict[str, Any]]:
        """Scrape all RSS feeds"""
        try:
            articles = []
            for feed_url in self.feeds:
                try:
                    feed = feedparser.parse(feed_url)
                    for entry in feed.entries[:10]:  # Get first 10 articles
                        article = {
                            'title': entry.get('title', ''),
                            'content': entry.get('summary', ''),
                            'link': entry.get('link', ''),
                            'published': entry.get('published', ''),
                            'source': feed_url,
                            'source_type': 'rss'
                        }
                        articles.append(article)
                except Exception as e:
                    logger.error(f"Error scraping {feed_url}: {e}")
            
            return articles
        except Exception as e:
            logger.error(f"Error in RSS scraping: {e}")
            return []
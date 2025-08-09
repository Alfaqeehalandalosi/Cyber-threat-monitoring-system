# =============================================================================
# TOR-ENABLED WEB SCRAPER MODULE
# =============================================================================
"""
Advanced web scraper with TOR proxy support for anonymous data collection
from dark web and surface web sources for threat intelligence gathering.
"""

import asyncio
import aiohttp
import hashlib
import time
import random
from typing import Optional, Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime

from ctms.core.config import settings, get_tor_proxy_config
from ctms.core.logger import get_logger
from ctms.database.models import ScrapingSource, ScrapedContent, SourceType
from ctms.database.connection import get_database

logger = get_logger(__name__)


# =============================================================================
# TOR PROXY MANAGER
# =============================================================================
class TorProxyManager:
    """
    Manages TOR proxy connections and circuit rotation.
    Provides anonymous web access for threat intelligence collection.
    """
    
    def __init__(self):
        """Initialize TOR proxy manager."""
        self.config = get_tor_proxy_config()
        self.session: Optional[aiohttp.ClientSession] = None
        self._circuit_renewal_count = 0
        
    async def create_session(self) -> aiohttp.ClientSession:
        """
        Create an aiohttp session with TOR proxy configuration.
        
        Returns:
            aiohttp.ClientSession: Configured session
        """
        if not self.config["enabled"]:
            logger.info("🌐 Creating standard HTTP session (TOR disabled)")
            connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            
            return aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": settings.user_agent}
            )
        
        logger.info("🧅 Creating TOR proxy session")
        
        # Configure TOR proxy
        proxy_url = f"socks5://{self.config['host']}:{self.config['port']}"
        
        connector = aiohttp.TCPConnector(
            limit=10,
            ttl_dns_cache=300,
            use_dns_cache=False  # Important for anonymity
        )
        
        timeout = aiohttp.ClientTimeout(total=60, connect=30)
        
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": settings.user_agent}
        )
        
        # Store proxy URL for requests
        session._proxy_url = proxy_url
        
        return session
    
    async def get_session(self) -> aiohttp.ClientSession:
        """
        Get or create a session with TOR proxy.
        
        Returns:
            aiohttp.ClientSession: Session instance
        """
        if not self.session or self.session.closed:
            self.session = await self.create_session()
        
        return self.session
    
    async def renew_circuit(self) -> bool:
        """
        Renew TOR circuit for fresh IP address.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.config["enabled"]:
                logger.info("🌐 Circuit renewal skipped (TOR disabled)")
                return True
            
            # Close existing session
            if self.session and not self.session.closed:
                await self.session.close()
            
            # Wait for circuit renewal
            await asyncio.sleep(5)
            
            # Create new session
            self.session = await self.create_session()
            self._circuit_renewal_count += 1
            
            logger.info(f"🔄 TOR circuit renewed (count: {self._circuit_renewal_count})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to renew TOR circuit: {e}")
            return False
    
    async def close(self) -> None:
        """Close the session and cleanup."""
        if self.session and not self.session.closed:
            await self.session.close()
            logger.info("🔌 TOR proxy session closed")


# =============================================================================
# CONTENT EXTRACTOR
# =============================================================================
class ContentExtractor:
    """
    Extracts and processes content from scraped web pages.
    Handles various content types and formats.
    """
    
    def __init__(self):
        """Initialize content extractor."""
        self.min_content_length = 100
    
    def extract_text_content(self, html: str, selectors: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Extract text content from HTML using BeautifulSoup.
        
        Args:
            html: Raw HTML content
            selectors: CSS selectors for specific content
            
        Returns:
            Dict[str, Any]: Extracted content
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style", "nav", "footer", "header"]):
                script.decompose()
            
            extracted = {
                "title": "",
                "content": "",
                "links": [],
                "images": [],
                "metadata": {}
            }
            
            # Extract title
            title_tag = soup.find("title")
            if title_tag:
                extracted["title"] = title_tag.get_text().strip()
            
            # Use custom selectors if provided
            if selectors:
                content_parts = []
                for name, selector in selectors.items():
                    elements = soup.select(selector)
                    for element in elements:
                        content_parts.append(element.get_text().strip())
                
                extracted["content"] = "\n\n".join(content_parts)
            else:
                # Default content extraction
                # Try main content areas first
                main_selectors = [
                    "main", "article", ".content", "#content",
                    ".post", ".article", ".entry"
                ]
                
                content_found = False
                for selector in main_selectors:
                    main_content = soup.select_one(selector)
                    if main_content:
                        extracted["content"] = main_content.get_text().strip()
                        content_found = True
                        break
                
                # Fallback to body content
                if not content_found:
                    body = soup.find("body")
                    if body:
                        extracted["content"] = body.get_text().strip()
            
            # Clean up content
            extracted["content"] = self._clean_text(extracted["content"])
            
            # Extract links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                text = link.get_text().strip()
                if href and text:
                    extracted["links"].append({"url": href, "text": text})
            
            # Extract images
            for img in soup.find_all("img", src=True):
                src = img["src"]
                alt = img.get("alt", "")
                extracted["images"].append({"src": src, "alt": alt})
            
            # Extract metadata
            for meta in soup.find_all("meta"):
                name = meta.get("name") or meta.get("property")
                content = meta.get("content")
                if name and content:
                    extracted["metadata"][name] = content
            
            return extracted
            
        except Exception as e:
            logger.error(f"❌ Content extraction failed: {e}")
            return {
                "title": "",
                "content": "",
                "links": [],
                "images": [],
                "metadata": {}
            }
    
    def _clean_text(self, text: str) -> str:
        """
        Clean and normalize extracted text.
        
        Args:
            text: Raw text
            
        Returns:
            str: Cleaned text
        """
        if not text:
            return ""
        
        # Remove extra whitespace
        lines = [line.strip() for line in text.split('\n')]
        lines = [line for line in lines if line]
        
        # Join with single newlines
        cleaned = '\n'.join(lines)
        
        # Remove excessive newlines
        while '\n\n\n' in cleaned:
            cleaned = cleaned.replace('\n\n\n', '\n\n')
        
        return cleaned.strip()
    
    def generate_content_hash(self, content: str) -> str:
        """
        Generate a hash for content deduplication.
        
        Args:
            content: Content to hash
            
        Returns:
            str: SHA-256 hash
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()


# =============================================================================
# MAIN SCRAPER CLASS
# =============================================================================
class ThreatIntelligenceScraper:
    """
    Main scraper class for collecting threat intelligence from various sources.
    Supports TOR proxy, rate limiting, and intelligent content extraction.
    """
    
    def __init__(self):
        """Initialize the threat intelligence scraper."""
        self.tor_manager = TorProxyManager()
        self.content_extractor = ContentExtractor()
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Rate limiting and delays
        self.delay_range = (
            settings.scraping_delay - settings.scraping_randomize_delay,
            settings.scraping_delay + settings.scraping_randomize_delay
        )
        
        # Tracking
        self.scraped_urls: Set[str] = set()
        self.failed_urls: Set[str] = set()
        self.session_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "start_time": None
        }
    
    async def initialize(self) -> None:
        """Initialize the scraper and TOR session."""
        try:
            self.session = await self.tor_manager.get_session()
            self.session_stats["start_time"] = datetime.utcnow()
            logger.info("🕷️ Threat intelligence scraper initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize scraper: {e}")
            raise
    
    async def scrape_url(
        self,
        url: str,
        source_config: Optional[ScrapingSource] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ) -> Optional[ScrapedContent]:
        """
        Scrape content from a single URL.
        
        Args:
            url: Target URL to scrape
            source_config: Source configuration
            custom_headers: Additional HTTP headers
            
        Returns:
            Optional[ScrapedContent]: Scraped content or None if failed
        """
        if url in self.scraped_urls:
            logger.info(f"🔄 URL already scraped: {url}")
            return None
        
        try:
            # Apply rate limiting
            await self._apply_rate_limit()
            
            # Prepare headers
            headers = {"User-Agent": settings.user_agent}
            if custom_headers:
                headers.update(custom_headers)
            if source_config and source_config.custom_headers:
                headers.update(source_config.custom_headers)
            
            # Track request
            self.session_stats["total_requests"] += 1
            
            logger.scraping_activity(url, "STARTING", {"headers_count": len(headers)})
            
            # Make request
            proxy = getattr(self.session, '_proxy_url', None) if self.tor_manager.config["enabled"] else None
            
            async with self.session.get(
                url,
                headers=headers,
                proxy=proxy,
                allow_redirects=True,
                max_redirects=5
            ) as response:
                
                # Check response status
                if response.status != 200:
                    logger.warning(f"⚠️ Non-200 response: {response.status} for {url}")
                    self.session_stats["failed_requests"] += 1
                    self.failed_urls.add(url)
                    return None
                
                # Read content
                content = await response.text()
                content_length = len(content)
                
                # Validate content length
                min_length = source_config.min_content_length if source_config else self.content_extractor.min_content_length
                if content_length < min_length:
                    logger.warning(f"⚠️ Content too short ({content_length} bytes): {url}")
                    self.session_stats["failed_requests"] += 1
                    return None
                
                # Extract content
                extracted = self.content_extractor.extract_text_content(
                    content,
                    source_config.content_selectors if source_config else None
                )
                
                # Generate content hash
                content_hash = self.content_extractor.generate_content_hash(extracted["content"])
                
                # Create scraped content document
                scraped_content = ScrapedContent(
                    source_id=str(source_config.id) if source_config else "manual",
                    source_url=source_config.url if source_config else url,
                    scraped_url=url,
                    title=extracted["title"],
                    content=extracted["content"],
                    content_hash=content_hash,
                    response_status=response.status,
                    content_length=content_length,
                    scraping_timestamp=datetime.utcnow()
                )
                
                # Track success
                self.scraped_urls.add(url)
                self.session_stats["successful_requests"] += 1
                
                logger.scraping_activity(
                    url, 
                    "SUCCESS", 
                    {
                        "content_length": content_length,
                        "title_length": len(extracted["title"]),
                        "links_found": len(extracted["links"])
                    }
                )
                
                return scraped_content
                
        except asyncio.TimeoutError:
            logger.error(f"⏰ Timeout scraping {url}")
            self.session_stats["failed_requests"] += 1
            self.failed_urls.add(url)
            
        except Exception as e:
            logger.error(f"❌ Error scraping {url}: {e}")
            self.session_stats["failed_requests"] += 1
            self.failed_urls.add(url)
        
        return None
    
    async def scrape_source(self, source: ScrapingSource) -> List[ScrapedContent]:
        """
        Scrape content from a configured source.
        
        Args:
            source: Source configuration
            
        Returns:
            List[ScrapedContent]: List of scraped content
        """
        logger.info(f"🎯 Starting scrape for source: {source.name}")
        
        if not source.enabled:
            logger.info(f"⏸️ Source disabled: {source.name}")
            return []
        
        scraped_content = []
        
        try:
            # Discover URLs to scrape
            urls_to_scrape = await self._discover_urls(source)
            
            logger.info(f"🔍 Found {len(urls_to_scrape)} URLs to scrape for {source.name}")
            
            # Apply concurrent request limit
            semaphore = asyncio.Semaphore(settings.concurrent_requests)
            
            async def scrape_with_semaphore(url: str) -> Optional[ScrapedContent]:
                async with semaphore:
                    return await self.scrape_url(url, source)
            
            # Scrape all URLs
            tasks = [scrape_with_semaphore(url) for url in urls_to_scrape]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect successful results
            for result in results:
                if isinstance(result, ScrapedContent):
                    scraped_content.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"❌ Scraping task failed: {result}")
            
            # Update source statistics
            await self._update_source_stats(source, len(scraped_content), len(urls_to_scrape))
            
            logger.info(f"✅ Completed scraping {source.name}: {len(scraped_content)} items collected")
            
        except Exception as e:
            logger.error(f"❌ Failed to scrape source {source.name}: {e}")
        
        return scraped_content
    
    async def _discover_urls(self, source: ScrapingSource) -> List[str]:
        """
        Discover URLs to scrape from a source.
        
        Args:
            source: Source configuration
            
        Returns:
            List[str]: URLs to scrape
        """
        urls = []
        
        try:
            # Start with the base URL
            urls.append(source.url)
            
            # If URL patterns are specified, try to discover more URLs
            if source.url_patterns:
                discovered_urls = await self._crawl_for_urls(source)
                urls.extend(discovered_urls)
            
            # Remove duplicates and invalid URLs
            urls = list(set(urls))
            urls = [url for url in urls if self._is_valid_url(url)]
            
        except Exception as e:
            logger.error(f"❌ URL discovery failed for {source.name}: {e}")
        
        return urls
    
    async def _crawl_for_urls(self, source: ScrapingSource) -> List[str]:
        """
        Crawl source page to discover additional URLs.
        
        Args:
            source: Source configuration
            
        Returns:
            List[str]: Discovered URLs
        """
        discovered_urls = []
        
        try:
            # Scrape the base page
            scraped = await self.scrape_url(source.url)
            if not scraped:
                return discovered_urls
            
            # Parse HTML to find links
            soup = BeautifulSoup(scraped.content, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Convert relative URLs to absolute
                full_url = urljoin(source.url, href)
                
                # Check against URL patterns
                for pattern in source.url_patterns:
                    import re
                    if re.search(pattern, full_url):
                        discovered_urls.append(full_url)
                        break
            
        except Exception as e:
            logger.error(f"❌ URL crawling failed: {e}")
        
        return discovered_urls
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format and accessibility.
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if valid
        """
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        delay = random.uniform(*self.delay_range)
        await asyncio.sleep(delay)
    
    async def _update_source_stats(self, source: ScrapingSource, success_count: int, total_count: int) -> None:
        """
        Update source scraping statistics.
        
        Args:
            source: Source configuration
            success_count: Number of successful scrapes
            total_count: Total URLs attempted
        """
        try:
            # Calculate success rate
            success_rate = (success_count / total_count) if total_count > 0 else 0.0
            
            # Update source in database
            db = await get_database()
            await db.scraping_sources.update_one(
                {"_id": source.id},
                {
                    "$set": {
                        "last_scraped": datetime.utcnow(),
                        "success_rate": success_rate,
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            logger.info(f"📊 Updated stats for {source.name}: {success_rate:.2%} success rate")
            
        except Exception as e:
            logger.error(f"❌ Failed to update source stats: {e}")
    
    async def renew_tor_circuit(self) -> bool:
        """
        Renew TOR circuit and session.
        
        Returns:
            bool: True if successful
        """
        success = await self.tor_manager.renew_circuit()
        if success:
            self.session = await self.tor_manager.get_session()
        return success
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get current session statistics.
        
        Returns:
            Dict[str, Any]: Session statistics
        """
        stats = self.session_stats.copy()
        
        if stats["start_time"]:
            duration = (datetime.utcnow() - stats["start_time"]).total_seconds()
            stats["duration_seconds"] = duration
            stats["requests_per_minute"] = (stats["total_requests"] / duration) * 60 if duration > 0 else 0
        
        stats["success_rate"] = (
            stats["successful_requests"] / stats["total_requests"] 
            if stats["total_requests"] > 0 else 0
        )
        
        stats["unique_urls_scraped"] = len(self.scraped_urls)
        stats["failed_urls"] = len(self.failed_urls)
        
        return stats
    
    async def close(self) -> None:
        """Close scraper and cleanup resources."""
        await self.tor_manager.close()
        logger.info("🛑 Threat intelligence scraper closed")


# =============================================================================
# SCRAPING ORCHESTRATOR
# =============================================================================
class ScrapingOrchestrator:
    """
    Orchestrates scraping operations across multiple sources.
    Manages scheduling, prioritization, and resource allocation.
    """
    
    def __init__(self):
        """Initialize scraping orchestrator."""
        self.scraper = ThreatIntelligenceScraper()
        self.running = False
    
    async def initialize(self) -> None:
        """Initialize the orchestrator."""
        await self.scraper.initialize()
        logger.info("🎭 Scraping orchestrator initialized")
    
    async def run_scraping_cycle(self) -> Dict[str, Any]:
        """
        Run a complete scraping cycle for all enabled sources.
        
        Returns:
            Dict[str, Any]: Cycle results and statistics
        """
        logger.info("🔄 Starting scraping cycle")
        cycle_start = datetime.utcnow()
        
        try:
            # Get all enabled sources
            db = await get_database()
            sources_cursor = db.scraping_sources.find({"enabled": True})
            sources = []
            async for doc in sources_cursor:
                if doc.get("_id") is not None:
                    doc["_id"] = str(doc["_id"])
                sources.append(ScrapingSource(**doc))
            
            logger.info(f"📋 Found {len(sources)} enabled sources")
            
            all_scraped_content = []
            source_results = {}
            
            # Process each source
            for source in sources:
                try:
                    scraped_content = await self.scraper.scrape_source(source)
                    all_scraped_content.extend(scraped_content)
                    source_results[source.name] = {
                        "items_scraped": len(scraped_content),
                        "success": True
                    }
                    
                    # Save scraped content to database
                    if scraped_content:
                        content_docs = [content.dict() for content in scraped_content]
                        await db.scraped_content.insert_many(content_docs)
                        
                        logger.info(f"💾 Saved {len(scraped_content)} items for {source.name}")
                    
                    # Renew TOR circuit periodically
                    if len(all_scraped_content) % 50 == 0:
                        await self.scraper.renew_tor_circuit()
                
                except Exception as e:
                    logger.error(f"❌ Source {source.name} failed: {e}")
                    source_results[source.name] = {
                        "items_scraped": 0,
                        "success": False,
                        "error": str(e)
                    }
            
            # Calculate cycle statistics
            cycle_duration = (datetime.utcnow() - cycle_start).total_seconds()
            session_stats = self.scraper.get_session_stats()
            
            results = {
                "cycle_duration_seconds": cycle_duration,
                "total_items_scraped": len(all_scraped_content),
                "sources_processed": len(sources),
                "successful_sources": sum(1 for r in source_results.values() if r["success"]),
                "source_results": source_results,
                "session_stats": session_stats,
                "timestamp": cycle_start
            }
            
            logger.info(f"✅ Scraping cycle completed: {len(all_scraped_content)} items in {cycle_duration:.1f}s")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Scraping cycle failed: {e}")
            raise
    
    async def close(self) -> None:
        """Close orchestrator and cleanup."""
        await self.scraper.close()
        logger.info("🛑 Scraping orchestrator closed")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================
async def create_scraper() -> ThreatIntelligenceScraper:
    """
    Create and initialize a threat intelligence scraper.
    
    Returns:
        ThreatIntelligenceScraper: Initialized scraper
    """
    scraper = ThreatIntelligenceScraper()
    await scraper.initialize()
    return scraper


async def scrape_single_url(url: str) -> Optional[ScrapedContent]:
    """
    Convenience function to scrape a single URL.
    
    Args:
        url: URL to scrape
        
    Returns:
        Optional[ScrapedContent]: Scraped content
    """
    scraper = await create_scraper()
    try:
        return await scraper.scrape_url(url)
    finally:
        await scraper.close()
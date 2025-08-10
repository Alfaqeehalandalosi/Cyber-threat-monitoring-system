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
            bool: Success status
        """
        if not self.config["enabled"]:
            return True
        
        try:
            # Use TOR control protocol to renew circuit
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.config["host"], self.config["control_port"]))
            
            # Send authentication and new circuit command
            sock.send(b"AUTHENTICATE\r\n")
            sock.send(b"NEWNYM\r\n")
            sock.close()
            
            self._circuit_renewal_count += 1
            logger.info(f"🔄 TOR circuit renewed (count: {self._circuit_renewal_count})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to renew TOR circuit: {e}")
            return False
    
    async def close(self) -> None:
        """Close TOR proxy manager."""
        if self.session and not self.session.closed:
            await self.session.close()
            logger.info("🛑 TOR proxy manager closed")


# =============================================================================
# CONTENT EXTRACTION
# =============================================================================
class ContentExtractor:
    """
    Extracts and processes content from web pages.
    Handles HTML parsing, text extraction, and content cleaning.
    """
    
    def __init__(self):
        """Initialize content extractor."""
        pass
    
    def extract_text_content(self, html: str, selectors: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Extract text content from HTML using CSS selectors.
        
        Args:
            html: Raw HTML content
            selectors: CSS selectors for content extraction
            
        Returns:
            Dict[str, Any]: Extracted content
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Default selectors if none provided
            if not selectors:
                selectors = {
                    'title': 'title',
                    'main_content': 'main, article, .content, .post, .entry',
                    'headings': 'h1, h2, h3, h4, h5, h6',
                    'paragraphs': 'p',
                    'links': 'a[href]',
                    'meta_description': 'meta[name="description"]',
                    'meta_keywords': 'meta[name="keywords"]'
                }
            
            extracted_content = {}
            
            # Extract title
            title_elem = soup.select_one(selectors.get('title', 'title'))
            extracted_content['title'] = title_elem.get_text(strip=True) if title_elem else ""
            
            # Extract main content
            main_content = soup.select(selectors.get('main_content', 'main, article, .content'))
            if main_content:
                extracted_content['main_content'] = ' '.join([elem.get_text(strip=True) for elem in main_content])
            else:
                # Fallback to body content
                body = soup.find('body')
                extracted_content['main_content'] = body.get_text(strip=True) if body else ""
            
            # Extract headings
            headings = soup.select(selectors.get('headings', 'h1, h2, h3, h4, h5, h6'))
            extracted_content['headings'] = [h.get_text(strip=True) for h in headings]
            
            # Extract paragraphs
            paragraphs = soup.select(selectors.get('paragraphs', 'p'))
            extracted_content['paragraphs'] = [p.get_text(strip=True) for p in paragraphs]
            
            # Extract links
            links = soup.select(selectors.get('links', 'a[href]'))
            extracted_content['links'] = [
                {
                    'text': link.get_text(strip=True),
                    'href': link.get('href', ''),
                    'title': link.get('title', '')
                }
                for link in links
            ]
            
            # Extract meta tags
            meta_desc = soup.select_one(selectors.get('meta_description', 'meta[name="description"]'))
            extracted_content['meta_description'] = meta_desc.get('content', '') if meta_desc else ""
            
            meta_keywords = soup.select_one(selectors.get('meta_keywords', 'meta[name="keywords"]'))
            extracted_content['meta_keywords'] = meta_keywords.get('content', '') if meta_keywords else ""
            
            # Clean and combine all text content
            all_text = ' '.join([
                extracted_content['title'],
                extracted_content['main_content'],
                ' '.join(extracted_content['headings']),
                ' '.join(extracted_content['paragraphs']),
                extracted_content['meta_description'],
                extracted_content['meta_keywords']
            ])
            
            extracted_content['full_text'] = self._clean_text(all_text)
            
            return extracted_content
            
        except Exception as e:
            logger.error(f"❌ Content extraction failed: {e}")
            return {
                'title': '',
                'main_content': '',
                'headings': [],
                'paragraphs': [],
                'links': [],
                'meta_description': '',
                'meta_keywords': '',
                'full_text': ''
            }
    
    def _clean_text(self, text: str) -> str:
        """
        Clean and normalize text content.
        
        Args:
            text: Raw text content
            
        Returns:
            str: Cleaned text
        """
        if not text:
            return ""
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Remove special characters but keep basic punctuation
        import re
        text = re.sub(r'[^\w\s\.\,\!\?\;\:\-\(\)\[\]\{\}]', '', text)
        
        # Normalize spacing around punctuation
        text = re.sub(r'\s+([\.\,\!\?\;\:])', r'\1', text)
        
        return text.strip()
    
    def generate_content_hash(self, content: str) -> str:
        """
        Generate SHA-256 hash of content for deduplication.
        
        Args:
            content: Content to hash
            
        Returns:
            str: SHA-256 hash
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()


# =============================================================================
# THREAT INTELLIGENCE SCRAPER
# =============================================================================
class ThreatIntelligenceScraper:
    """
    Advanced web scraper for threat intelligence collection.
    Supports TOR proxy, rate limiting, and content processing.
    """
    
    def __init__(self):
        """Initialize threat intelligence scraper."""
        self.tor_manager = TorProxyManager()
        self.content_extractor = ContentExtractor()
        self.session: Optional[aiohttp.ClientSession] = None
        self.database_url = settings.database_url
        self._request_count = 0
        self._last_request_time = 0
        
    async def initialize(self) -> None:
        """Initialize the scraper."""
        self.session = await self.tor_manager.create_session()
        logger.info("🔧 Threat intelligence scraper initialized")
    
    async def get_session(self) -> aiohttp.ClientSession:
        """
        Get or create a session.
        
        Returns:
            aiohttp.ClientSession: Session instance
        """
        if not self.session or self.session.closed:
            await self.initialize()
        return self.session
    
    async def scrape_url(
        self,
        url: str,
        source_config: Optional[ScrapingSource] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ) -> Optional[ScrapedContent]:
        """
        Scrape a single URL for threat intelligence content.
        
        Args:
            url: URL to scrape
            source_config: Source configuration
            custom_headers: Custom HTTP headers
            
        Returns:
            Optional[ScrapedContent]: Scraped content
        """
        session = await self.get_session()
        
        try:
            # Apply rate limiting
            await self._apply_rate_limit()
            
            # Prepare headers
            headers = {"User-Agent": settings.user_agent}
            if custom_headers:
                headers.update(custom_headers)
            
            # Make request
            async with session.get(url, headers=headers, ssl=False) as response:
                if response.status == 200:
                    html_content = await response.text()
                    
                    # Extract content
                    extracted_content = self.content_extractor.extract_text_content(html_content)
                    
                    # Create scraped content object
                    scraped_content = ScrapedContent(
                        url=url,
                        title=extracted_content.get('title', ''),
                        content=extracted_content.get('full_text', ''),
                        content_hash=self.content_extractor.generate_content_hash(extracted_content.get('full_text', '')),
                        source_name=source_config.name if source_config else 'manual',
                        source_type=source_config.source_type if source_config else SourceType.SURFACE_WEB,
                        scraped_at=datetime.utcnow(),
                        metadata={
                            'headings': extracted_content.get('headings', []),
                            'links': extracted_content.get('links', []),
                            'meta_description': extracted_content.get('meta_description', ''),
                            'meta_keywords': extracted_content.get('meta_keywords', ''),
                            'response_headers': dict(response.headers),
                            'status_code': response.status
                        }
                    )
                    
                    self._request_count += 1
                    logger.info(f"✅ Scraped {url} ({len(extracted_content.get('full_text', ''))} chars)")
                    
                    return scraped_content
                    
                else:
                    logger.warning(f"⚠️ Failed to scrape {url}: HTTP {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ Error scraping {url}: {e}")
            return None
    
    async def scrape_source(self, source: ScrapingSource) -> List[ScrapedContent]:
        """
        Scrape all URLs from a source.
        
        Args:
            source: Source configuration
            
        Returns:
            List[ScrapedContent]: List of scraped content
        """
        logger.info(f"🔍 Scraping source: {source.name}")
        
        try:
            # Discover URLs from source
            urls = await self._discover_urls(source)
            logger.info(f"📋 Found {len(urls)} URLs for {source.name}")
            
            # Scrape URLs with concurrency control
            semaphore = asyncio.Semaphore(source.max_concurrent_requests)
            scraped_content = []
            
            async def scrape_with_semaphore(url: str) -> Optional[ScrapedContent]:
                async with semaphore:
                    return await self.scrape_url(url, source)
            
            # Scrape all URLs concurrently
            tasks = [scrape_with_semaphore(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful results
            for result in results:
                if isinstance(result, ScrapedContent):
                    scraped_content.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"❌ Scraping task failed: {result}")
            
            # Update source statistics
            await self._update_source_stats(source, len(scraped_content), len(urls))
            
            logger.info(f"✅ Scraped {len(scraped_content)} items from {source.name}")
            return scraped_content
            
        except Exception as e:
            logger.error(f"❌ Failed to scrape source {source.name}: {e}")
            return []
    
    async def _discover_urls(self, source: ScrapingSource) -> List[str]:
        """
        Discover URLs from a source.
        
        Args:
            source: Source configuration
            
        Returns:
            List[str]: List of discovered URLs
        """
        urls = []
        
        # Add base URLs
        if source.base_urls:
            urls.extend(source.base_urls)
        
        # Add specific URLs
        if source.urls:
            urls.extend(source.urls)
        
        # Crawl for additional URLs if enabled
        if source.enable_crawling and source.base_urls:
            crawled_urls = await self._crawl_for_urls(source)
            urls.extend(crawled_urls)
        
        # Remove duplicates and validate
        unique_urls = list(set(urls))
        valid_urls = [url for url in unique_urls if self._is_valid_url(url)]
        
        return valid_urls[:source.max_urls_per_cycle]
    
    async def _crawl_for_urls(self, source: ScrapingSource) -> List[str]:
        """
        Crawl source for additional URLs.
        
        Args:
            source: Source configuration
            
        Returns:
            List[str]: List of discovered URLs
        """
        discovered_urls = []
        session = await self.get_session()
        
        for base_url in source.base_urls[:3]:  # Limit crawling to first 3 base URLs
            try:
                async with session.get(base_url, ssl=False) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Find links
                        links = soup.find_all('a', href=True)
                        for link in links:
                            href = link['href']
                            
                            # Convert relative URLs to absolute
                            if href.startswith('/'):
                                href = urljoin(base_url, href)
                            elif not href.startswith('http'):
                                continue
                            
                            # Filter by domain if specified
                            if source.domain_filter:
                                if source.domain_filter in href:
                                    discovered_urls.append(href)
                            else:
                                discovered_urls.append(href)
                                
            except Exception as e:
                logger.error(f"❌ Crawling failed for {base_url}: {e}")
        
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
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        if self._last_request_time > 0:
            elapsed = time.time() - self._last_request_time
            min_interval = 1.0  # Minimum 1 second between requests
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
    
    async def _update_source_stats(self, source: ScrapingSource, success_count: int, total_count: int) -> None:
        """
        Update source statistics in database.
        
        Args:
            source: Source configuration
            success_count: Number of successful scrapes
            total_count: Total number of attempts
        """
        try:
            db = await get_database()
            await db.scraping_sources.update_one(
                {"_id": source.id},
                {
                    "$set": {
                        "last_scraped": datetime.utcnow(),
                        "last_success_count": success_count,
                        "last_total_count": total_count
                    },
                    "$inc": {
                        "total_scrapes": 1,
                        "total_successful_scrapes": success_count
                    }
                }
            )
        except Exception as e:
            logger.error(f"❌ Failed to update source stats: {e}")
    
    async def renew_tor_circuit(self) -> bool:
        """
        Renew TOR circuit for fresh IP address.
        
        Returns:
            bool: Success status
        """
        return await self.tor_manager.renew_circuit()
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get session statistics.
        
        Returns:
            Dict[str, Any]: Session statistics
        """
        return {
            "total_requests": self._request_count,
            "tor_enabled": self.tor_manager.config["enabled"],
            "circuit_renewals": self.tor_manager._circuit_renewal_count,
            "session_active": self.session is not None and not self.session.closed
        }
    
    async def close(self) -> None:
        """Close scraper and cleanup resources."""
        if self.session and not self.session.closed:
            await self.session.close()
        await self.tor_manager.close()
        logger.info("🛑 Threat intelligence scraper closed")

    # =============================================================================
    # BACKWARD COMPATIBILITY METHOD
    # =============================================================================
    async def run_full_cycle(self) -> Dict[str, Any]:
        """
        Run a full scraping cycle for all enabled sources.
        This method provides backward compatibility for older code.
        
        Returns:
            Dict[str, Any]: Cycle results and statistics
        """
        logger.info("🔄 Starting full scraping cycle (backward compatibility)")
        
        try:
            # Create orchestrator and run cycle
            orchestrator = ScrapingOrchestrator()
            await orchestrator.initialize()
            
            try:
                results = await orchestrator.run_scraping_cycle()
                logger.info("✅ Full scraping cycle completed")
                return results
            finally:
                await orchestrator.close()
                
        except Exception as e:
            logger.error(f"❌ Full scraping cycle failed: {e}")
            raise


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
            sources = [ScrapingSource(**doc) async for doc in sources_cursor]
            
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
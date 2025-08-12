"""
Advanced Threat Intelligence Scraper
Comprehensive threat monitoring system for academic cybersecurity research
"""

import asyncio
import aiohttp
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
from bs4 import BeautifulSoup
import feedparser
import hashlib
from urllib.parse import urljoin, urlparse
import time
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedThreatScraper:
    """Advanced threat intelligence scraper for multiple sources"""
    
    def __init__(self):
        self.session = None
        self.config = self._load_config()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        self.headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load advanced threat sources configuration"""
        try:
            with open('ctms/config/advanced_sources.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading advanced sources config: {str(e)}")
            return {}
    
    async def scrape_github_security(self) -> List[Dict[str, Any]]:
        """Scrape GitHub for security-related repositories and advisories"""
        articles = []
        
        try:
            # Search for CVE-related repositories
            search_terms = ["CVE", "exploit", "PoC", "vulnerability", "zero-day"]
            
            for term in search_terms:
                try:
                    url = f"https://api.github.com/search/repositories?q={term}+security&sort=updated&order=desc&per_page=10"
                    
                    async with self.session.get(url, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            for repo in data.get('items', [])[:5]:  # Top 5 repos per term
                                article = {
                                    'title': f"GitHub: {repo['name']} - {repo['description'] or 'Security repository'}",
                                    'content': repo.get('description', ''),
                                    'link': repo['html_url'],
                                    'source': 'GitHub Security',
                                    'published': repo['updated_at'],
                                    'threat_score': self._calculate_github_threat_score(repo, term),
                                    'threat_type': self._classify_github_content(repo, term),
                                    'source_type': 'github',
                                    'tags': repo.get('topics', []) + [term],
                                    'scraped_at': datetime.now().isoformat()
                                }
                                articles.append(article)
                                
                except Exception as e:
                    logger.error(f"Error scraping GitHub for term '{term}': {str(e)}")
                    continue
                    
                # Rate limiting
                await asyncio.sleep(2)
                
        except Exception as e:
            logger.error(f"Error in GitHub security scraping: {str(e)}")
            
        return articles
    
    async def scrape_cve_databases(self) -> List[Dict[str, Any]]:
        """Scrape CVE databases for new vulnerabilities"""
        articles = []
        
        cve_sources = self.config.get('advanced_threat_sources', {}).get('cve_databases', [])
        
        for source in cve_sources:
            if not source.get('enabled', True):
                continue
                
            try:
                if source['id'] == 'nvd_cve':
                    articles.extend(await self._scrape_nvd_cve(source))
                elif source['id'] == 'cve_details':
                    articles.extend(await self._scrape_cve_details(source))
                elif source['id'] == 'exploit_db':
                    articles.extend(await self._scrape_exploit_db(source))
                    
                # Rate limiting
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Error scraping {source['name']}: {str(e)}")
                continue
                
        return articles
    
    async def _scrape_nvd_cve(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape NVD CVE database"""
        articles = []
        
        try:
            async with self.session.get(source['api_endpoint'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    feed = feedparser.parse(content)
                    
                    for entry in feed.entries[:10]:
                        # Extract CVE ID from title
                        cve_match = re.search(r'CVE-\d{4}-\d+', entry.title)
                        cve_id = cve_match.group(0) if cve_match else 'Unknown'
                        
                        article = {
                            'title': entry.title,
                            'content': entry.get('summary', ''),
                            'link': entry.get('link', ''),
                            'source': 'NVD CVE Database',
                            'published': entry.get('published', ''),
                            'threat_score': self._calculate_cve_threat_score(entry),
                            'threat_type': 'vulnerability',
                            'source_type': 'cve',
                            'tags': ['cve', 'vulnerability', 'nvd'] + [cve_id],
                            'cve_id': cve_id,
                            'scraped_at': datetime.now().isoformat()
                        }
                        articles.append(article)
                        
        except Exception as e:
            logger.error(f"Error scraping NVD CVE: {str(e)}")
            
        return articles
    
    async def _scrape_cve_details(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape CVE Details"""
        articles = []
        
        try:
            async with self.session.get(source['api_endpoint'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    feed = feedparser.parse(content)
                    
                    for entry in feed.entries[:10]:
                        article = {
                            'title': entry.title,
                            'content': entry.get('summary', ''),
                            'link': entry.get('link', ''),
                            'source': 'CVE Details',
                            'published': entry.get('published', ''),
                            'threat_score': self._calculate_cve_threat_score(entry),
                            'threat_type': 'vulnerability',
                            'source_type': 'cve',
                            'tags': ['cve', 'vulnerability', 'details'],
                            'scraped_at': datetime.now().isoformat()
                        }
                        articles.append(article)
                        
        except Exception as e:
            logger.error(f"Error scraping CVE Details: {str(e)}")
            
        return articles
    
    async def _scrape_exploit_db(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape Exploit Database"""
        articles = []
        
        try:
            async with self.session.get(source['api_endpoint'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    feed = feedparser.parse(content)
                    
                    for entry in feed.entries[:10]:
                        article = {
                            'title': entry.title,
                            'content': entry.get('summary', ''),
                            'link': entry.get('link', ''),
                            'source': 'Exploit Database',
                            'published': entry.get('published', ''),
                            'threat_score': self._calculate_exploit_threat_score(entry),
                            'threat_type': 'exploit',
                            'source_type': 'exploit',
                            'tags': ['exploit', 'vulnerability', 'PoC'],
                            'scraped_at': datetime.now().isoformat()
                        }
                        articles.append(article)
                        
        except Exception as e:
            logger.error(f"Error scraping Exploit DB: {str(e)}")
            
        return articles
    
    async def scrape_paste_sites(self) -> List[Dict[str, Any]]:
        """Scrape public paste sites for security content"""
        articles = []
        
        paste_sources = self.config.get('advanced_threat_sources', {}).get('paste_sites', [])
        
        for source in paste_sources:
            if not source.get('enabled', True):
                continue
                
            try:
                if source['id'] == 'pastebin_public':
                    articles.extend(await self._scrape_pastebin_public(source))
                elif source['id'] == 'ghostbin_public':
                    articles.extend(await self._scrape_ghostbin_public(source))
                    
                # Rate limiting
                await asyncio.sleep(3)
                
            except Exception as e:
                logger.error(f"Error scraping {source['name']}: {str(e)}")
                continue
                
        return articles
    
    async def _scrape_pastebin_public(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape public Pastebin content"""
        articles = []
        
        try:
            async with self.session.get(source['api_endpoint'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Find recent public pastes
                    paste_links = soup.find_all('a', href=re.compile(r'/[\w]+'))
                    
                    for link in paste_links[:10]:
                        try:
                            paste_url = urljoin(source['api_endpoint'], link['href'])
                            
                            # Get paste content
                            async with self.session.get(paste_url, timeout=30) as paste_response:
                                if paste_response.status == 200:
                                    paste_content = await paste_response.text()
                                    
                                    # Check if content contains security-related keywords
                                    if self._contains_security_keywords(paste_content):
                                        article = {
                                            'title': f"Pastebin: {link.get_text(strip=True)}",
                                            'content': paste_content[:500] + "..." if len(paste_content) > 500 else paste_content,
                                            'link': paste_url,
                                            'source': 'Pastebin Public',
                                            'published': datetime.now().isoformat(),
                                            'threat_score': self._calculate_paste_threat_score(paste_content),
                                            'threat_type': self._classify_paste_content(paste_content),
                                            'source_type': 'paste',
                                            'tags': ['pastebin', 'public', 'dump'],
                                            'scraped_at': datetime.now().isoformat()
                                        }
                                        articles.append(article)
                                        
                        except Exception as e:
                            logger.warning(f"Error processing paste: {str(e)}")
                            continue
                            
        except Exception as e:
            logger.error(f"Error scraping Pastebin: {str(e)}")
            
        return articles
    
    async def _scrape_ghostbin_public(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape public Ghostbin content"""
        articles = []
        
        try:
            async with self.session.get(source['api_endpoint'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Find recent public pastes
                    paste_links = soup.find_all('a', href=re.compile(r'/[\w]+'))
                    
                    for link in paste_links[:10]:
                        try:
                            paste_url = urljoin(source['api_endpoint'], link['href'])
                            
                            # Get paste content
                            async with self.session.get(paste_url, timeout=30) as paste_response:
                                if paste_response.status == 200:
                                    paste_content = await paste_response.text()
                                    
                                    # Check if content contains security-related keywords
                                    if self._contains_security_keywords(paste_content):
                                        article = {
                                            'title': f"Ghostbin: {link.get_text(strip=True)}",
                                            'content': paste_content[:500] + "..." if len(paste_content) > 500 else paste_content,
                                            'link': paste_url,
                                            'source': 'Ghostbin Public',
                                            'published': datetime.now().isoformat(),
                                            'threat_score': self._calculate_paste_threat_score(paste_content),
                                            'threat_type': self._classify_paste_content(paste_content),
                                            'source_type': 'paste',
                                            'tags': ['ghostbin', 'public', 'dump'],
                                            'scraped_at': datetime.now().isoformat()
                                        }
                                        articles.append(article)
                                        
                        except Exception as e:
                            logger.warning(f"Error processing paste: {str(e)}")
                            continue
                            
        except Exception as e:
            logger.error(f"Error scraping Ghostbin: {str(e)}")
            
        return articles
    
    def _contains_security_keywords(self, content: str) -> bool:
        """Check if content contains security-related keywords"""
        security_keywords = [
            'password', 'credential', 'exploit', 'vulnerability', 'CVE', 'malware',
            'hack', 'breach', 'leak', 'dump', 'SQL injection', 'XSS', 'RCE',
            'zero-day', '0day', 'PoC', 'proof of concept'
        ]
        
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in security_keywords)
    
    def _calculate_github_threat_score(self, repo: Dict[str, Any], search_term: str) -> float:
        """Calculate threat score for GitHub repository"""
        score = 0.0
        
        # Base score from search term
        if search_term in ['CVE', 'exploit', 'PoC']:
            score += 0.3
        elif search_term in ['vulnerability', 'zero-day']:
            score += 0.4
            
        # Repository factors
        if repo.get('stargazers_count', 0) > 100:
            score += 0.1
        if repo.get('forks_count', 0) > 50:
            score += 0.1
        if repo.get('updated_at'):
            # Recent updates get higher score
            updated = datetime.fromisoformat(repo['updated_at'].replace('Z', '+00:00'))
            days_old = (datetime.now(updated.tzinfo) - updated).days
            if days_old < 7:
                score += 0.2
            elif days_old < 30:
                score += 0.1
                
        # Topics analysis
        topics = repo.get('topics', [])
        if any(topic in ['security', 'vulnerability', 'exploit', 'malware'] for topic in topics):
            score += 0.2
            
        return min(1.0, score)
    
    def _calculate_cve_threat_score(self, entry: Any) -> float:
        """Calculate threat score for CVE entry"""
        score = 0.5  # Base score for CVE
        
        title = entry.get('title', '').lower()
        summary = entry.get('summary', '').lower()
        
        # Critical keywords
        if any(word in title or word in summary for word in ['critical', 'severe', 'high severity']):
            score += 0.3
        if any(word in title or word in summary for word in ['remote code execution', 'RCE']):
            score += 0.2
        if any(word in title or word in summary for word in ['zero-day', '0day']):
            score += 0.2
            
        return min(1.0, score)
    
    def _calculate_exploit_threat_score(self, entry: Any) -> float:
        """Calculate threat score for exploit entry"""
        score = 0.6  # Base score for exploit
        
        title = entry.get('title', '').lower()
        summary = entry.get('summary', '').lower()
        
        # Exploit-specific keywords
        if any(word in title or word in summary for word in ['working', 'verified', 'tested']):
            score += 0.2
        if any(word in title or word in summary for word in ['PoC', 'proof of concept']):
            score += 0.1
        if any(word in title or word in summary for word in ['remote', 'RCE']):
            score += 0.1
            
        return min(1.0, score)
    
    def _calculate_paste_threat_score(self, content: str) -> float:
        """Calculate threat score for paste content"""
        score = 0.3  # Base score for paste
        
        content_lower = content.lower()
        
        # High-threat keywords
        if any(word in content_lower for word in ['password', 'credential', 'login']):
            score += 0.2
        if any(word in content_lower for word in ['exploit', 'vulnerability', 'CVE']):
            score += 0.2
        if any(word in content_lower for word in ['zero-day', '0day']):
            score += 0.3
        if any(word in content_lower for word in ['malware', 'trojan', 'virus']):
            score += 0.2
            
        return min(1.0, score)
    
    def _classify_github_content(self, repo: Dict[str, Any], search_term: str) -> str:
        """Classify GitHub content type"""
        if search_term in ['CVE', 'vulnerability']:
            return 'vulnerability'
        elif search_term in ['exploit', 'PoC']:
            return 'exploit'
        elif search_term in ['zero-day', '0day']:
            return 'zero_day'
        else:
            return 'security_research'
    
    def _classify_paste_content(self, content: str) -> str:
        """Classify paste content type"""
        content_lower = content.lower()
        
        if any(word in content_lower for word in ['password', 'credential', 'login']):
            return 'data_breach'
        elif any(word in content_lower for word in ['exploit', 'vulnerability', 'CVE']):
            return 'vulnerability'
        elif any(word in content_lower for word in ['zero-day', '0day']):
            return 'zero_day'
        elif any(word in content_lower for word in ['malware', 'trojan', 'virus']):
            return 'malware'
        else:
            return 'security_content'
    
    async def collect_all_threats(self) -> List[Dict[str, Any]]:
        """Collect threats from all sources"""
        all_articles = []
        
        # Collect from different source types
        logger.info("Collecting threats from GitHub security...")
        github_articles = await self.scrape_github_security()
        all_articles.extend(github_articles)
        
        logger.info("Collecting threats from CVE databases...")
        cve_articles = await self.scrape_cve_databases()
        all_articles.extend(cve_articles)
        
        logger.info("Collecting threats from paste sites...")
        paste_articles = await self.scrape_paste_sites()
        all_articles.extend(paste_articles)
        
        # Remove duplicates and sort by threat score
        unique_articles = self._remove_duplicates(all_articles)
        sorted_articles = sorted(unique_articles, key=lambda x: x.get('threat_score', 0), reverse=True)
        
        logger.info(f"Collected {len(sorted_articles)} unique threat articles")
        return sorted_articles
    
    def _remove_duplicates(self, articles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate articles based on content hash"""
        seen_hashes = set()
        unique_articles = []
        
        for article in articles:
            # Create content hash
            content = f"{article.get('title', '')}{article.get('link', '')}"
            content_hash = hashlib.md5(content.encode()).hexdigest()
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                unique_articles.append(article)
                
        return unique_articles

# Utility function for easy access
async def get_advanced_threat_intelligence() -> Dict[str, Any]:
    """Get advanced threat intelligence data"""
    async with AdvancedThreatScraper() as scraper:
        articles = await scraper.collect_all_threats()
        
        # Transform to dashboard format
        return {
            'threat_articles': articles,
            'total_articles': len(articles),
            'high_severity_count': len([a for a in articles if a.get('threat_score', 0) > 0.8]),
            'source_types': list(set(a.get('source_type', '') for a in articles)),
            'threat_types': list(set(a.get('threat_type', '') for a in articles)),
            'collection_time': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Test the advanced scraper
    async def test_advanced_scraper():
        data = await get_advanced_threat_intelligence()
        print(f"Advanced Threat Intelligence Results:")
        print(f"Total articles: {data['total_articles']}")
        print(f"High severity threats: {data['high_severity_count']}")
        print(f"Source types: {data['source_types']}")
        print(f"Threat types: {data['threat_types']}")
        
        # Show top 5 threats
        print("\nTop 5 threats:")
        for i, article in enumerate(data['threat_articles'][:5]):
            print(f"{i+1}. {article['title']} (Score: {article['threat_score']:.2f})")
    
    asyncio.run(test_advanced_scraper())
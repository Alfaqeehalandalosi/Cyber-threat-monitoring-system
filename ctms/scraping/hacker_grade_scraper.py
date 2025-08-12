"""
Hacker-Grade Threat Intelligence Scraper
Advanced threat monitoring for hacker forums, ransomware leaks, paste sites, and GitHub
Educational purposes only - Defensive security research
"""

import asyncio
import aiohttp
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
from bs4 import BeautifulSoup
import hashlib
from urllib.parse import urljoin, urlparse
import time
import random
import lxml.html
from lxml import etree

# Import configuration
from ctms.config.hacker_sources import HACKER_SOURCES_CONFIG, THREAT_KEYWORDS, TRUST_LEVELS

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HackerGradeScraper:
    """Advanced hacker-grade threat intelligence scraper"""
    
    def __init__(self):
        self.session = None
        self.config = HACKER_SOURCES_CONFIG
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        self.headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.session = aiohttp.ClientSession(headers=self.headers, timeout=timeout)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def scrape_hacker_forums(self) -> List[Dict[str, Any]]:
        """Scrape hacker forums for threat intelligence"""
        articles = []
        forum_config = self.config.get('hacker_forums', {})
        
        if not forum_config.get('enabled', True):
            return articles
        
        sources = forum_config.get('sources', [])
        
        for source in sources:
            try:
                logger.info(f"Scraping hacker forum: {source['name']}")
                forum_articles = await self._scrape_forum_source(source)
                articles.extend(forum_articles)
                
                # Rate limiting
                await asyncio.sleep(random.uniform(2, 5))
                
            except Exception as e:
                logger.error(f"Error scraping forum {source['name']}: {str(e)}")
                continue
                
        return articles
    
    async def _scrape_forum_source(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape individual forum source"""
        articles = []
        
        try:
            async with self.session.get(source['url'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse with lxml for better XPath support
                    tree = lxml.html.fromstring(content)
                    
                    # Extract threads using XPath selectors
                    selectors = source.get('selectors', {})
                    thread_elements = tree.xpath(selectors.get('threads', '//div[contains(@class, "thread")]'))
                    
                    for element in thread_elements[:20]:  # Limit to 20 threads per forum
                        try:
                            # Extract title
                            title_elements = element.xpath(selectors.get('title', './/h3[@class="thread-title"]/a/text()'))
                            title = title_elements[0].strip() if title_elements else "Unknown Thread"
                            
                            # Extract link
                            link_elements = element.xpath(selectors.get('link', './/h3[@class="thread-title"]/a/@href'))
                            link = link_elements[0] if link_elements else ""
                            if link and not link.startswith('http'):
                                link = urljoin(source['url'], link)
                            
                            # Extract content (first post)
                            content_elements = element.xpath(selectors.get('content', './/div[@class="post-content"]/text()'))
                            content = content_elements[0].strip() if content_elements else ""
                            
                            # Extract date
                            date_elements = element.xpath(selectors.get('date', './/span[@class="post-date"]/text()'))
                            date = date_elements[0].strip() if date_elements else datetime.now().isoformat()
                            
                            # Check if content contains threat keywords
                            if self._contains_threat_keywords(title + " " + content):
                                article = {
                                    'title': title,
                                    'content': content[:500] + "..." if len(content) > 500 else content,
                                    'link': link,
                                    'source': source['name'],
                                    'source_type': 'hacker_forum',
                                    'published': date,
                                    'threat_score': self._calculate_forum_threat_score(title, content, source),
                                    'threat_type': self._classify_forum_content(title, content),
                                    'tags': source.get('tags', []) + self._extract_tags(title, content),
                                    'scraped_at': datetime.now().isoformat(),
                                    'trust_level': source.get('trust_level', 0.5)
                                }
                                articles.append(article)
                                
                        except Exception as e:
                            logger.warning(f"Error processing forum thread: {str(e)}")
                            continue
                            
        except Exception as e:
            logger.error(f"Error scraping forum {source['name']}: {str(e)}")
            
        return articles
    
    async def scrape_ransomware_leak_sites(self) -> List[Dict[str, Any]]:
        """Scrape ransomware leak sites for data breach intelligence"""
        articles = []
        leak_config = self.config.get('ransomware_leak_sites', {})
        
        if not leak_config.get('enabled', True):
            return articles
        
        sources = leak_config.get('sources', [])
        
        for source in sources:
            try:
                logger.info(f"Scraping ransomware leak site: {source['name']}")
                leak_articles = await self._scrape_leak_site(source)
                articles.extend(leak_articles)
                
                # Rate limiting
                await asyncio.sleep(random.uniform(3, 7))
                
            except Exception as e:
                logger.error(f"Error scraping leak site {source['name']}: {str(e)}")
                continue
                
        return articles
    
    async def _scrape_leak_site(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape individual ransomware leak site"""
        articles = []
        
        try:
            async with self.session.get(source['url'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse with lxml
                    tree = lxml.html.fromstring(content)
                    
                    # Extract victim entries
                    selectors = source.get('selectors', {})
                    victim_elements = tree.xpath(selectors.get('victims', '//div[@class="victim-item"]'))
                    
                    for element in victim_elements[:15]:  # Limit to 15 victims per site
                        try:
                            # Extract victim name/title
                            title_elements = element.xpath(selectors.get('title', './/h3[@class="victim-name"]/text()'))
                            title = title_elements[0].strip() if title_elements else "Unknown Victim"
                            
                            # Extract link
                            link_elements = element.xpath(selectors.get('link', './/a[@class="victim-link"]/@href'))
                            link = link_elements[0] if link_elements else ""
                            if link and not link.startswith('http'):
                                link = urljoin(source['url'], link)
                            
                            # Extract description
                            content_elements = element.xpath(selectors.get('content', './/div[@class="victim-description"]/text()'))
                            content = content_elements[0].strip() if content_elements else ""
                            
                            # Extract date
                            date_elements = element.xpath(selectors.get('date', './/span[@class="leak-date"]/text()'))
                            date = date_elements[0].strip() if date_elements else datetime.now().isoformat()
                            
                            article = {
                                'title': f"Ransomware Victim: {title}",
                                'content': content[:500] + "..." if len(content) > 500 else content,
                                'link': link,
                                'source': source['name'],
                                'source_type': 'ransomware_leak',
                                'published': date,
                                'threat_score': self._calculate_leak_threat_score(title, content, source),
                                'threat_type': 'data_breach',
                                'tags': source.get('tags', []) + ['ransomware', 'data_breach', 'victim'],
                                'scraped_at': datetime.now().isoformat(),
                                'trust_level': source.get('trust_level', 0.9)
                            }
                            articles.append(article)
                            
                        except Exception as e:
                            logger.warning(f"Error processing leak victim: {str(e)}")
                            continue
                            
        except Exception as e:
            logger.error(f"Error scraping leak site {source['name']}: {str(e)}")
            
        return articles
    
    async def scrape_paste_sites(self) -> List[Dict[str, Any]]:
        """Scrape paste sites for threat intelligence"""
        articles = []
        paste_config = self.config.get('paste_sites', {})
        
        if not paste_config.get('enabled', True):
            return articles
        
        sources = paste_config.get('sources', [])
        
        for source in sources:
            try:
                logger.info(f"Scraping paste site: {source['name']}")
                paste_articles = await self._scrape_paste_site(source)
                articles.extend(paste_articles)
                
                # Rate limiting
                await asyncio.sleep(random.uniform(1, 3))
                
            except Exception as e:
                logger.error(f"Error scraping paste site {source['name']}: {str(e)}")
                continue
                
        return articles
    
    async def _scrape_paste_site(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scrape individual paste site"""
        articles = []
        
        try:
            async with self.session.get(source['url'], timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse with lxml
                    tree = lxml.html.fromstring(content)
                    
                    # Extract paste entries
                    selectors = source.get('selectors', {})
                    paste_elements = tree.xpath(selectors.get('pastes', '//div[@class="archive-entry"]'))
                    
                    for element in paste_elements[:10]:  # Limit to 10 pastes per site
                        try:
                            # Extract title
                            title_elements = element.xpath(selectors.get('title', './/a[@class="archive-title"]/text()'))
                            title = title_elements[0].strip() if title_elements else "Unknown Paste"
                            
                            # Extract link
                            link_elements = element.xpath(selectors.get('link', './/a[@class="archive-title"]/@href'))
                            link = link_elements[0] if link_elements else ""
                            if link and not link.startswith('http'):
                                link = urljoin(source['url'], link)
                            
                            # Extract content
                            content_elements = element.xpath(selectors.get('content', './/div[@class="archive-content"]/text()'))
                            content = content_elements[0].strip() if content_elements else ""
                            
                            # Extract date
                            date_elements = element.xpath(selectors.get('date', './/span[@class="archive-date"]/text()'))
                            date = date_elements[0].strip() if date_elements else datetime.now().isoformat()
                            
                            # Check if content contains threat keywords
                            if self._contains_threat_keywords(title + " " + content):
                                article = {
                                    'title': f"Paste: {title}",
                                    'content': content[:500] + "..." if len(content) > 500 else content,
                                    'link': link,
                                    'source': source['name'],
                                    'source_type': 'paste_site',
                                    'published': date,
                                    'threat_score': self._calculate_paste_threat_score(title, content, source),
                                    'threat_type': self._classify_paste_content(title, content),
                                    'tags': source.get('tags', []) + self._extract_tags(title, content),
                                    'scraped_at': datetime.now().isoformat(),
                                    'trust_level': source.get('trust_level', 0.4)
                                }
                                articles.append(article)
                                
                        except Exception as e:
                            logger.warning(f"Error processing paste: {str(e)}")
                            continue
                            
        except Exception as e:
            logger.error(f"Error scraping paste site {source['name']}: {str(e)}")
            
        return articles
    
    async def scrape_github_exploits(self) -> List[Dict[str, Any]]:
        """Scrape GitHub for exploit repositories"""
        articles = []
        github_config = self.config.get('github_monitoring', {})
        
        if not github_config.get('enabled', True):
            return articles
        
        queries = github_config.get('queries', [])
        api_endpoint = github_config.get('api_endpoint', 'https://api.github.com/search/repositories')
        
        for query_config in queries:
            try:
                logger.info(f"Searching GitHub for: {query_config['query']}")
                github_articles = await self._search_github_exploits(api_endpoint, query_config)
                articles.extend(github_articles)
                
                # Rate limiting for GitHub API
                await asyncio.sleep(random.uniform(2, 4))
                
            except Exception as e:
                logger.error(f"Error searching GitHub for {query_config['query']}: {str(e)}")
                continue
                
        return articles
    
    async def _search_github_exploits(self, api_endpoint: str, query_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search GitHub for exploit repositories"""
        articles = []
        
        try:
            # Add GitHub API headers
            headers = self.headers.copy()
            headers['Accept'] = 'application/vnd.github.v3+json'
            
            # Make API request
            params = {
                'q': query_config['query'],
                'sort': 'updated',
                'order': 'desc',
                'per_page': 10
            }
            
            async with self.session.get(api_endpoint, params=params, headers=headers, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for repo in data.get('items', [])[:5]:  # Top 5 repos per query
                        try:
                            # Check if repository contains threat-related content
                            if self._is_exploit_repository(repo):
                                article = {
                                    'title': f"GitHub Exploit: {repo['name']}",
                                    'content': repo.get('description', '') or f"Exploit repository for {query_config['query']}",
                                    'link': repo['html_url'],
                                    'source': 'GitHub',
                                    'source_type': 'github',
                                    'published': repo['updated_at'],
                                    'threat_score': self._calculate_github_threat_score(repo, query_config),
                                    'threat_type': self._classify_github_content(repo, query_config),
                                    'tags': query_config.get('tags', []) + repo.get('topics', []) + ['github', 'exploit'],
                                    'scraped_at': datetime.now().isoformat(),
                                    'trust_level': query_config.get('trust_level', 0.7),
                                    'github_data': {
                                        'stars': repo.get('stargazers_count', 0),
                                        'forks': repo.get('forks_count', 0),
                                        'language': repo.get('language', 'Unknown'),
                                        'size': repo.get('size', 0)
                                    }
                                }
                                articles.append(article)
                                
                        except Exception as e:
                            logger.warning(f"Error processing GitHub repo: {str(e)}")
                            continue
                            
        except Exception as e:
            logger.error(f"Error searching GitHub: {str(e)}")
            
        return articles
    
    def _contains_threat_keywords(self, text: str) -> bool:
        """Check if text contains threat-related keywords"""
        text_lower = text.lower()
        
        for category, keywords in THREAT_KEYWORDS.items():
            if any(keyword in text_lower for keyword in keywords):
                return True
                
        return False
    
    def _calculate_forum_threat_score(self, title: str, content: str, source: Dict[str, Any]) -> float:
        """Calculate threat score for forum content"""
        score = source.get('trust_level', 0.5)
        text = f"{title} {content}".lower()
        
        # Keyword-based scoring
        for category, keywords in THREAT_KEYWORDS.items():
            matches = sum(1 for keyword in keywords if keyword in text)
            if matches > 0:
                if category == 'zero_day':
                    score += 0.3
                elif category == 'critical_vulnerability':
                    score += 0.2
                elif category == 'data_breach':
                    score += 0.2
                elif category == 'malware':
                    score += 0.15
                elif category == 'exploit':
                    score += 0.1
                    
        # Code indicators
        if any(indicator in text for indicator in ['function(', 'class ', 'import ', 'require ', 'include ']):
            score += 0.1
            
        # URL indicators
        if re.findall(r'http[s]?://', text):
            score += 0.05
            
        return min(1.0, score)
    
    def _calculate_leak_threat_score(self, title: str, content: str, source: Dict[str, Any]) -> float:
        """Calculate threat score for ransomware leak content"""
        score = source.get('trust_level', 0.9)
        text = f"{title} {content}".lower()
        
        # Data breach indicators
        if any(indicator in text for indicator in ['data', 'breach', 'leak', 'stolen', 'compromised']):
            score += 0.1
            
        # Company indicators
        if re.findall(r'\b[A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company)\b', text):
            score += 0.1
            
        # Size indicators
        if re.findall(r'\d+[KMB]?\s*(?:records|users|accounts|files)', text):
            score += 0.1
            
        return min(1.0, score)
    
    def _calculate_paste_threat_score(self, title: str, content: str, source: Dict[str, Any]) -> float:
        """Calculate threat score for paste content"""
        score = source.get('trust_level', 0.4)
        text = f"{title} {content}".lower()
        
        # High-threat keywords
        for category, keywords in THREAT_KEYWORDS.items():
            matches = sum(1 for keyword in keywords if keyword in text)
            if matches > 0:
                if category == 'zero_day':
                    score += 0.4
                elif category == 'critical_vulnerability':
                    score += 0.3
                elif category == 'data_breach':
                    score += 0.3
                elif category == 'malware':
                    score += 0.2
                elif category == 'exploit':
                    score += 0.2
                    
        # Code indicators
        if re.findall(r'(?:function|class|def|import|require|include)', text):
            score += 0.2
            
        # Command indicators
        if re.findall(r'(?:cmd|powershell|bash|sh|\.exe|\.bat)', text):
            score += 0.15
            
        return min(1.0, score)
    
    def _calculate_github_threat_score(self, repo: Dict[str, Any], query_config: Dict[str, Any]) -> float:
        """Calculate threat score for GitHub repository"""
        score = query_config.get('trust_level', 0.7)
        
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
        threat_topics = ['exploit', 'vulnerability', 'malware', 'hacking', 'security']
        if any(topic in threat_topics for topic in topics):
            score += 0.2
            
        return min(1.0, score)
    
    def _classify_forum_content(self, title: str, content: str) -> str:
        """Classify forum content type"""
        text = f"{title} {content}".lower()
        
        if any(word in text for word in ['zero-day', '0day', 'zero day']):
            return 'zero_day'
        elif any(word in text for word in ['exploit', 'vulnerability', 'CVE']):
            return 'exploit'
        elif any(word in text for word in ['malware', 'trojan', 'virus']):
            return 'malware'
        elif any(word in text for word in ['data breach', 'leak', 'stolen']):
            return 'data_breach'
        else:
            return 'general_threat'
    
    def _classify_paste_content(self, title: str, content: str) -> str:
        """Classify paste content type"""
        text = f"{title} {content}".lower()
        
        if any(word in text for word in ['password', 'credential', 'login']):
            return 'data_breach'
        elif any(word in text for word in ['exploit', 'vulnerability', 'CVE']):
            return 'exploit'
        elif any(word in text for word in ['zero-day', '0day']):
            return 'zero_day'
        elif any(word in text for word in ['malware', 'trojan', 'virus']):
            return 'malware'
        else:
            return 'security_content'
    
    def _classify_github_content(self, repo: Dict[str, Any], query_config: Dict[str, Any]) -> str:
        """Classify GitHub content type"""
        query = query_config.get('query', '').lower()
        
        if '0day' in query or 'zero-day' in query:
            return 'zero_day'
        elif 'exploit' in query:
            return 'exploit'
        elif 'CVE' in query:
            return 'vulnerability'
        elif 'privilege escalation' in query:
            return 'privilege_escalation'
        elif 'rce' in query:
            return 'remote_code_execution'
        else:
            return 'security_research'
    
    def _is_exploit_repository(self, repo: Dict[str, Any]) -> bool:
        """Check if repository is likely an exploit repository"""
        name = repo.get('name', '').lower()
        description = repo.get('description', '').lower()
        topics = [topic.lower() for topic in repo.get('topics', [])]
        
        # Check for exploit-related terms
        exploit_terms = ['exploit', 'poc', 'vulnerability', 'cve', '0day', 'zero-day', 'hack']
        
        return any(term in name or term in description or any(term in topic for topic in topics) for term in exploit_terms)
    
    def _extract_tags(self, title: str, content: str) -> List[str]:
        """Extract relevant tags from content"""
        text = f"{title} {content}".lower()
        tags = []
        
        # Extract CVE IDs
        cve_matches = re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
        tags.extend(cve_matches)
        
        # Extract common security terms
        security_terms = ['exploit', 'vulnerability', 'malware', 'hack', 'breach', 'leak']
        for term in security_terms:
            if term in text:
                tags.append(term)
                
        return list(set(tags))  # Remove duplicates
    
    async def collect_all_hacker_threats(self) -> List[Dict[str, Any]]:
        """Collect threats from all hacker-grade sources"""
        all_articles = []
        
        # Collect from different source types
        logger.info("Collecting threats from hacker forums...")
        forum_articles = await self.scrape_hacker_forums()
        all_articles.extend(forum_articles)
        
        logger.info("Collecting threats from ransomware leak sites...")
        leak_articles = await self.scrape_ransomware_leak_sites()
        all_articles.extend(leak_articles)
        
        logger.info("Collecting threats from paste sites...")
        paste_articles = await self.scrape_paste_sites()
        all_articles.extend(paste_articles)
        
        logger.info("Collecting threats from GitHub...")
        github_articles = await self.scrape_github_exploits()
        all_articles.extend(github_articles)
        
        # Remove duplicates and sort by threat score
        unique_articles = self._remove_duplicates(all_articles)
        sorted_articles = sorted(unique_articles, key=lambda x: x.get('threat_score', 0), reverse=True)
        
        logger.info(f"Collected {len(sorted_articles)} unique hacker-grade threat articles")
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
async def get_hacker_grade_threat_intelligence() -> Dict[str, Any]:
    """Get hacker-grade threat intelligence data"""
    async with HackerGradeScraper() as scraper:
        articles = await scraper.collect_all_hacker_threats()
        
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
    # Test the hacker-grade scraper
    async def test_hacker_scraper():
        data = await get_hacker_grade_threat_intelligence()
        print(f"Hacker-Grade Threat Intelligence Results:")
        print(f"Total articles: {data['total_articles']}")
        print(f"High severity threats: {data['high_severity_count']}")
        print(f"Source types: {data['source_types']}")
        print(f"Threat types: {data['threat_types']}")
        
        # Show top 5 threats
        print("\nTop 5 threats:")
        for i, article in enumerate(data['threat_articles'][:5]):
            print(f"{i+1}. {article['title']} (Score: {article['threat_score']:.2f})")
    
    asyncio.run(test_hacker_scraper())
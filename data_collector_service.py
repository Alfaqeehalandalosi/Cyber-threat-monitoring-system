#!/usr/bin/env python3
"""
Hacker-Grade Threat Intelligence - Data Collection Service
Production-ready background data collection service
"""

import asyncio
import aiohttp
import sqlite3
import json
import logging
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os
import signal
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ctms/logs/collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatDataCollector:
    """Production threat data collector"""
    
    def __init__(self):
        self.db_path = "ctms/data/threat_intelligence.db"
        self.collection_interval = 60  # 1 minute instead of 5 minutes
        self.running = True
        self.session = None
        
        # Ensure directories exist
        os.makedirs('ctms/data', exist_ok=True)
        os.makedirs('ctms/logs', exist_ok=True)
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize database with proper schema"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT,
                    threat_score REAL DEFAULT 0.0,
                    threat_type TEXT,
                    source TEXT,
                    source_type TEXT,
                    published_at TEXT,
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    indicators TEXT,
                    hash_id TEXT UNIQUE,
                    status TEXT DEFAULT 'active'
                )
            ''')
            
            # Create collection_log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS collection_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_type TEXT,
                    articles_collected INTEGER,
                    articles_new INTEGER,
                    duration_seconds REAL,
                    status TEXT,
                    error_message TEXT
                )
            ''')
            
            # Create system_status table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    last_collection TIMESTAMP,
                    total_threats INTEGER,
                    high_severity_count INTEGER,
                    next_collection TIMESTAMP,
                    system_health TEXT DEFAULT 'healthy'
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    async def start_session(self):
        """Start aiohttp session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    def generate_hash_id(self, title: str, source: str, published: str) -> str:
        """Generate unique hash for threat article"""
        import hashlib
        content = f"{title}:{source}:{published}"
        return hashlib.md5(content.encode()).hexdigest()
    
    async def collect_hacker_forum_data(self) -> List[Dict[str, Any]]:
        """Collect data from hacker forums"""
        start_time = time.time()
        articles = []
        
        try:
            # Real hacker forum sources
            forum_urls = [
                "https://exploit.in/index.php",
                "https://xss.is/index.php", 
                "https://breachforums.st/index.php",
                "https://0day.today/exploit",
                "https://www.nulled.to/forum/10-security-and-hacking/",
                "https://hackforums.net/forumdisplay.php?fid=45",
                "https://cracked.to/Forum-Hacking-Tutorials",
                "https://sinister.ly/Forum-Hacking-Tutorials",
                "https://leakbase.pw/",
                "https://www.blackhatworld.com/forums/white-hat-seo.58/"
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            successful_scrapes = 0
            
            for url in forum_urls:
                try:
                    async with self.session.get(url, headers=headers, timeout=15) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # More flexible threat patterns
                            threat_patterns = [
                                r'(?i)(zero.?day|0day|zero day)',
                                r'(?i)(exploit|vulnerability|bug)',
                                r'(?i)(malware|ransomware|trojan|virus)',
                                r'(?i)(breach|leak|stolen|compromised)',
                                r'(?i)(hack|attack|intrusion)',
                                r'(?i)(CVE-\d{4}-\d+)',
                                r'(?i)(remote.?code.?execution|RCE)',
                                r'(?i)(sql.?injection|XSS|CSRF)',
                                r'(?i)(privilege.?escalation)',
                                r'(?i)(data.?breach|data.?leak)'
                            ]
                            
                            found_threats = 0
                            for pattern in threat_patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    # Create threat article from found content
                                    threat_content = ' '.join(matches[:3])  # Take first 3 matches
                                    
                                    # Calculate threat score based on keywords
                                    threat_score = self._calculate_threat_score(threat_content)
                                    
                                    if threat_score > 0.2:  # Lower threshold
                                        # Extract indicators from content
                                        indicators = self._extract_indicators(threat_content)
                                        
                                        article = {
                                            'title': f'Hacker Forum Threat: {pattern}',
                                            'content': threat_content[:1000],  # Increased content length for better indicator extraction
                                            'source': url,
                                            'source_type': 'hacker_forum',
                                            'published': datetime.now().isoformat(),
                                            'threat_score': threat_score,
                                            'threat_type': self._classify_threat_type(threat_content),
                                            'indicators': indicators
                                        }
                                        article['hash_id'] = self.generate_hash_id(
                                            article['title'], 
                                            article['source'], 
                                            article['published']
                                        )
                                        articles.append(article)
                                        found_threats += 1
                            
                            if found_threats > 0:
                                successful_scrapes += 1
                                logger.info(f"Scraped {url}: Found {found_threats} threats")
                            else:
                                logger.info(f"Scraped {url}: No threats found")
                            
                except Exception as e:
                    logger.warning(f"Failed to scrape {url}: {e}")
                    continue
            
            # If no threats found from hacker forums, try mainstream cybersecurity news
            if len(articles) == 0:
                logger.info("No threats found from hacker forums, trying mainstream cybersecurity news")
                articles.extend(await self._collect_mainstream_cybersecurity_news())
            
            duration = time.time() - start_time
            await self.log_collection('hacker_forum', len(articles), len(articles), duration, 'success')
            logger.info(f"Collected {len(articles)} articles from hacker forums in {duration:.2f}s")
            
        except Exception as e:
            duration = time.time() - start_time
            await self.log_collection('hacker_forum', 0, 0, duration, 'error', str(e))
            logger.error(f"Error collecting hacker forum data: {e}")
        
        return articles
    
    async def _collect_mainstream_cybersecurity_news(self) -> List[Dict[str, Any]]:
        """Collect real cybersecurity news from mainstream sources"""
        articles = []
        
        try:
            # Mainstream cybersecurity news sources that work reliably
            news_sources = [
                {
                    'url': 'https://www.bleepingcomputer.com/',
                    'name': 'Bleeping Computer',
                    'type': 'mainstream_news'
                },
                {
                    'url': 'https://thehackernews.com/',
                    'name': 'The Hacker News',
                    'type': 'mainstream_news'
                },
                {
                    'url': 'https://www.darkreading.com/',
                    'name': 'Dark Reading',
                    'type': 'mainstream_news'
                },
                {
                    'url': 'https://www.securityweek.com/',
                    'name': 'Security Week',
                    'type': 'mainstream_news'
                },
                {
                    'url': 'https://threatpost.com/',
                    'name': 'Threatpost',
                    'type': 'mainstream_news'
                }
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            for source in news_sources:
                try:
                    async with self.session.get(source['url'], headers=headers, timeout=15) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Look for article titles and content
                            # Common patterns for news sites
                            title_patterns = [
                                r'<h[1-6][^>]*>([^<]*?(?:vulnerability|exploit|malware|ransomware|breach|attack|hack|cyber|security)[^<]*)</h[1-6]>',
                                r'<title[^>]*>([^<]*?(?:vulnerability|exploit|malware|ransomware|breach|attack|hack|cyber|security)[^<]*)</title>',
                                r'<a[^>]*href[^>]*>([^<]*?(?:vulnerability|exploit|malware|ransomware|breach|attack|hack|cyber|security)[^<]*)</a>'
                            ]
                            
                            for pattern in title_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches[:3]:  # Take first 3 matches
                                    if len(match.strip()) > 20:  # Only meaningful titles
                                        threat_score = self._calculate_threat_score(match)
                                        
                                        if threat_score > 0.3:  # Higher threshold for news
                                            # Extract indicators from content
                                            indicators = self._extract_indicators(match)
                                            
                                            article = {
                                                'title': match.strip()[:100],
                                                'content': f"Latest cybersecurity news from {source['name']}: {match.strip()}",
                                                'source': source['name'],
                                                'source_type': source['type'],
                                                'published': datetime.now().isoformat(),
                                                'threat_score': threat_score,
                                                'threat_type': self._classify_threat_type(match),
                                                'indicators': indicators
                                            }
                                            article['hash_id'] = self.generate_hash_id(
                                                article['title'], 
                                                article['source'], 
                                                article['published']
                                            )
                                            articles.append(article)
                            
                            logger.info(f"Scraped {source['name']}: Found {len([a for a in articles if a['source'] == source['name']])} threats")
                            
                except Exception as e:
                    logger.warning(f"Failed to scrape {source['name']}: {e}")
                    continue
            
            logger.info(f"Collected {len(articles)} articles from mainstream cybersecurity news")
            
        except Exception as e:
            logger.error(f"Error collecting mainstream cybersecurity news: {e}")
        
        return articles
    
    async def collect_ransomware_leak_data(self) -> List[Dict[str, Any]]:
        """Collect data from ransomware leak sites"""
        start_time = time.time()
        articles = []
        
        try:
            # Real ransomware leak site URLs
            leak_urls = [
                "https://lockbitfiles.com/",
                "https://blackcatleaks.com/",
                "https://blackbasta.net/",
                "https://medusaleaks.com/",
                "https://playleaks.com/",
                "https://bianliannews.com/",
                "https://royalleaks.com/",
                "https://snatchleaks.com/",
                "https://cubaleaks.com/",
                "https://vicesocietyleaks.com/"
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            for url in leak_urls:
                try:
                    async with self.session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Look for data breach indicators
                            breach_patterns = [
                                r'(?i)(company|organization|corporation|enterprise)',
                                r'(?i)(data.?breach|leak|stolen|compromised|dumped)',
                                r'(?i)(customer|user|employee|personal)',
                                r'(?i)(email|password|credential|account)',
                                r'(?i)(ransom|payment|bitcoin|cryptocurrency)'
                            ]
                            
                            for pattern in breach_patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    breach_content = ' '.join(matches[:5])
                                    threat_score = self._calculate_threat_score(breach_content)
                                    
                                    if threat_score > 0.4:  # Higher threshold for leak sites
                                        # Extract indicators from content
                                        indicators = self._extract_indicators(breach_content)
                                        
                                        article = {
                                            'title': f'Ransomware Leak: {pattern}',
                                            'content': breach_content[:1000],  # Increased content length
                                            'source': url,
                                            'source_type': 'ransomware_leak',
                                            'published': datetime.now().isoformat(),
                                            'threat_score': threat_score,
                                            'threat_type': 'data_breach',
                                            'indicators': indicators
                                        }
                                        article['hash_id'] = self.generate_hash_id(
                                            article['title'], 
                                            article['source'], 
                                            article['published']
                                        )
                                        articles.append(article)
                            
                            logger.info(f"Scraped {url}: Found {len([a for a in articles if a['source'] == url])} leaks")
                            
                except Exception as e:
                    logger.warning(f"Failed to scrape {url}: {e}")
                    continue
            
            # If no threats found from ransomware leaks, try mainstream cybersecurity news
            if len(articles) == 0:
                logger.info("No ransomware leaks found, trying mainstream cybersecurity news")
                articles.extend(await self._collect_mainstream_cybersecurity_news())
            
            duration = time.time() - start_time
            await self.log_collection('ransomware_leak', len(articles), len(articles), duration, 'success')
            logger.info(f"Collected {len(articles)} articles from ransomware leaks in {duration:.2f}s")
            
        except Exception as e:
            duration = time.time() - start_time
            await self.log_collection('ransomware_leak', 0, 0, duration, 'error', str(e))
            logger.error(f"Error collecting ransomware leak data: {e}")
        
        return articles
    
    async def collect_paste_site_data(self) -> List[Dict[str, Any]]:
        """Collect data from paste sites"""
        start_time = time.time()
        articles = []
        
        try:
            # Real paste site URLs
            paste_urls = [
                "https://pastebin.com/archive",
                "https://ghostbin.com/pastes",
                "https://paste.ee/latest",
                "https://justpaste.it/en/latest",
                "https://hastebin.com/",
                "https://rentry.co/",
                "https://dumpz.org/en/latest/",
                "https://paste.org.ru/",
                "https://paste2.org/",
                "https://ideone.com/recent"
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            for url in paste_urls:
                try:
                    async with self.session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Look for credential dumps and exploits
                            paste_patterns = [
                                r'(?i)(email|password|credential|account|login)',
                                r'(?i)(exploit|vulnerability|PoC|proof.?of.?concept)',
                                r'(?i)(sql.?injection|XSS|CSRF|buffer.?overflow)',
                                r'(?i)(malware|virus|trojan|backdoor)',
                                r'(?i)(CVE-\d{4}-\d+)'
                            ]
                            
                            for pattern in paste_patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    paste_content = ' '.join(matches[:5])
                                    threat_score = self._calculate_threat_score(paste_content)
                                    
                                    if threat_score > 0.3:
                                        # Extract indicators from content
                                        indicators = self._extract_indicators(paste_content)
                                        
                                        article = {
                                            'title': f'Paste Site: {pattern}',
                                            'content': paste_content[:1000],  # Increased content length
                                            'source': url,
                                            'source_type': 'paste_site',
                                            'published': datetime.now().isoformat(),
                                            'threat_score': threat_score,
                                            'threat_type': self._classify_threat_type(paste_content),
                                            'indicators': indicators
                                        }
                                        article['hash_id'] = self.generate_hash_id(
                                            article['title'], 
                                            article['source'], 
                                            article['published']
                                        )
                                        articles.append(article)
                            
                            logger.info(f"Scraped {url}: Found {len([a for a in articles if a['source'] == url])} threats")
                            
                except Exception as e:
                    logger.warning(f"Failed to scrape {url}: {e}")
                    continue
            
            # If no threats found from paste sites, try mainstream cybersecurity news
            if len(articles) == 0:
                logger.info("No paste site threats found, trying mainstream cybersecurity news")
                articles.extend(await self._collect_mainstream_cybersecurity_news())
            
            duration = time.time() - start_time
            await self.log_collection('paste_site', len(articles), len(articles), duration, 'success')
            logger.info(f"Collected {len(articles)} articles from paste sites in {duration:.2f}s")
            
        except Exception as e:
            duration = time.time() - start_time
            await self.log_collection('paste_site', 0, 0, duration, 'error', str(e))
            logger.error(f"Error collecting paste site data: {e}")
        
        return articles
    
    async def collect_github_data(self) -> List[Dict[str, Any]]:
        """Collect data from GitHub"""
        start_time = time.time()
        articles = []
        
        try:
            # GitHub search queries for exploits and vulnerabilities
            github_queries = [
                "exploit language:Python",
                "PoC CVE",
                "CVE-2025",
                "0day exploit",
                "privilege escalation",
                "rce exploit",
                "sql injection exploit",
                "xss exploit",
                "csrf exploit",
                "buffer overflow exploit"
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            for query in github_queries:
                try:
                    # GitHub search API endpoint
                    search_url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc&per_page=10"
                    
                    async with self.session.get(search_url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            for repo in data.get('items', []):
                                repo_name = repo.get('name', '')
                                repo_description = repo.get('description', '')
                                repo_url = repo.get('html_url', '')
                                created_at = repo.get('created_at', '')
                                
                                # Analyze repository for threat indicators
                                repo_content = f"{repo_name} {repo_description}"
                                threat_score = self._calculate_threat_score(repo_content)
                                
                                if threat_score > 0.4:  # Only significant threats
                                    # Extract indicators from content
                                    indicators = self._extract_indicators(repo_content)
                                    
                                    article = {
                                        'title': f'GitHub: {repo_name}',
                                        'content': repo_description[:1000] if repo_description else f"Repository: {repo_name}",
                                        'source': repo_url,
                                        'source_type': 'github',
                                        'published': created_at,
                                        'threat_score': threat_score,
                                        'threat_type': self._classify_threat_type(repo_content),
                                        'indicators': indicators
                                    }
                                    article['hash_id'] = self.generate_hash_id(
                                        article['title'], 
                                        article['source'], 
                                        article['published']
                                    )
                                    articles.append(article)
                            
                            logger.info(f"GitHub query '{query}': Found {len([a for a in articles if query in a['title']])} threats")
                            
                except Exception as e:
                    logger.warning(f"Failed to query GitHub for '{query}': {e}")
                    continue
            
            # If no threats found from GitHub, try mainstream cybersecurity news
            if len(articles) == 0:
                logger.info("No GitHub threats found, trying mainstream cybersecurity news")
                articles.extend(await self._collect_mainstream_cybersecurity_news())
            
            duration = time.time() - start_time
            await self.log_collection('github', len(articles), len(articles), duration, 'success')
            logger.info(f"Collected {len(articles)} articles from GitHub in {duration:.2f}s")
            
        except Exception as e:
            duration = time.time() - start_time
            await self.log_collection('github', 0, 0, duration, 'error', str(e))
            logger.error(f"Error collecting GitHub data: {e}")
        
        return articles
    
    def _calculate_threat_score(self, content: str) -> float:
        """Calculate threat score based on content analysis"""
        content_lower = content.lower()
        score = 0.0
        
        # High severity keywords
        high_severity = ['zero-day', '0day', 'zero day', 'critical', 'remote code execution', 'rce']
        for keyword in high_severity:
            if keyword in content_lower:
                score += 0.2
        
        # Medium severity keywords
        medium_severity = ['exploit', 'vulnerability', 'malware', 'ransomware', 'breach', 'attack']
        for keyword in medium_severity:
            if keyword in content_lower:
                score += 0.1
        
        # CVE references
        cve_matches = re.findall(r'CVE-\d{4}-\d+', content, re.IGNORECASE)
        score += len(cve_matches) * 0.15
        
        # Code indicators
        code_indicators = ['function', 'class', 'def', 'import', 'require', 'include']
        for indicator in code_indicators:
            if indicator in content_lower:
                score += 0.05
        
        return min(1.0, score)
    
    def _classify_threat_type(self, content: str) -> str:
        """Classify threat type based on content"""
        content_lower = content.lower()
        
        if any(word in content_lower for word in ['zero-day', '0day', 'zero day']):
            return 'zero_day'
        elif any(word in content_lower for word in ['remote code execution', 'rce']):
            return 'remote_code_execution'
        elif any(word in content_lower for word in ['data breach', 'leak', 'stolen', 'compromised']):
            return 'data_breach'
        elif any(word in content_lower for word in ['malware', 'ransomware', 'trojan', 'virus']):
            return 'malware'
        elif any(word in content_lower for word in ['exploit', 'poc', 'proof of concept']):
            return 'exploit'
        elif any(word in content_lower for word in ['sql injection', 'xss', 'csrf']):
            return 'web_vulnerability'
        else:
            return 'general_threat'
    
    def _extract_indicators(self, content: str) -> Dict[str, Any]:
        """Extract threat indicators from content"""
        indicators = {
            'cve_identifiers': [],
            'company_names': [],
            'github_repositories': [],
            'ip_addresses': [],
            'email_addresses': [],
            'file_hashes': [],
            'urls': []
        }
        
        # Extract CVE identifiers
        cve_matches = re.findall(r'CVE-\d{4}-\d+', content, re.IGNORECASE)
        indicators['cve_identifiers'] = list(set(cve_matches))
        
        # Extract company names (common patterns)
        company_patterns = [
            r'\b[A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company|Corporation|Technologies|Systems|Security)\b',
            r'\b[A-Z][a-z]+ [A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company|Corporation)\b',
            r'\b[A-Z]{2,}(?:[A-Z][a-z]+)* (?:Inc|Corp|LLC|Ltd|Company|Corporation)\b',
            r'\b[A-Z][a-z]+ [A-Z][a-z]+\b',  # Two-word company names like "Allianz Life"
            r'\b[A-Z][a-z]+(?:[A-Z][a-z]+)*\b'  # CamelCase company names like "Fortinet"
        ]
        
        # Filter out common false positives
        false_positives = {
            'Hackers', 'Attackers', 'Global', 'Brute', 'Force', 'Wave', 'Before', 
            'Shift', 'Hit', 'Life', 'Inc', 'Corp', 'LLC', 'Ltd', 'Company', 
            'Corporation', 'Technologies', 'Systems', 'Security'
        }
        for pattern in company_patterns:
            companies = re.findall(pattern, content)
            indicators['company_names'].extend(companies)
        
        # Filter out false positives and clean up
        filtered_companies = []
        for company in indicators['company_names']:
            # Skip if it's a known false positive
            if company in false_positives:
                continue
            # Skip single words that are likely not company names
            if len(company.split()) == 1 and len(company) < 6:
                continue
            # Skip if it's just a common word
            if company.lower() in ['hackers', 'attackers', 'global', 'brute', 'force', 'wave', 'before', 'shift', 'hit']:
                continue
            filtered_companies.append(company)
        
        indicators['company_names'] = list(set(filtered_companies))
        
        # Extract GitHub repositories
        github_patterns = [
            r'github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+',
            r'https?://github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+',
            r'github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+/blob/',
            r'github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+/tree/'
        ]
        for pattern in github_patterns:
            repos = re.findall(pattern, content)
            indicators['github_repositories'].extend(repos)
        indicators['github_repositories'] = list(set(indicators['github_repositories']))
        
        # Extract IP addresses
        ip_patterns = [
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'  # IPv6
        ]
        for pattern in ip_patterns:
            ips = re.findall(pattern, content)
            indicators['ip_addresses'].extend(ips)
        indicators['ip_addresses'] = list(set(indicators['ip_addresses']))
        
        # Extract email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        indicators['email_addresses'] = list(set(emails))
        
        # Extract file hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        for pattern in hash_patterns:
            hashes = re.findall(pattern, content)
            indicators['file_hashes'].extend(hashes)
        indicators['file_hashes'] = list(set(indicators['file_hashes']))
        
        # Extract URLs
        url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        urls = re.findall(url_pattern, content)
        indicators['urls'] = list(set(urls))
        
        return indicators
    
    async def store_threats(self, articles: List[Dict[str, Any]]) -> int:
        """Store threats in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            new_articles = 0
            for article in articles:
                try:
                    # Use INSERT OR REPLACE instead of INSERT OR IGNORE to ensure data is stored
                    cursor.execute('''
                        INSERT OR REPLACE INTO threats 
                        (title, content, threat_score, threat_type, source, source_type, 
                         published_at, hash_id, indicators)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        article['title'],
                        article['content'],
                        article.get('threat_score', 0.0),
                        article.get('threat_type', 'unknown'),
                        article['source'],
                        article['source_type'],
                        article['published'],
                        article['hash_id'],
                        json.dumps(article.get('indicators', {}))
                    ))
                    
                    new_articles += 1
                    logger.info(f"Stored article: {article['title'][:50]}...")
                        
                except Exception as e:
                    logger.error(f"Error storing article {article['title']}: {e}")
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Successfully stored {new_articles} articles in database")
            return new_articles
            
        except Exception as e:
            logger.error(f"❌ Error storing threats: {e}")
            return 0
    
    async def log_collection(self, source_type: str, collected: int, new: int, 
                           duration: float, status: str, error_msg: str = None):
        """Log collection activity"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO collection_log 
                (source_type, articles_collected, articles_new, duration_seconds, status, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (source_type, collected, new, duration, status, error_msg))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging collection: {e}")
    
    async def update_system_status(self):
        """Update system status"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total threats
            cursor.execute('SELECT COUNT(*) FROM threats WHERE status = "active"')
            total_threats = cursor.fetchone()[0]
            
            # Get high severity count
            cursor.execute('SELECT COUNT(*) FROM threats WHERE threat_score > 0.8 AND status = "active"')
            high_severity_count = cursor.fetchone()[0]
            
            # Calculate next collection time
            next_collection = datetime.now() + timedelta(seconds=self.collection_interval)
            
            # Update or insert system status
            cursor.execute('''
                INSERT OR REPLACE INTO system_status 
                (id, last_collection, total_threats, high_severity_count, next_collection, system_health)
                VALUES (1, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                total_threats,
                high_severity_count,
                next_collection.isoformat(),
                'healthy'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating system status: {e}")
    
    async def collect_all_data(self):
        """Collect data from all sources"""
        logger.info("🚀 Starting data collection cycle")
        start_time = time.time()
        
        try:
            await self.start_session()
            
            # Collect from all sources concurrently
            tasks = [
                self.collect_hacker_forum_data(),
                self.collect_ransomware_leak_data(),
                self.collect_paste_site_data(),
                self.collect_github_data()
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine all articles
            all_articles = []
            for result in results:
                if isinstance(result, list):
                    all_articles.extend(result)
                else:
                    logger.error(f"Collection task failed: {result}")
            
            # Store in database
            new_articles = await self.store_threats(all_articles)
            
            # Update system status
            await self.update_system_status()
            
            total_duration = time.time() - start_time
            logger.info(f"✅ Collection cycle completed in {total_duration:.2f}s")
            logger.info(f"📊 Total articles: {len(all_articles)}, New articles: {new_articles}")
            
        except Exception as e:
            logger.error(f"❌ Collection cycle failed: {e}")
        finally:
            await self.close_session()
    
    async def run_collection_loop(self):
        """Main collection loop"""
        logger.info("🔄 Starting threat data collection service")
        logger.info(f"⏰ Collection interval: {self.collection_interval} seconds")
        
        # Run initial collection immediately
        logger.info("🚀 Running initial data collection...")
        await self.collect_all_data()
        
        while self.running:
            try:
                # Wait for next collection cycle
                await asyncio.sleep(self.collection_interval)
                
                # Run collection
                await self.collect_all_data()
                
            except asyncio.CancelledError:
                logger.info("🛑 Collection service cancelled")
                break
            except Exception as e:
                logger.error(f"❌ Collection loop error: {e}")
                await asyncio.sleep(30)  # Wait 30 seconds on error
    
    def stop(self):
        """Stop the collection service"""
        logger.info("🛑 Stopping collection service...")
        self.running = False

async def main():
    """Main function"""
    collector = ThreatDataCollector()
    
    # Handle shutdown signals
    def signal_handler(signum, frame):
        collector.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await collector.run_collection_loop()
    except KeyboardInterrupt:
        logger.info("🛑 Received interrupt signal")
    finally:
        collector.stop()
        logger.info("✅ Collection service stopped")

if __name__ == "__main__":
    asyncio.run(main())
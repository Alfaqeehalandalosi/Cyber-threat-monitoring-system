"""
Hacker-Grade Threat Intelligence Sources Configuration
Comprehensive source list for advanced threat monitoring (Educational purposes only)
"""

HACKER_SOURCES_CONFIG = {
    "hacker_forums": {
        "enabled": True,
        "scraping_interval": 1800,  # 30 minutes
        "sources": [
            {
                "id": "exploit_in",
                "name": "Exploit.in",
                "url": "https://exploit.in/index.php",
                "type": "forum",
                "description": "Russian hacking forum",
                "trust_level": 0.7,
                "tags": ["exploit", "vulnerability", "russian"],
                "selectors": {
                    "threads": "//div[contains(@class, 'thread')]",
                    "title": "//h3[@class='thread-title']/a/text()",
                    "link": "//h3[@class='thread-title']/a/@href",
                    "content": "//div[@class='post-content']/text()",
                    "date": "//span[@class='post-date']/text()"
                }
            },
            {
                "id": "xss_is",
                "name": "XSS.is",
                "url": "https://xss.is/index.php",
                "type": "forum",
                "description": "Cross-site scripting forum",
                "trust_level": 0.6,
                "tags": ["xss", "web_security", "exploit"],
                "selectors": {
                    "threads": "//div[contains(@class, 'topic')]",
                    "title": "//h2[@class='topic-title']/a/text()",
                    "link": "//h2[@class='topic-title']/a/@href",
                    "content": "//div[@class='message-content']/text()",
                    "date": "//span[@class='message-date']/text()"
                }
            },
            {
                "id": "breachforums",
                "name": "BreachForums",
                "url": "https://breachforums.st/index.php",
                "type": "forum",
                "description": "Data breach discussion forum",
                "trust_level": 0.8,
                "tags": ["data_breach", "leak", "credentials"],
                "selectors": {
                    "threads": "//div[contains(@class, 'thread')]",
                    "title": "//h3[@class='thread-title']/a/text()",
                    "link": "//h3[@class='thread-title']/a/@href",
                    "content": "//div[@class='post-content']/text()",
                    "date": "//span[@class='post-date']/text()"
                }
            },
            {
                "id": "0day_today",
                "name": "0day.today",
                "url": "https://0day.today/exploit",
                "type": "exploit_db",
                "description": "Zero-day exploit database",
                "trust_level": 0.9,
                "tags": ["0day", "exploit", "vulnerability"],
                "selectors": {
                    "exploits": "//div[@class='exploit-item']",
                    "title": "//h3[@class='exploit-title']/a/text()",
                    "link": "//h3[@class='exploit-title']/a/@href",
                    "content": "//div[@class='exploit-description']/text()",
                    "date": "//span[@class='exploit-date']/text()"
                }
            },
            {
                "id": "nulled_to",
                "name": "Nulled.to",
                "url": "https://www.nulled.to/forum/10-security-and-hacking/",
                "type": "forum",
                "description": "Security and hacking forum",
                "trust_level": 0.6,
                "tags": ["hacking", "security", "tools"],
                "selectors": {
                    "threads": "//div[contains(@class, 'thread')]",
                    "title": "//h3[@class='thread-title']/a/text()",
                    "link": "//h3[@class='thread-title']/a/@href",
                    "content": "//div[@class='post-content']/text()",
                    "date": "//span[@class='post-date']/text()"
                }
            },
            {
                "id": "hackforums",
                "name": "HackForums",
                "url": "https://hackforums.net/forumdisplay.php?fid=45",
                "type": "forum",
                "description": "Hacking tutorials and discussions",
                "trust_level": 0.5,
                "tags": ["hacking", "tutorials", "security"],
                "selectors": {
                    "threads": "//div[contains(@class, 'thread')]",
                    "title": "//h3[@class='thread-title']/a/text()",
                    "link": "//h3[@class='thread-title']/a/@href",
                    "content": "//div[@class='post-content']/text()",
                    "date": "//span[@class='post-date']/text()"
                }
            },
            {
                "id": "cracked_to",
                "name": "Cracked.to",
                "url": "https://cracked.to/Forum-Hacking-Tutorials",
                "type": "forum",
                "description": "Hacking tutorials forum",
                "trust_level": 0.5,
                "tags": ["hacking", "tutorials", "cracking"],
                "selectors": {
                    "threads": "//div[contains(@class, 'thread')]",
                    "title": "//h3[@class='thread-title']/a/text()",
                    "link": "//h3[@class='thread-title']/a/@href",
                    "content": "//div[@class='post-content']/text()",
                    "date": "//span[@class='post-date']/text()"
                }
            },
            {
                "id": "sinister_ly",
                "name": "Sinister.ly",
                "url": "https://sinister.ly/Forum-Hacking-Tutorials",
                "type": "forum",
                "description": "Hacking tutorials and discussions",
                "trust_level": 0.5,
                "tags": ["hacking", "tutorials", "security"],
                "selectors": {
                    "threads": "//div[contains(@class, 'thread')]",
                    "title": "//h3[@class='thread-title']/a/text()",
                    "link": "//h3[@class='thread-title']/a/@href",
                    "content": "//div[@class='post-content']/text()",
                    "date": "//span[@class='post-date']/text()"
                }
            },
            {
                "id": "leakbase",
                "name": "LeakBase",
                "url": "https://leakbase.pw/",
                "type": "leak_site",
                "description": "Data leak repository",
                "trust_level": 0.8,
                "tags": ["data_breach", "leak", "credentials"],
                "selectors": {
                    "leaks": "//div[@class='leak-item']",
                    "title": "//h3[@class='leak-title']/a/text()",
                    "link": "//h3[@class='leak-title']/a/@href",
                    "content": "//div[@class='leak-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "blackhatworld",
                "name": "BlackHatWorld",
                "url": "https://www.blackhatworld.com/forums/white-hat-seo.58/",
                "type": "forum",
                "description": "White hat SEO and security",
                "trust_level": 0.6,
                "tags": ["white_hat", "seo", "security"],
                "selectors": {
                    "threads": "//div[contains(@class, 'thread')]",
                    "title": "//h3[@class='thread-title']/a/text()",
                    "link": "//h3[@class='thread-title']/a/@href",
                    "content": "//div[@class='post-content']/text()",
                    "date": "//span[@class='post-date']/text()"
                }
            }
        ]
    },
    
    "ransomware_leak_sites": {
        "enabled": True,
        "scraping_interval": 3600,  # 1 hour
        "sources": [
            {
                "id": "lockbit_leaks",
                "name": "LockBit Leaks",
                "url": "https://lockbitfiles.com/",
                "type": "ransomware_leak",
                "description": "LockBit ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "lockbit", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "blackcat_leaks",
                "name": "BlackCat Leaks",
                "url": "https://blackcatleaks.com/",
                "type": "ransomware_leak",
                "description": "BlackCat ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "blackcat", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "blackbasta_leaks",
                "name": "BlackBasta Leaks",
                "url": "https://blackbasta.net/",
                "type": "ransomware_leak",
                "description": "BlackBasta ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "blackbasta", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "medusa_leaks",
                "name": "Medusa Leaks",
                "url": "https://medusaleaks.com/",
                "type": "ransomware_leak",
                "description": "Medusa ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "medusa", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "play_leaks",
                "name": "Play Leaks",
                "url": "https://playleaks.com/",
                "type": "ransomware_leak",
                "description": "Play ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "play", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "bianlian_leaks",
                "name": "BianLian Leaks",
                "url": "https://bianliannews.com/",
                "type": "ransomware_leak",
                "description": "BianLian ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "bianlian", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "royal_leaks",
                "name": "Royal Leaks",
                "url": "https://royalleaks.com/",
                "type": "ransomware_leak",
                "description": "Royal ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "royal", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "snatch_leaks",
                "name": "Snatch Leaks",
                "url": "https://snatchleaks.com/",
                "type": "ransomware_leak",
                "description": "Snatch ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "snatch", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "cuba_leaks",
                "name": "Cuba Leaks",
                "url": "https://cubaleaks.com/",
                "type": "ransomware_leak",
                "description": "Cuba ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "cuba", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            },
            {
                "id": "vicesociety_leaks",
                "name": "Vice Society Leaks",
                "url": "https://vicesocietyleaks.com/",
                "type": "ransomware_leak",
                "description": "Vice Society ransomware leak site",
                "trust_level": 0.9,
                "tags": ["ransomware", "vice_society", "data_breach"],
                "selectors": {
                    "victims": "//div[@class='victim-item']",
                    "title": "//h3[@class='victim-name']/text()",
                    "link": "//a[@class='victim-link']/@href",
                    "content": "//div[@class='victim-description']/text()",
                    "date": "//span[@class='leak-date']/text()"
                }
            }
        ]
    },
    
    "paste_sites": {
        "enabled": True,
        "scraping_interval": 900,  # 15 minutes
        "sources": [
            {
                "id": "pastebin",
                "name": "Pastebin",
                "url": "https://pastebin.com/archive",
                "type": "paste_site",
                "description": "Public paste repository",
                "trust_level": 0.4,
                "tags": ["paste", "dump", "public"],
                "selectors": {
                    "pastes": "//div[@class='archive-entry']",
                    "title": "//a[@class='archive-title']/text()",
                    "link": "//a[@class='archive-title']/@href",
                    "content": "//div[@class='archive-content']/text()",
                    "date": "//span[@class='archive-date']/text()"
                }
            },
            {
                "id": "ghostbin",
                "name": "Ghostbin",
                "url": "https://ghostbin.com/pastes",
                "type": "paste_site",
                "description": "Anonymous paste service",
                "trust_level": 0.4,
                "tags": ["paste", "anonymous", "dump"],
                "selectors": {
                    "pastes": "//div[@class='paste-item']",
                    "title": "//a[@class='paste-title']/text()",
                    "link": "//a[@class='paste-title']/@href",
                    "content": "//div[@class='paste-content']/text()",
                    "date": "//span[@class='paste-date']/text()"
                }
            },
            {
                "id": "paste_ee",
                "name": "Paste.ee",
                "url": "https://paste.ee/latest",
                "type": "paste_site",
                "description": "Simple paste service",
                "trust_level": 0.4,
                "tags": ["paste", "simple", "dump"],
                "selectors": {
                    "pastes": "//div[@class='paste-entry']",
                    "title": "//a[@class='paste-title']/text()",
                    "link": "//a[@class='paste-title']/@href",
                    "content": "//div[@class='paste-content']/text()",
                    "date": "//span[@class='paste-date']/text()"
                }
            },
            {
                "id": "justpaste_it",
                "name": "JustPaste.it",
                "url": "https://justpaste.it/en/latest",
                "type": "paste_site",
                "description": "Rich text paste service",
                "trust_level": 0.4,
                "tags": ["paste", "rich_text", "dump"],
                "selectors": {
                    "pastes": "//div[@class='paste-item']",
                    "title": "//a[@class='paste-title']/text()",
                    "link": "//a[@class='paste-title']/@href",
                    "content": "//div[@class='paste-content']/text()",
                    "date": "//span[@class='paste-date']/text()"
                }
            },
            {
                "id": "hastebin",
                "name": "Hastebin",
                "url": "https://hastebin.com/",
                "type": "paste_site",
                "description": "Fast paste service",
                "trust_level": 0.4,
                "tags": ["paste", "fast", "dump"],
                "selectors": {
                    "pastes": "//div[@class='paste-entry']",
                    "title": "//a[@class='paste-title']/text()",
                    "link": "//a[@class='paste-title']/@href",
                    "content": "//div[@class='paste-content']/text()",
                    "date": "//span[@class='paste-date']/text()"
                }
            },
            {
                "id": "rentry",
                "name": "Rentry.co",
                "url": "https://rentry.co/",
                "type": "paste_site",
                "description": "Simple markdown paste service",
                "trust_level": 0.4,
                "tags": ["paste", "markdown", "dump"],
                "selectors": {
                    "pastes": "//div[@class='entry-item']",
                    "title": "//a[@class='entry-title']/text()",
                    "link": "//a[@class='entry-title']/@href",
                    "content": "//div[@class='entry-content']/text()",
                    "date": "//span[@class='entry-date']/text()"
                }
            },
            {
                "id": "dumpz",
                "name": "Dumpz.org",
                "url": "https://dumpz.org/en/latest/",
                "type": "paste_site",
                "description": "Code dump service",
                "trust_level": 0.4,
                "tags": ["paste", "code", "dump"],
                "selectors": {
                    "pastes": "//div[@class='dump-item']",
                    "title": "//a[@class='dump-title']/text()",
                    "link": "//a[@class='dump-title']/@href",
                    "content": "//div[@class='dump-content']/text()",
                    "date": "//span[@class='dump-date']/text()"
                }
            },
            {
                "id": "paste_org_ru",
                "name": "Paste.org.ru",
                "url": "https://paste.org.ru/",
                "type": "paste_site",
                "description": "Russian paste service",
                "trust_level": 0.4,
                "tags": ["paste", "russian", "dump"],
                "selectors": {
                    "pastes": "//div[@class='paste-item']",
                    "title": "//a[@class='paste-title']/text()",
                    "link": "//a[@class='paste-title']/@href",
                    "content": "//div[@class='paste-content']/text()",
                    "date": "//span[@class='paste-date']/text()"
                }
            },
            {
                "id": "paste2_org",
                "name": "Paste2.org",
                "url": "https://paste2.org/",
                "type": "paste_site",
                "description": "Simple paste service",
                "trust_level": 0.4,
                "tags": ["paste", "simple", "dump"],
                "selectors": {
                    "pastes": "//div[@class='paste-entry']",
                    "title": "//a[@class='paste-title']/text()",
                    "link": "//a[@class='paste-title']/@href",
                    "content": "//div[@class='paste-content']/text()",
                    "date": "//span[@class='paste-date']/text()"
                }
            },
            {
                "id": "ideone",
                "name": "Ideone",
                "url": "https://ideone.com/recent",
                "type": "paste_site",
                "description": "Online IDE and code sharing",
                "trust_level": 0.4,
                "tags": ["paste", "code", "ide"],
                "selectors": {
                    "pastes": "//div[@class='code-item']",
                    "title": "//a[@class='code-title']/text()",
                    "link": "//a[@class='code-title']/@href",
                    "content": "//div[@class='code-content']/text()",
                    "date": "//span[@class='code-date']/text()"
                }
            }
        ]
    },
    
    "github_monitoring": {
        "enabled": True,
        "scraping_interval": 3600,  # 1 hour
        "api_endpoint": "https://api.github.com/search/repositories",
        "queries": [
            {
                "id": "exploit_python",
                "query": "exploit language:Python",
                "description": "Python exploit repositories",
                "trust_level": 0.7,
                "tags": ["exploit", "python", "github"]
            },
            {
                "id": "poc_cve",
                "query": "PoC CVE",
                "description": "Proof of Concept CVE exploits",
                "trust_level": 0.8,
                "tags": ["poc", "cve", "exploit"]
            },
            {
                "id": "cve_2025",
                "query": "CVE-2025",
                "description": "2025 CVE vulnerabilities",
                "trust_level": 0.9,
                "tags": ["cve", "2025", "vulnerability"]
            },
            {
                "id": "0day_exploit",
                "query": "0day exploit",
                "description": "Zero-day exploits",
                "trust_level": 0.9,
                "tags": ["0day", "exploit", "zero_day"]
            },
            {
                "id": "privilege_escalation",
                "query": "privilege escalation",
                "description": "Privilege escalation exploits",
                "trust_level": 0.7,
                "tags": ["privilege_escalation", "exploit"]
            },
            {
                "id": "rce_exploit",
                "query": "rce exploit",
                "description": "Remote Code Execution exploits",
                "trust_level": 0.8,
                "tags": ["rce", "exploit", "remote_code_execution"]
            },
            {
                "id": "sql_injection_exploit",
                "query": "sql injection exploit",
                "description": "SQL injection exploits",
                "trust_level": 0.7,
                "tags": ["sql_injection", "exploit", "web_security"]
            },
            {
                "id": "xss_exploit",
                "query": "xss exploit",
                "description": "Cross-site scripting exploits",
                "trust_level": 0.7,
                "tags": ["xss", "exploit", "web_security"]
            },
            {
                "id": "csrf_exploit",
                "query": "csrf exploit",
                "description": "CSRF exploits",
                "trust_level": 0.7,
                "tags": ["csrf", "exploit", "web_security"]
            },
            {
                "id": "buffer_overflow_exploit",
                "query": "buffer overflow exploit",
                "description": "Buffer overflow exploits",
                "trust_level": 0.8,
                "tags": ["buffer_overflow", "exploit", "memory_corruption"]
            }
        ]
    }
}

# Threat keywords for enhanced detection
THREAT_KEYWORDS = {
    "zero_day": [
        "zero-day", "0day", "zero day", "unpatched", "no patch", "exploit available",
        "proof of concept", "PoC", "working exploit", "exploit code", "new vulnerability",
        "undisclosed", "unreported", "fresh exploit"
    ],
    "critical_vulnerability": [
        "critical", "severe", "high severity", "remote code execution", "RCE",
        "privilege escalation", "authentication bypass", "SQL injection", "XSS",
        "CSRF", "buffer overflow", "memory corruption", "use after free",
        "double free", "format string", "integer overflow"
    ],
    "data_breach": [
        "data breach", "leak", "stolen", "compromised", "exposed", "dumped",
        "credentials", "passwords", "personal data", "PII", "credit cards",
        "social security", "email addresses", "phone numbers", "addresses"
    ],
    "malware": [
        "malware", "ransomware", "trojan", "virus", "worm", "backdoor",
        "keylogger", "spyware", "rootkit", "botnet", "DDoS", "crypto miner",
        "stealer", "loader", "dropper"
    ],
    "exploit": [
        "exploit", "exploitation", "vulnerability", "CVE", "security flaw",
        "bug", "weakness", "attack vector", "payload", "shellcode",
        "metasploit", "exploit kit", "weaponized"
    ],
    "tools": [
        "hacking tool", "penetration testing", "pentest", "security scanner",
        "vulnerability scanner", "exploit framework", "malware builder",
        "keylogger", "password cracker", "network scanner"
    ]
}

# Trust level scoring
TRUST_LEVELS = {
    "ransomware_leak": 0.9,
    "exploit_db": 0.8,
    "data_breach": 0.8,
    "forum": 0.5,
    "paste_site": 0.4,
    "github": 0.7,
    "news": 0.6,
    "research": 0.8,
    "government": 0.9
}

# Severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 0.9,
    "high": 0.7,
    "medium": 0.5,
    "low": 0.3
}
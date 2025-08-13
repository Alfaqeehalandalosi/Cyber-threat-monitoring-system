#!/usr/bin/env python3
"""
Database Population Script
Populate the database with initial threat data for immediate dashboard functionality
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
import hashlib

def generate_hash_id(title: str, source: str, published: str) -> str:
    """Generate unique hash for threat article"""
    content = f"{title}:{source}:{published}"
    return hashlib.md5(content.encode()).hexdigest()

def populate_database():
    """Populate database with initial threat data"""
    
    # Ensure directory exists
    os.makedirs('ctms/data', exist_ok=True)
    
    db_path = "ctms/data/threat_intelligence.db"
    
    # Sample threat data
    sample_threats = [
        {
            'title': 'Critical Zero-Day Exploit for Windows Systems',
            'content': 'A critical zero-day vulnerability has been discovered that allows remote code execution on Windows systems. This vulnerability affects Windows 10 and 11 systems.',
            'threat_score': 0.95,
            'threat_type': 'zero_day',
            'source': 'Hacker Forum',
            'source_type': 'hacker_forum',
            'published': (datetime.now() - timedelta(hours=2)).isoformat(),
            'indicators': {
                'cve_ids': ['CVE-2024-XXXX'],
                'ip_addresses': ['192.168.1.1'],
                'domains': ['malicious.example.com']
            }
        },
        {
            'title': 'New Ransomware Leak: Company Data Exposed',
            'content': 'Ransomware group has leaked sensitive company data including customer information and internal documents.',
            'threat_score': 0.88,
            'threat_type': 'data_breach',
            'source': 'Ransomware Leak Site',
            'source_type': 'ransomware_leak',
            'published': (datetime.now() - timedelta(hours=4)).isoformat(),
            'indicators': {
                'domains': ['leak.example.com'],
                'hashes': ['a1b2c3d4e5f6...']
            }
        },
        {
            'title': 'GitHub: CVE-2024-1234 Exploit PoC',
            'content': 'Proof of concept exploit for CVE-2024-1234 now available on GitHub. This exploit targets web applications.',
            'threat_score': 0.82,
            'threat_type': 'exploit',
            'source': 'GitHub',
            'source_type': 'github',
            'published': (datetime.now() - timedelta(hours=6)).isoformat(),
            'indicators': {
                'cve_ids': ['CVE-2024-1234'],
                'github_repos': ['github.com/exploit/CVE-2024-1234']
            }
        },
        {
            'title': 'Paste Site: Credential Dump Analysis',
            'content': 'Large credential dump found on paste site with millions of compromised accounts from various services.',
            'threat_score': 0.75,
            'threat_type': 'data_breach',
            'source': 'Paste Site',
            'source_type': 'paste_site',
            'published': (datetime.now() - timedelta(hours=8)).isoformat(),
            'indicators': {
                'email_addresses': ['user@example.com'],
                'domains': ['paste.example.com']
            }
        },
        {
            'title': 'New Malware Variant Targeting Healthcare',
            'content': 'New malware variant discovered targeting healthcare systems with sophisticated evasion techniques.',
            'threat_score': 0.87,
            'threat_type': 'malware',
            'source': 'Hacker Forum',
            'source_type': 'hacker_forum',
            'published': (datetime.now() - timedelta(hours=10)).isoformat(),
            'indicators': {
                'hashes': ['malware_hash_123...'],
                'domains': ['malware.example.com']
            }
        },
        {
            'title': 'SQL Injection Exploit for E-commerce Platforms',
            'content': 'New SQL injection exploit discovered affecting popular e-commerce platforms.',
            'threat_score': 0.78,
            'threat_type': 'exploit',
            'source': 'GitHub',
            'source_type': 'github',
            'published': (datetime.now() - timedelta(hours=12)).isoformat(),
            'indicators': {
                'github_repos': ['github.com/sql-injection-exploit']
            }
        },
        {
            'title': 'Phishing Campaign Targeting Financial Services',
            'content': 'Sophisticated phishing campaign targeting major financial services with realistic spoofing.',
            'threat_score': 0.73,
            'threat_type': 'phishing',
            'source': 'Hacker Forum',
            'source_type': 'hacker_forum',
            'published': (datetime.now() - timedelta(hours=14)).isoformat(),
            'indicators': {
                'domains': ['phishing.example.com'],
                'email_addresses': ['phish@example.com']
            }
        },
        {
            'title': 'Privilege Escalation Vulnerability in Linux',
            'content': 'New privilege escalation vulnerability discovered in Linux kernel affecting multiple distributions.',
            'threat_score': 0.85,
            'threat_type': 'exploit',
            'source': 'GitHub',
            'source_type': 'github',
            'published': (datetime.now() - timedelta(hours=16)).isoformat(),
            'indicators': {
                'cve_ids': ['CVE-2024-5678'],
                'github_repos': ['github.com/linux-priv-esc']
            }
        }
    ]
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
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
        
        # Insert sample threats
        inserted_count = 0
        for threat in sample_threats:
            try:
                threat['hash_id'] = generate_hash_id(
                    threat['title'], 
                    threat['source'], 
                    threat['published']
                )
                
                cursor.execute('''
                    INSERT OR IGNORE INTO threats 
                    (title, content, threat_score, threat_type, source, source_type, 
                     published_at, hash_id, indicators)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat['title'],
                    threat['content'],
                    threat['threat_score'],
                    threat['threat_type'],
                    threat['source'],
                    threat['source_type'],
                    threat['published'],
                    threat['hash_id'],
                    json.dumps(threat['indicators'])
                ))
                
                if cursor.rowcount > 0:
                    inserted_count += 1
                    
            except Exception as e:
                print(f"Error inserting threat {threat['title']}: {e}")
        
        # Insert system status
        cursor.execute('''
            INSERT OR REPLACE INTO system_status 
            (id, last_collection, total_threats, high_severity_count, next_collection, system_health)
            VALUES (1, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            len(sample_threats),
            len([t for t in sample_threats if t['threat_score'] > 0.8]),
            (datetime.now() + timedelta(minutes=5)).isoformat(),
            'healthy'
        ))
        
        # Insert collection log
        cursor.execute('''
            INSERT INTO collection_log 
            (source_type, articles_collected, articles_new, duration_seconds, status)
            VALUES (?, ?, ?, ?, ?)
        ''', ('initial_population', len(sample_threats), inserted_count, 1.0, 'success'))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Database populated successfully!")
        print(f"📊 Inserted {inserted_count} new threats")
        print(f"📈 Total threats in database: {len(sample_threats)}")
        print(f"🚀 Dashboard should now work immediately!")
        
    except Exception as e:
        print(f"❌ Error populating database: {e}")

if __name__ == "__main__":
    print("🔄 Populating database with initial threat data...")
    populate_database()
    print("✅ Database population complete!")
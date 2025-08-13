#!/usr/bin/env python3
"""
Check Content Script
Check the actual content being stored to see why indicators aren't being extracted
"""

import sqlite3
import json
import re

def check_content():
    """Check content in the database"""
    
    db_path = "ctms/data/threat_intelligence.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 Checking content in database...")
        print("=" * 50)
        
        # Get threats with their content
        cursor.execute("SELECT title, content, source_type FROM threats LIMIT 5")
        threats = cursor.fetchall()
        
        for title, content, source_type in threats:
            print(f"\n📰 Threat: {title}")
            print(f"   📋 Source Type: {source_type}")
            print(f"   📄 Content: {content[:200]}...")
            
            # Test indicator extraction on this content
            indicators = extract_indicators_test(content)
            print(f"   🔍 Extracted Indicators: {indicators}")
            
            # Check for specific patterns
            cve_matches = re.findall(r'CVE-\d{4}-\d+', content, re.IGNORECASE)
            company_matches = re.findall(r'\b[A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company|Corporation)\b', content)
            github_matches = re.findall(r'github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+', content)
            
            print(f"   🎯 CVE matches: {cve_matches}")
            print(f"   🏢 Company matches: {company_matches}")
            print(f"   📦 GitHub matches: {github_matches}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking content: {e}")

def extract_indicators_test(content: str) -> dict:
    """Test indicator extraction on content"""
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
        r'\b[A-Z]{2,}(?:[A-Z][a-z]+)* (?:Inc|Corp|LLC|Ltd|Company|Corporation)\b'
    ]
    for pattern in company_patterns:
        companies = re.findall(pattern, content)
        indicators['company_names'].extend(companies)
    indicators['company_names'] = list(set(indicators['company_names']))
    
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

if __name__ == "__main__":
    check_content()
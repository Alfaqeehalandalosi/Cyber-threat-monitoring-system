#!/usr/bin/env python3
"""
Check Full Content Script
Check the full content length and see what's actually being stored
"""

import sqlite3
import json
import re

def check_full_content():
    """Check full content in the database"""
    
    db_path = "ctms/data/threat_intelligence.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 Checking full content in database...")
        print("=" * 50)
        
        # Get threats with their full content
        cursor.execute("SELECT title, content, source_type, LENGTH(content) as content_length FROM threats WHERE source_type = 'mainstream_news' LIMIT 3")
        threats = cursor.fetchall()
        
        for title, content, source_type, content_length in threats:
            print(f"\n📰 Threat: {title}")
            print(f"   📋 Source Type: {source_type}")
            print(f"   📏 Content Length: {content_length} characters")
            print(f"   📄 Full Content: {content}")
            
            # Test indicator extraction on this content
            indicators = extract_indicators_test(content)
            print(f"   🔍 Extracted Indicators: {indicators}")
            
            # Check for specific patterns
            cve_matches = re.findall(r'CVE-\d{4}-\d+', content, re.IGNORECASE)
            company_matches = re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', content)
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

if __name__ == "__main__":
    check_full_content()
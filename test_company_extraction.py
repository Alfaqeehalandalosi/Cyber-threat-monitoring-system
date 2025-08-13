#!/usr/bin/env python3
"""
Test Company Extraction Script
Test company name extraction on specific content
"""

import re

def test_company_extraction():
    """Test company name extraction"""
    
    # Test content with company names
    test_content = "Hackers leak Allianz Life data stolen in Salesforce attacks. Fortinet SSL VPNs Hit by Global Brute-Force Wave Before Attackers Shift to FortiManager. Microsoft Corp and Google Inc are also affected."
    
    print("🔍 Testing Company Name Extraction...")
    print("=" * 50)
    print(f"📄 Test Content: {test_content}")
    print()
    
    # Company name patterns
    company_patterns = [
        r'\b[A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company|Corporation|Technologies|Systems|Security)\b',
        r'\b[A-Z][a-z]+ [A-Z][a-z]+ (?:Inc|Corp|LLC|Ltd|Company|Corporation)\b',
        r'\b[A-Z]{2,}(?:[A-Z][a-z]+)* (?:Inc|Corp|LLC|Ltd|Company|Corporation)\b',
        r'\b[A-Z][a-z]+ [A-Z][a-z]+\b',  # Two-word company names like "Allianz Life"
        r'\b[A-Z][a-z]+(?:[A-Z][a-z]+)*\b'  # CamelCase company names like "Fortinet"
    ]
    
    all_companies = []
    
    for i, pattern in enumerate(company_patterns):
        matches = re.findall(pattern, test_content)
        print(f"Pattern {i+1}: {pattern}")
        print(f"   Matches: {matches}")
        all_companies.extend(matches)
        print()
    
    # Remove duplicates
    unique_companies = list(set(all_companies))
    print(f"🎯 All unique companies found: {unique_companies}")
    
    # Test specific company names
    specific_companies = ["Allianz Life", "Fortinet", "Microsoft Corp", "Google Inc", "Salesforce"]
    print(f"\n🔍 Testing specific companies:")
    for company in specific_companies:
        if company in test_content:
            print(f"   ✅ '{company}' found in content")
        else:
            print(f"   ❌ '{company}' NOT found in content")

if __name__ == "__main__":
    test_company_extraction()
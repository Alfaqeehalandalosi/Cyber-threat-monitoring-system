#!/usr/bin/env python3
"""
Test Indicator Extraction Script
Tests the indicator extraction functionality of the Hacker-Grade Threat Intelligence System
"""

import requests
import json
import time

def test_indicator_extraction():
    """Test indicator extraction functionality"""
    
    # API configuration
    api_url = "http://localhost:8000"
    headers = {
        "Authorization": "Bearer demo_token_for_development_12345",
        "Content-Type": "application/json"
    }
    
    print("🔍 Testing Indicator Extraction...")
    print("=" * 50)
    
    # Test 1: Check API health
    print("1. Checking API health...")
    try:
        response = requests.get(f"{api_url}/api/v1/hacker-grade/health", headers=headers, timeout=10)
        if response.status_code == 200:
            print("✅ API is healthy")
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ API health check error: {e}")
        return
    
    # Test 2: Force data collection to get fresh data with indicators
    print("\n2. Forcing data collection...")
    try:
        response = requests.post(f"{api_url}/api/v1/hacker-grade/clear-cache", headers=headers, timeout=10)
        if response.status_code == 200:
            print("✅ Cache cleared, forcing fresh data collection")
        else:
            print(f"❌ Cache clear failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Cache clear error: {e}")
    
    # Test 3: Get indicators
    print("\n3. Testing indicator extraction...")
    try:
        response = requests.get(f"{api_url}/api/v1/hacker-grade/threats/indicators", headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Indicators extracted successfully")
            print(f"📊 Total indicators found: {result.get('total_indicators', 0)}")
            
            # Show indicator breakdown
            indicators = result.get('indicators', {})
            for indicator_type, values in indicators.items():
                count = len(values)
                if count > 0:
                    print(f"   • {indicator_type}: {count} found")
                    if count <= 3:  # Show first few examples
                        for val in values[:3]:
                            print(f"     - {val}")
                else:
                    print(f"   • {indicator_type}: None found")
            
            if result.get('total_indicators', 0) == 0:
                print("\n⚠️  No indicators found. This could mean:")
                print("   - No threats have been collected yet")
                print("   - Threats don't contain extractable indicators")
                print("   - Data collection needs to run first")
                
        else:
            print(f"❌ Indicator extraction failed: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Indicator extraction error: {e}")
    
    # Test 4: Get threat summary to see if data exists
    print("\n4. Checking threat data...")
    try:
        response = requests.get(f"{api_url}/api/v1/hacker-grade/threats/summary", headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            total_articles = result.get('total_articles', 0)
            print(f"📰 Total articles in database: {total_articles}")
            
            if total_articles == 0:
                print("\n💡 To get indicators, you need to:")
                print("   1. Run data collection: python force_collect_data.py")
                print("   2. Wait for collection to complete")
                print("   3. Check indicators again")
            else:
                print("✅ Threat data exists - indicators should be extracted")
                
        else:
            print(f"❌ Threat summary failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Threat summary error: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Indicator Extraction Testing Complete!")
    print("\n📝 Next steps:")
    print("1. If no indicators found, run: python force_collect_data.py")
    print("2. Wait for collection to complete")
    print("3. Run this test again to see extracted indicators")

if __name__ == "__main__":
    test_indicator_extraction()
#!/usr/bin/env python3
"""
Test script to verify cache clearing and force refresh functionality
"""

import requests
import json
import time

API_BASE_URL = "http://localhost:8000"
API_TOKEN = "demo_token_for_development_12345"

def make_request(endpoint, force_refresh=False):
    """Make API request"""
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{API_BASE_URL}{endpoint}"
    if force_refresh:
        url += "?force_refresh=true"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None

def clear_cache():
    """Clear the cache"""
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{API_BASE_URL}/api/v1/real/clear-cache"
    try:
        response = requests.post(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error clearing cache: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Cache clear failed: {e}")
        return None

def test_cache_functionality():
    """Test the cache functionality"""
    print("🧪 Testing Cache Functionality")
    print("=" * 50)
    
    # Test 1: Get initial data
    print("\n1. Getting initial data...")
    initial_data = make_request("/api/v1/real/threats/summary")
    if initial_data:
        print(f"✅ Initial data: {initial_data.get('total_articles', 0)} articles")
        initial_time = initial_data.get('collection_time', '')
        print(f"   Collection time: {initial_time}")
    else:
        print("❌ Failed to get initial data")
        return
    
    # Test 2: Get data again (should be cached)
    print("\n2. Getting data again (should be cached)...")
    cached_data = make_request("/api/v1/real/threats/summary")
    if cached_data:
        print(f"✅ Cached data: {cached_data.get('total_articles', 0)} articles")
        cached_time = cached_data.get('collection_time', '')
        print(f"   Collection time: {cached_time}")
        
        # Check if it's the same data
        if initial_time == cached_time:
            print("   ✅ Data is cached (same timestamp)")
        else:
            print("   ❌ Data is not cached (different timestamp)")
    else:
        print("❌ Failed to get cached data")
        return
    
    # Test 3: Clear cache
    print("\n3. Clearing cache...")
    clear_result = clear_cache()
    if clear_result:
        print("✅ Cache cleared successfully")
    else:
        print("❌ Failed to clear cache")
        return
    
    # Test 4: Get data after cache clear (should be fresh)
    print("\n4. Getting data after cache clear (should be fresh)...")
    fresh_data = make_request("/api/v1/real/threats/summary")
    if fresh_data:
        print(f"✅ Fresh data: {fresh_data.get('total_articles', 0)} articles")
        fresh_time = fresh_data.get('collection_time', '')
        print(f"   Collection time: {fresh_time}")
        
        # Check if it's different data
        if fresh_time != cached_time:
            print("   ✅ Data is fresh (different timestamp)")
        else:
            print("   ⚠️ Data might still be cached (same timestamp)")
    else:
        print("❌ Failed to get fresh data")
        return
    
    # Test 5: Force refresh
    print("\n5. Testing force refresh...")
    force_data = make_request("/api/v1/real/threats/summary", force_refresh=True)
    if force_data:
        print(f"✅ Force refresh data: {force_data.get('total_articles', 0)} articles")
        force_time = force_data.get('collection_time', '')
        print(f"   Collection time: {force_time}")
        
        # Check if it's different data
        if force_time != fresh_time:
            print("   ✅ Force refresh worked (different timestamp)")
        else:
            print("   ⚠️ Force refresh might not have worked (same timestamp)")
    else:
        print("❌ Failed to get force refresh data")
        return
    
    print("\n" + "=" * 50)
    print("🎉 Cache functionality test completed!")

if __name__ == "__main__":
    test_cache_functionality()
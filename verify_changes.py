#!/usr/bin/env python3
"""
Simple verification script to check if the changes were applied correctly
"""

import os
import re

def check_file_changes():
    """Check if the changes were applied correctly"""
    print("🔍 Verifying Changes Applied")
    print("=" * 50)
    
    # Check API endpoints file
    print("\n1. Checking API endpoints file...")
    api_file = "ctms/api/real_data_endpoints.py"
    
    if os.path.exists(api_file):
        with open(api_file, 'r') as f:
            content = f.read()
        
        # Check cache duration
        if "CACHE_DURATION = 300" in content:
            print("✅ Cache duration reduced to 5 minutes")
        else:
            print("❌ Cache duration not updated")
        
        # Check force refresh parameter
        if "force_refresh: bool = False" in content:
            print("✅ Force refresh parameter added")
        else:
            print("❌ Force refresh parameter not found")
        
        # Check clear cache endpoint
        if "@router.post(\"/clear-cache\")" in content:
            print("✅ Clear cache endpoint added")
        else:
            print("❌ Clear cache endpoint not found")
    else:
        print("❌ API endpoints file not found")
    
    # Check dashboard file
    print("\n2. Checking dashboard file...")
    dashboard_file = "dashboard.py"
    
    if os.path.exists(dashboard_file):
        with open(dashboard_file, 'r') as f:
            content = f.read()
        
        # Check force refresh in make_api_request
        if "force_refresh: bool = False" in content:
            print("✅ Force refresh parameter added to make_api_request")
        else:
            print("❌ Force refresh parameter not found in make_api_request")
        
        # Check cache status indicator
        if "🔄 Fresh Data" in content and "💾 Cached Data" in content:
            print("✅ Cache status indicator added")
        else:
            print("❌ Cache status indicator not found")
        
        # Check clear cache button
        if "🗑️ Clear Cache" in content:
            print("✅ Clear cache button added")
        else:
            print("❌ Clear cache button not found")
    else:
        print("❌ Dashboard file not found")
    
    # Check test script
    print("\n3. Checking test script...")
    test_file = "test_cache_fix.py"
    
    if os.path.exists(test_file):
        print("✅ Test script created")
    else:
        print("❌ Test script not found")
    
    # Check documentation
    print("\n4. Checking documentation...")
    doc_file = "CACHE_FIX_SUMMARY.md"
    
    if os.path.exists(doc_file):
        print("✅ Documentation created")
    else:
        print("❌ Documentation not found")
    
    print("\n" + "=" * 50)
    print("🎉 Verification completed!")

if __name__ == "__main__":
    check_file_changes()

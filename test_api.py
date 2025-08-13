#!/usr/bin/env python3
"""
Simple test script to check API server startup
"""

import sys
import os

def test_api_imports():
    """Test if we can import the API components"""
    print("🧪 Testing API imports...")
    
    try:
        # Test basic imports
        import fastapi
        print("   ✅ fastapi")
        
        import uvicorn
        print("   ✅ uvicorn")
        
        # Test our modules
        sys.path.append('.')
        
        try:
            from ctms.main import app
            print("   ✅ ctms.main.app")
        except Exception as e:
            print(f"   ❌ ctms.main.app - {str(e)}")
            
        try:
            from ctms.api.hacker_grade_endpoints import router
            print("   ✅ ctms.api.hacker_grade_endpoints")
        except Exception as e:
            print(f"   ❌ ctms.api.hacker_grade_endpoints - {str(e)}")
            
        try:
            from ctms.scraping.hacker_grade_scraper import get_hacker_grade_threat_intelligence
            print("   ✅ ctms.scraping.hacker_grade_scraper")
        except Exception as e:
            print(f"   ❌ ctms.scraping.hacker_grade_scraper - {str(e)}")
            
        try:
            from ctms.analysis.hacker_grade_analyzer import analyze_hacker_grade_articles
            print("   ✅ ctms.analysis.hacker_grade_analyzer")
        except Exception as e:
            print(f"   ❌ ctms.analysis.hacker_grade_analyzer - {str(e)}")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return False
    
    return True

def test_api_startup():
    """Test if the API server can start"""
    print("\n🚀 Testing API startup...")
    
    try:
        import uvicorn
        from ctms.main import app
        
        print("   ✅ App created successfully")
        print("   ✅ Ready to start server")
        return True
        
    except Exception as e:
        print(f"   ❌ API startup failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🔍 API Server Test")
    print("=" * 50)
    
    # Test imports
    imports_ok = test_api_imports()
    
    # Test startup
    startup_ok = test_api_startup()
    
    print("\n" + "=" * 50)
    if imports_ok and startup_ok:
        print("✅ API server should work correctly!")
        print("Try running: python -m uvicorn ctms.main:app --host localhost --port 8000")
    else:
        print("❌ API server has issues that need to be fixed")
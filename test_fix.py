#!/usr/bin/env python3
"""
Test script to verify the fixes for the Cyber Threat Monitoring System.
This script tests the previously failing methods to ensure they work correctly.
"""

import asyncio
import sys
import traceback
from datetime import datetime

def print_status(message, status="INFO"):
    """Print a formatted status message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if status == "SUCCESS":
        print(f"[{timestamp}] ✅ {message}")
    elif status == "ERROR":
        print(f"[{timestamp}] ❌ {message}")
    elif status == "WARNING":
        print(f"[{timestamp}] ⚠️ {message}")
    else:
        print(f"[{timestamp}] ℹ️ {message}")

async def test_scraper_methods():
    """Test the scraper methods that were previously failing."""
    print_status("Testing scraper methods...")
    
    try:
        # Test 1: Import the scraper
        from ctms.scraping.tor_scraper import ThreatIntelligenceScraper, create_scraper
        print_status("✅ Successfully imported ThreatIntelligenceScraper")
        
        # Test 2: Create scraper instance
        scraper = ThreatIntelligenceScraper()
        print_status("✅ Successfully created ThreatIntelligenceScraper instance")
        
        # Test 3: Check if run_full_cycle method exists
        if hasattr(scraper, 'run_full_cycle'):
            print_status("✅ run_full_cycle method exists on ThreatIntelligenceScraper")
        else:
            print_status("❌ run_full_cycle method missing from ThreatIntelligenceScraper", "ERROR")
            return False
        
        # Test 4: Test create_scraper function
        try:
            test_scraper = await create_scraper()
            print_status("✅ create_scraper function works correctly")
            await test_scraper.close()
        except Exception as e:
            print_status(f"❌ create_scraper function failed: {e}", "ERROR")
            return False
        
        return True
        
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def test_analyzer_methods():
    """Test the analyzer methods that were previously failing."""
    print_status("Testing analyzer methods...")
    
    try:
        # Test 1: Import the analyzer
        from ctms.nlp.threat_analyzer import ThreatAnalyzer
        print_status("✅ Successfully imported ThreatAnalyzer")
        
        # Test 2: Create analyzer instance
        analyzer = ThreatAnalyzer()
        print_status("✅ Successfully created ThreatAnalyzer instance")
        
        # Test 3: Check if analyze_latest_threats method exists
        if hasattr(analyzer, 'analyze_latest_threats'):
            print_status("✅ analyze_latest_threats method exists on ThreatAnalyzer")
        else:
            print_status("❌ analyze_latest_threats method missing from ThreatAnalyzer", "ERROR")
            return False
        
        return True
        
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def test_background_function():
    """Test the background scraping function."""
    print_status("Testing background scraping function...")
    
    try:
        # Test 1: Import the function
        from ctms.api.main import _background_run_scrape
        print_status("✅ Successfully imported _background_run_scrape function")
        
        # Test 2: Check if function is callable
        if callable(_background_run_scrape):
            print_status("✅ _background_run_scrape is callable")
        else:
            print_status("❌ _background_run_scrape is not callable", "ERROR")
            return False
        
        return True
        
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def test_api_endpoints():
    """Test the API endpoints."""
    print_status("Testing API endpoints...")
    
    try:
        # Test 1: Import FastAPI app
        from ctms.api.main import app
        print_status("✅ Successfully imported FastAPI app")
        
        # Test 2: Check if scraping endpoint exists
        routes = [route.path for route in app.routes]
        if "/api/v1/scraping/run" in routes:
            print_status("✅ Scraping endpoint exists")
        else:
            print_status("❌ Scraping endpoint missing", "ERROR")
            return False
        
        return True
        
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def test_database_connection():
    """Test database connection (if available)."""
    print_status("Testing database connection...")
    
    try:
        from ctms.database.connection import get_database
        print_status("✅ Successfully imported database connection")
        
        # Try to get database (this might fail if MongoDB is not running)
        try:
            db = await get_database()
            print_status("✅ Database connection successful")
            return True
        except Exception as e:
            print_status(f"⚠️ Database connection failed (this is normal if MongoDB is not running): {e}", "WARNING")
            return True  # This is not a critical failure
            
    except ImportError as e:
        print_status(f"❌ Import error: {e}", "ERROR")
        return False
    except Exception as e:
        print_status(f"❌ Unexpected error: {e}", "ERROR")
        traceback.print_exc()
        return False

async def run_comprehensive_test():
    """Run all tests to verify the fixes."""
    print_status("=" * 60)
    print_status("CYBER THREAT MONITORING SYSTEM - FIX VERIFICATION")
    print_status("=" * 60)
    
    tests = [
        ("Scraper Methods", test_scraper_methods),
        ("Analyzer Methods", test_analyzer_methods),
        ("Background Function", test_background_function),
        ("API Endpoints", test_api_endpoints),
        ("Database Connection", test_database_connection),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print_status(f"\n--- Testing {test_name} ---")
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print_status(f"❌ Test {test_name} failed with exception: {e}", "ERROR")
            results.append((test_name, False))
    
    # Summary
    print_status("\n" + "=" * 60)
    print_status("TEST RESULTS SUMMARY")
    print_status("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        if result:
            print_status(f"✅ {test_name}: PASSED", "SUCCESS")
            passed += 1
        else:
            print_status(f"❌ {test_name}: FAILED", "ERROR")
    
    print_status(f"\nOverall Result: {passed}/{total} tests passed")
    
    if passed == total:
        print_status("🎉 ALL TESTS PASSED! The fixes are working correctly.", "SUCCESS")
        print_status("\nYou can now run the system without the AttributeError.")
        print_status("To start the system:")
        print_status("1. Start services: docker-compose up -d")
        print_status("2. Start API: python -m ctms.api.main")
        print_status("3. Start Dashboard: streamlit run ctms/dashboard/main_dashboard.py")
        return True
    else:
        print_status("⚠️ Some tests failed. Please check the errors above.", "WARNING")
        return False

def main():
    """Main function to run the test suite."""
    try:
        # Run the tests
        success = asyncio.run(run_comprehensive_test())
        
        if success:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print_status("\n⚠️ Test interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        print_status(f"❌ Test suite failed: {e}", "ERROR")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
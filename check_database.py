#!/usr/bin/env python3
"""
Database Check Script
Check what's in the database and debug the dashboard issue
"""

import sqlite3
import os
from datetime import datetime

def check_database():
    """Check database contents and status"""
    
    db_path = "ctms/data/threat_intelligence.db"
    
    print("🔍 Checking database status...")
    print(f"Database path: {db_path}")
    
    # Check if database exists
    if not os.path.exists(db_path):
        print("❌ Database does not exist!")
        print("This means the data collector hasn't run yet or failed to create the database.")
        return
    
    print("✅ Database exists")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"📋 Tables in database: {[table[0] for table in tables]}")
        
        # Check threats table
        if ('threats',) in tables:
            cursor.execute("SELECT COUNT(*) FROM threats")
            threat_count = cursor.fetchone()[0]
            print(f"📊 Total threats in database: {threat_count}")
            
            if threat_count > 0:
                cursor.execute("SELECT title, threat_score, threat_type, source_type FROM threats LIMIT 5")
                threats = cursor.fetchall()
                print("📋 Sample threats:")
                for threat in threats:
                    print(f"  - {threat[0]} (Score: {threat[1]}, Type: {threat[2]}, Source: {threat[3]})")
            else:
                print("⚠️ No threats found in database")
        
        # Check system status
        if ('system_status',) in tables:
            cursor.execute("SELECT * FROM system_status WHERE id = 1")
            status = cursor.fetchone()
            if status:
                print(f"📈 System Status:")
                print(f"  - Last collection: {status[1]}")
                print(f"  - Total threats: {status[2]}")
                print(f"  - High severity: {status[3]}")
                print(f"  - Next collection: {status[4]}")
                print(f"  - System health: {status[5]}")
            else:
                print("⚠️ No system status found")
        
        # Check collection logs
        if ('collection_log',) in tables:
            cursor.execute("SELECT COUNT(*) FROM collection_log")
            log_count = cursor.fetchone()[0]
            print(f"📝 Collection logs: {log_count}")
            
            if log_count > 0:
                cursor.execute("SELECT collection_time, source_type, articles_collected, status FROM collection_log ORDER BY collection_time DESC LIMIT 5")
                logs = cursor.fetchall()
                print("📋 Recent collection logs:")
                for log in logs:
                    print(f"  - {log[0]}: {log[1]} ({log[2]} articles, {log[3]})")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")

def test_api_endpoints():
    """Test API endpoints"""
    print("\n🌐 Testing API endpoints...")
    
    import requests
    
    # Test basic health
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        print(f"✅ Basic health: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Basic health failed: {e}")
    
    # Test hacker-grade health
    try:
        headers = {"Authorization": "Bearer demo_token_for_development_12345"}
        response = requests.get("http://localhost:8000/api/v1/hacker-grade/health", headers=headers, timeout=5)
        print(f"✅ Hacker-grade health: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"❌ Hacker-grade health failed: {e}")
    
    # Test threats summary
    try:
        headers = {"Authorization": "Bearer demo_token_for_development_12345"}
        response = requests.get("http://localhost:8000/api/v1/hacker-grade/threats/summary", headers=headers, timeout=5)
        print(f"✅ Threats summary: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Total threats: {data.get('total_threats', 'N/A')}")
            print(f"   High severity: {data.get('high_severity_count', 'N/A')}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"❌ Threats summary failed: {e}")

if __name__ == "__main__":
    print("🔍 Hacker-Grade Threat Intelligence System - Database Check")
    print("=" * 60)
    
    check_database()
    test_api_endpoints()
    
    print("\n" + "=" * 60)
    print("💡 Recommendations:")
    print("1. If database is empty, the data collector may not be running")
    print("2. If API endpoints fail, check if the API server is running")
    print("3. If data exists but dashboard fails, check dashboard logs")
    print("=" * 60)
#!/usr/bin/env python3
"""
Check Database Schema Script
Check the database schema and see what's actually in the database
"""

import sqlite3

def check_db_schema():
    """Check database schema and content"""
    
    db_path = "ctms/data/threat_intelligence.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 Checking database schema...")
        print("=" * 50)
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"📋 Tables in database: {[table[0] for table in tables]}")
        
        # Check threats table schema
        cursor.execute("PRAGMA table_info(threats)")
        columns = cursor.fetchall()
        print(f"\n📋 Threats table columns:")
        for col in columns:
            print(f"   • {col[1]} ({col[2]})")
        
        # Check recent threats with indicators
        cursor.execute("SELECT id, title, indicators FROM threats ORDER BY id DESC LIMIT 3")
        recent_threats = cursor.fetchall()
        
        print(f"\n📊 Recent threats with indicators:")
        for threat_id, title, indicators in recent_threats:
            print(f"\n   ID: {threat_id}")
            print(f"   Title: {title[:50]}...")
            print(f"   Indicators: {indicators}")
        
        # Check total count
        cursor.execute("SELECT COUNT(*) FROM threats")
        total_threats = cursor.fetchone()[0]
        print(f"\n📊 Total threats: {total_threats}")
        
        # Check threats with non-empty indicators
        cursor.execute("SELECT COUNT(*) FROM threats WHERE indicators IS NOT NULL AND indicators != '' AND indicators != '{}'")
        threats_with_indicators = cursor.fetchone()[0]
        print(f"📊 Threats with indicators: {threats_with_indicators}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking database schema: {e}")

if __name__ == "__main__":
    check_db_schema()
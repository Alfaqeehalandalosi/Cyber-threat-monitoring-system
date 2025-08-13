#!/usr/bin/env python3
"""
Check Stored Indicators Script
Check if indicators are actually being stored in the database
"""

import sqlite3
import json

def check_stored_indicators():
    """Check if indicators are stored in the database"""
    
    db_path = "ctms/data/threat_intelligence.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 Checking stored indicators in database...")
        print("=" * 50)
        
        # Get threats with their stored indicators
        cursor.execute("SELECT title, indicators FROM threats WHERE indicators IS NOT NULL AND indicators != '' LIMIT 5")
        threats = cursor.fetchall()
        
        print(f"📊 Found {len(threats)} threats with stored indicators")
        
        for title, indicators_json in threats:
            print(f"\n📰 Threat: {title[:50]}...")
            print(f"   📋 Raw indicators: {indicators_json}")
            
            try:
                indicators = json.loads(indicators_json)
                print(f"   🔍 Parsed indicators: {indicators}")
                
                # Check each indicator type
                for indicator_type, values in indicators.items():
                    if values:
                        print(f"   ✅ {indicator_type}: {values}")
                    else:
                        print(f"   ❌ {indicator_type}: None")
                        
            except json.JSONDecodeError as e:
                print(f"   ❌ Error parsing indicators: {e}")
        
        # Check total count of threats with indicators
        cursor.execute("SELECT COUNT(*) FROM threats WHERE indicators IS NOT NULL AND indicators != ''")
        total_with_indicators = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM threats")
        total_threats = cursor.fetchone()[0]
        
        print(f"\n📊 Summary:")
        print(f"   Total threats: {total_threats}")
        print(f"   Threats with indicators: {total_with_indicators}")
        print(f"   Percentage: {(total_with_indicators/total_threats)*100:.1f}%")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking stored indicators: {e}")

if __name__ == "__main__":
    check_stored_indicators()
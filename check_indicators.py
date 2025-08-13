#!/usr/bin/env python3
"""
Check Indicators Script
Check if indicators are being extracted and stored in the database
"""

import sqlite3
import json

def check_indicators():
    """Check indicators in the database"""
    
    db_path = "ctms/data/threat_intelligence.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("🔍 Checking indicators in database...")
        print("=" * 50)
        
        # Check if database exists and has data
        cursor.execute("SELECT COUNT(*) FROM threats")
        total_threats = cursor.fetchone()[0]
        print(f"📊 Total threats in database: {total_threats}")
        
        if total_threats == 0:
            print("❌ No threats found in database")
            return
        
        # Check indicators column
        cursor.execute("PRAGMA table_info(threats)")
        columns = [col[1] for col in cursor.fetchall()]
        print(f"📋 Table columns: {columns}")
        
        if 'indicators' not in columns:
            print("❌ No indicators column found")
            return
        
        # Get threats with indicators
        cursor.execute("SELECT title, indicators FROM threats WHERE indicators IS NOT NULL AND indicators != '' LIMIT 5")
        threats_with_indicators = cursor.fetchall()
        
        print(f"\n🔍 Threats with indicators: {len(threats_with_indicators)}")
        
        all_indicators = {
            'cve_identifiers': set(),
            'company_names': set(),
            'github_repositories': set(),
            'ip_addresses': set(),
            'email_addresses': set(),
            'file_hashes': set(),
            'urls': set()
        }
        
        for title, indicators_json in threats_with_indicators:
            print(f"\n📰 Threat: {title[:50]}...")
            
            try:
                indicators = json.loads(indicators_json)
                print(f"   📋 Indicators: {indicators}")
                
                for indicator_type, values in indicators.items():
                    if indicator_type in all_indicators and isinstance(values, list):
                        all_indicators[indicator_type].update(values)
                        
            except json.JSONDecodeError as e:
                print(f"   ❌ Error parsing indicators: {e}")
                print(f"   Raw data: {indicators_json}")
        
        print(f"\n📊 Summary of extracted indicators:")
        for indicator_type, values in all_indicators.items():
            count = len(values)
            if count > 0:
                print(f"   • {indicator_type}: {count} found")
                for val in list(values)[:3]:  # Show first 3
                    print(f"     - {val}")
            else:
                print(f"   • {indicator_type}: None found")
        
        # Check total indicators
        total_indicators = sum(len(v) for v in all_indicators.values())
        print(f"\n🎯 Total unique indicators: {total_indicators}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking database: {e}")

if __name__ == "__main__":
    check_indicators()
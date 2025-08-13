#!/usr/bin/env python3
"""
Force Data Collection Script
Immediately collect data and test the system
"""

import asyncio
import sys
import os
from data_collector_service import ThreatDataCollector

async def force_collect_data():
    """Force immediate data collection"""
    print("🚀 Force collecting threat data...")
    
    try:
        # Create collector
        collector = ThreatDataCollector()
        
        # Start session
        await collector.start_session()
        
        # Force immediate collection
        print("📡 Collecting from all sources...")
        await collector.collect_all_data()
        
        # Close session
        await collector.close_session()
        
        print("✅ Data collection completed!")
        
        # Check what was collected
        import sqlite3
        db_path = "ctms/data/threat_intelligence.db"
        
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM threats")
            count = cursor.fetchone()[0]
            print(f"📊 Total threats in database: {count}")
            
            if count > 0:
                cursor.execute("SELECT title, threat_score, source_type FROM threats ORDER BY collected_at DESC LIMIT 5")
                threats = cursor.fetchall()
                print("📋 Recent threats:")
                for threat in threats:
                    print(f"  - {threat[0][:60]}... (Score: {threat[1]}, Source: {threat[2]})")
            else:
                print("⚠️ No threats found in database")
            
            conn.close()
        else:
            print("❌ Database not found")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(force_collect_data())
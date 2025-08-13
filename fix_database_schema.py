#!/usr/bin/env python3
"""
Fix Database Schema Script
Add missing columns to the threats table
"""

import sqlite3
import os

def fix_database_schema():
    """Fix the database schema by adding missing columns"""
    
    db_path = "ctms/data/threat_intelligence.db"
    
    print("🔧 Fixing database schema...")
    
    if not os.path.exists(db_path):
        print("❌ Database not found!")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check current table structure
        cursor.execute("PRAGMA table_info(threats)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        print(f"📋 Current columns: {column_names}")
        
        # Add missing columns
        missing_columns = []
        
        if 'threat_type' not in column_names:
            missing_columns.append('threat_type')
            cursor.execute("ALTER TABLE threats ADD COLUMN threat_type TEXT")
            print("✅ Added threat_type column")
        
        if 'status' not in column_names:
            missing_columns.append('status')
            cursor.execute("ALTER TABLE threats ADD COLUMN status TEXT DEFAULT 'active'")
            print("✅ Added status column")
        
        if 'indicators' not in column_names:
            missing_columns.append('indicators')
            cursor.execute("ALTER TABLE threats ADD COLUMN indicators TEXT")
            print("✅ Added indicators column")
        
        if 'hash_id' not in column_names:
            missing_columns.append('hash_id')
            try:
                # First add the column without UNIQUE constraint
                cursor.execute("ALTER TABLE threats ADD COLUMN hash_id TEXT")
                print("✅ Added hash_id column (without UNIQUE constraint)")
                
                # Then create a unique index on the column
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_threats_hash_id ON threats(hash_id)")
                print("✅ Created unique index on hash_id")
            except sqlite3.OperationalError as e:
                print(f"⚠️ Warning: Could not add hash_id column: {e}")
                # Remove from missing_columns if we couldn't add it
                if 'hash_id' in missing_columns:
                    missing_columns.remove('hash_id')
        
        # Check system_status table
        cursor.execute("PRAGMA table_info(system_status)")
        status_columns = cursor.fetchall()
        status_column_names = [col[1] for col in status_columns]
        
        print(f"📋 System status columns: {status_column_names}")
        
        if 'status' not in status_column_names:
            cursor.execute("ALTER TABLE system_status ADD COLUMN status TEXT DEFAULT 'healthy'")
            print("✅ Added status column to system_status table")
        
        conn.commit()
        conn.close()
        
        if missing_columns:
            print(f"✅ Fixed database schema! Added columns: {missing_columns}")
        else:
            print("✅ Database schema is already correct!")
        
        # Verify the fix
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(threats)")
        columns = cursor.fetchall()
        print(f"📋 Updated columns: {[col[1] for col in columns]}")
        conn.close()
        
    except Exception as e:
        print(f"❌ Error fixing database schema: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    fix_database_schema()
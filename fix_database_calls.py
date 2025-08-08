#!/usr/bin/env python3
import os
import re

def fix_file(file_path):
    """Fix await get_database() calls in a file."""
    if not os.path.exists(file_path):
        print(f"⚠️ File not found: {file_path}")
        return False
    
    print(f"🔧 Fixing {file_path}...")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Replace await get_database() with get_database()
    original_content = content
    content = re.sub(r'(\s+)db = await get_database\(\)', r'\1db = get_database()', content)
    
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"✅ Fixed {file_path}")
        return True
    else:
        print(f"ℹ️ No changes needed in {file_path}")
        return False

def main():
    """Fix all database call issues."""
    print("🔧 Fixing database call issues...")
    
    # Files to fix
    files_to_fix = [
        "ctms/api/main.py",
        "ctms/nlp/threat_analyzer.py", 
        "ctms/scraping/tor_scraper.py",
        "ctms/alerts/notification_engine.py",
        "scripts/test_api.py",
        "scripts/debug_api.py",
        "scripts/init_default_sources.py"
    ]
    
    fixed_count = 0
    for file_path in files_to_fix:
        if fix_file(file_path):
            fixed_count += 1
    
    print(f"\n✅ Fixed {fixed_count} files")
    print("\n📋 NEXT STEPS:")
    print("1. Restart your API:")
    print("   pkill -f 'python3 -m ctms.api.main'")
    print("   python3 -m ctms.api.main")
    print("2. Test the scraping source creation:")
    print("   curl -X POST http://localhost:8001/api/v1/scraping/sources \\")
    print("     -H \"Content-Type: application/json\" \\")
    print("     -H \"Authorization: Bearer test_token_12345\" \\")
    print("     -d '{\"name\":\"Test\",\"url\":\"https://example.com\",\"source_type\":\"surface_web\",\"enabled\":true,\"use_tor\":false,\"content_selectors\":{\"title\":\"h1\"},\"scraping_interval\":3600}'")

if __name__ == "__main__":
    main()
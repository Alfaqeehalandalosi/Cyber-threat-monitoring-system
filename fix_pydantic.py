#!/usr/bin/env python3
"""
Fix Pydantic v2 compatibility issues
"""

import os
import re

def fix_api_file():
    """Fix the main API file."""
    api_file = "ctms/api/main.py"
    
    if not os.path.exists(api_file):
        print(f"❌ API file not found: {api_file}")
        return False
    
    print(f"🔧 Fixing {api_file}...")
    
    with open(api_file, 'r') as f:
        content = f.read()
    
    # Replace .dict() with .model_dump()
    original_content = content
    content = content.replace('.dict()', '.model_dump()')
    
    if content != original_content:
        with open(api_file, 'w') as f:
            f.write(content)
        print("✅ Fixed .dict() calls in API file")
    else:
        print("ℹ️ No .dict() calls found in API file")
    
    return True

def fix_models_file():
    """Fix the models file."""
    models_file = "ctms/database/models.py"
    
    if not os.path.exists(models_file):
        print(f"❌ Models file not found: {models_file}")
        return False
    
    print(f"🔧 Fixing {models_file}...")
    
    with open(models_file, 'r') as f:
        content = f.read()
    
    # Replace old Config class with model_config
    original_content = content
    
    # Replace the Config class
    content = re.sub(
        r'class Config:\s*\n\s*populate_by_name = True\s*\n\s*json_encoders = \{\s*\n\s*datetime: lambda v: v\.isoformat\(\)\s*\n\s*\}',
        'model_config = {\n        "populate_by_name": True,\n        "json_encoders": {\n            datetime: lambda v: v.isoformat()\n        }\n    }',
        content
    )
    
    if content != original_content:
        with open(models_file, 'w') as f:
            f.write(content)
        print("✅ Fixed Config class in models file")
    else:
        print("ℹ️ No Config class found in models file")
    
    return True

def fix_other_files():
    """Fix other files with Pydantic issues."""
    files_to_fix = [
        "ctms/nlp/threat_analyzer.py",
        "ctms/scraping/tor_scraper.py",
        "ctms/alerts/notification_engine.py"
    ]
    
    for file_path in files_to_fix:
        if os.path.exists(file_path):
            print(f"🔧 Fixing {file_path}...")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            original_content = content
            content = content.replace('.dict()', '.model_dump()')
            
            if content != original_content:
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"✅ Fixed {file_path}")
            else:
                print(f"ℹ️ No changes needed in {file_path}")
        else:
            print(f"⚠️ File not found: {file_path}")

def main():
    """Main fix function."""
    print("🔧 Fixing Pydantic v2 compatibility issues...")
    
    # Fix API file
    fix_api_file()
    
    # Fix models file
    fix_models_file()
    
    # Fix other files
    fix_other_files()
    
    print("\n✅ Pydantic compatibility fixes completed!")
    print("\n📋 NEXT STEPS:")
    print("1. Start your database services:")
    print("   docker-compose up -d")
    print("2. Test the API:")
    print("   curl -X POST http://localhost:8001/api/v1/scraping/sources \\")
    print("     -H \"Content-Type: application/json\" \\")
    print("     -H \"Authorization: Bearer test_token_12345\" \\")
    print("     -d '{\"name\":\"Test\",\"url\":\"https://example.com\",\"source_type\":\"surface_web\",\"enabled\":true,\"use_tor\":false,\"content_selectors\":{\"title\":\"h1\"},\"scraping_interval\":3600}'")

if __name__ == "__main__":
    main()
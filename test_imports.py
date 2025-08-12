#!/usr/bin/env python3
"""
Test script to verify all imports work correctly
"""

def test_imports():
    """Test all required imports"""
    print("🧪 Testing imports...")
    
    imports_to_test = [
        ('fastapi', 'fastapi'),
        ('uvicorn', 'uvicorn'),
        ('streamlit', 'streamlit'),
        ('aiohttp', 'aiohttp'),
        ('requests', 'requests'),
        ('pandas', 'pandas'),
        ('numpy', 'numpy'),
        ('sklearn', 'scikit-learn'),
        ('bs4', 'beautifulsoup4'),
        ('lxml', 'lxml'),
        ('plotly', 'plotly'),
        ('matplotlib', 'matplotlib'),
        ('seaborn', 'seaborn'),
        ('sqlalchemy', 'sqlalchemy'),
        ('redis', 'redis'),
        ('python-dotenv', 'dotenv'),
        ('pydantic', 'pydantic'),
        ('nltk', 'nltk'),
        ('textblob', 'textblob'),
        ('spacy', 'spacy')
    ]
    
    failed_imports = []
    
    for import_name, package_name in imports_to_test:
        try:
            __import__(import_name)
            print(f"   ✅ {package_name}")
        except ImportError as e:
            print(f"   ❌ {package_name} - {str(e)}")
            failed_imports.append(package_name)
    
    if failed_imports:
        print(f"\n❌ Failed imports: {', '.join(failed_imports)}")
        return False
    else:
        print("\n✅ All imports successful!")
        return True

if __name__ == "__main__":
    success = test_imports()
    if success:
        print("🎉 All dependencies are working correctly!")
    else:
        print("⚠️  Some dependencies failed to import")
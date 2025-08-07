#!/bin/bash
# =============================================================================
# COMPLETE LOCAL FIX SCRIPT
# =============================================================================
# This script will fix everything on your local machine

set -e

echo "🔧 Complete Local Fix for Cyber Threat Monitoring System"
echo "========================================================"

# Check if we're in the right directory
if [ ! -f "requirements.txt" ]; then
    echo "❌ Please run this script from the Cyber-threat-monitoring-system directory"
    exit 1
fi

echo "📋 Step 1: Checking current setup..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "🐍 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🐍 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️ Creating .env file..."
    cp .env.example .env
fi

echo "📋 Step 2: Fixing security keys..."

# Create and run the security keys fix
cat > fix_keys.py << 'EOF'
#!/usr/bin/env python3
import secrets
import string
import os

def generate_secure_key(length=64):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_jwt_secret():
    return secrets.token_urlsafe(64)

def update_env_file():
    env_file = ".env"
    
    if not os.path.exists(env_file):
        print("❌ .env file not found")
        return False
    
    with open(env_file, 'r') as f:
        lines = f.readlines()
    
    secret_key = generate_secure_key(64)
    jwt_secret = generate_jwt_secret()
    
    print(f"Generated SECRET_KEY: {secret_key}")
    print(f"Generated JWT_SECRET_KEY: {jwt_secret}")
    
    updated_lines = []
    for line in lines:
        if line.startswith("SECRET_KEY=") and "your-super-secret-key" in line:
            updated_lines.append(f"SECRET_KEY={secret_key}\n")
        elif line.startswith("JWT_SECRET_KEY=") and "your-jwt-secret-key" in line:
            updated_lines.append(f"JWT_SECRET_KEY={jwt_secret}\n")
        else:
            updated_lines.append(line)
    
    with open(env_file, 'w') as f:
        f.writelines(updated_lines)
    
    print("✅ Updated .env file with secure keys")
    return True

if __name__ == "__main__":
    print("🔐 Fixing security keys...")
    if update_env_file():
        print("✅ Security keys updated successfully!")
    else:
        print("❌ Failed to update security keys")
EOF

python3 fix_keys.py

echo "📋 Step 3: Fixing Pydantic compatibility issues..."

# Create and run the Pydantic fix
cat > fix_pydantic.py << 'EOF'
#!/usr/bin/env python3
import os
import re

def fix_api_file():
    api_file = "ctms/api/main.py"
    
    if not os.path.exists(api_file):
        print(f"❌ API file not found: {api_file}")
        return False
    
    print(f"🔧 Fixing {api_file}...")
    
    with open(api_file, 'r') as f:
        content = f.read()
    
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
    models_file = "ctms/database/models.py"
    
    if not os.path.exists(models_file):
        print(f"❌ Models file not found: {models_file}")
        return False
    
    print(f"🔧 Fixing {models_file}...")
    
    with open(models_file, 'r') as f:
        content = f.read()
    
    original_content = content
    
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
    print("🔧 Fixing Pydantic v2 compatibility issues...")
    
    fix_api_file()
    fix_models_file()
    fix_other_files()
    
    print("\n✅ Pydantic compatibility fixes completed!")

if __name__ == "__main__":
    main()
EOF

python3 fix_pydantic.py

echo "📋 Step 4: Starting database services..."

# Check if Docker is available
if command -v docker &> /dev/null; then
    echo "🐳 Starting Docker services..."
    docker-compose up -d
    
    echo "⏳ Waiting for services to be ready..."
    sleep 30
else
    echo "⚠️ Docker not found. Please install Docker Desktop and run:"
    echo "   docker-compose up -d"
fi

echo "📋 Step 5: Creating startup script..."

# Create a startup script
cat > start_api.py << 'EOF'
#!/usr/bin/env python3
"""
Startup script for the Cyber Threat Monitoring System API.
"""

import asyncio
import sys
import os
import uvicorn

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctms.core.config import settings
from ctms.core.logger import configure_logging, get_logger
from ctms.database.connection import initialize_databases, close_databases

logger = get_logger(__name__)

async def initialize_system():
    """Initialize the system components."""
    try:
        logger.info("🚀 Initializing Cyber Threat Monitoring System...")
        
        # Configure logging
        configure_logging()
        
        # Initialize databases
        await initialize_databases()
        logger.info("✅ Database initialization completed")
        
        logger.info("✅ System initialization completed")
        
    except Exception as e:
        logger.error(f"❌ System initialization failed: {e}")
        raise

async def shutdown_system():
    """Shutdown the system components."""
    try:
        logger.info("🛑 Shutting down system...")
        await close_databases()
        logger.info("✅ System shutdown completed")
    except Exception as e:
        logger.error(f"❌ System shutdown failed: {e}")

def main():
    """Main startup function."""
    try:
        # Initialize system
        asyncio.run(initialize_system())
        
        # Start the API server
        logger.info("🌐 Starting API server...")
        uvicorn.run(
            "ctms.api.main:app",
            host="0.0.0.0",
            port=8001,
            reload=True,
            log_level="info"
        )
        
    except KeyboardInterrupt:
        logger.info("🛑 Received shutdown signal")
        asyncio.run(shutdown_system())
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        asyncio.run(shutdown_system())
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

echo "📋 Step 6: Creating test script..."

# Create a test script
cat > test_api.py << 'EOF'
#!/usr/bin/env python3
"""
Test script for the API
"""

import requests
import time
import sys

def test_api():
    """Test the API endpoints."""
    print("🧪 Testing API endpoints...")
    
    # Test health endpoint
    try:
        response = requests.get("http://localhost:8001/health", timeout=10)
        if response.status_code == 200:
            print("✅ Health endpoint working")
        else:
            print(f"❌ Health endpoint failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ API server is not running on port 8001")
        print("   Please start the API server first:")
        print("   python3 start_api.py")
        return False
    except Exception as e:
        print(f"❌ Health endpoint error: {e}")
        return False
    
    # Test scraping source creation
    try:
        source_data = {
            "name": "Bleeping Computer",
            "url": "https://www.bleepingcomputer.com",
            "source_type": "surface_web",
            "enabled": True,
            "use_tor": False,
            "content_selectors": {
                "title": "h1.entry-title",
                "content": ".entry-content"
            },
            "scraping_interval": 3600
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test_token_12345"
        }
        
        response = requests.post(
            "http://localhost:8001/api/v1/scraping/sources",
            headers=headers,
            json=source_data,
            timeout=10
        )
        
        if response.status_code == 201:
            print("✅ Create scraping source endpoint working")
            result = response.json()
            print(f"   Created source with ID: {result.get('_id', 'Unknown')}")
            return True
        else:
            print(f"❌ Create scraping source failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Create scraping source error: {e}")
        return False

if __name__ == "__main__":
    success = test_api()
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)
EOF

echo "📋 Step 7: Making scripts executable..."
chmod +x start_api.py test_api.py

echo "✅ Complete local fix completed!"
echo ""
echo "📋 NEXT STEPS:"
echo "1. Start the API server:"
echo "   python3 start_api.py"
echo ""
echo "2. In another terminal, test the API:"
echo "   python3 test_api.py"
echo ""
echo "3. Or test with curl:"
echo "   curl -X POST http://localhost:8001/api/v1/scraping/sources \\"
echo "     -H \"Content-Type: application/json\" \\"
echo "     -H \"Authorization: Bearer test_token_12345\" \\"
echo "     -d '{\"name\":\"Test\",\"url\":\"https://example.com\",\"source_type\":\"surface_web\",\"enabled\":true,\"use_tor\":false,\"content_selectors\":{\"title\":\"h1\"},\"scraping_interval\":3600}'"
echo ""
echo "4. Access the API documentation:"
echo "   http://localhost:8001/docs"
echo ""
echo "5. Access the dashboard:"
echo "   streamlit run ctms/dashboard/main_dashboard.py"
#!/usr/bin/env python3
"""
Simplified CTMS Demo Startup Script
This script starts the CTMS system without requiring Docker infrastructure
for demonstration purposes.
"""

import os
import sys
import subprocess
import time
import signal
import threading
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

def print_banner():
    """Print the CTMS banner."""
    print("""
🛡️  CYBER THREAT MONITORING SYSTEM - DEMO MODE
================================================
Starting simplified demo version without Docker infrastructure...
""")

def check_dependencies():
    """Check if required Python packages are installed."""
    required_packages = [
        'fastapi', 'uvicorn', 'streamlit', 'pydantic', 
        'pymongo', 'elasticsearch', 'redis', 'aiohttp',
        'loguru', 'requests', 'bs4'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Please install them with: pip install " + " ".join(missing_packages))
        return False
    
    print("✅ All required packages are installed")
    return True

def create_demo_data():
    """Create demo data for the system."""
    print("📊 Creating demo data...")
    
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    
    # Create demo data directory
    os.makedirs("demo_data", exist_ok=True)
    
    # Create a simple demo database file
    demo_db = {
        "iocs": [
            {
                "id": "demo_ioc_1",
                "type": "ip",
                "value": "192.168.1.100",
                "severity": "high",
                "description": "Demo malicious IP address",
                "created_at": "2024-01-15T10:30:00Z",
                "source": "demo_scraper"
            },
            {
                "id": "demo_ioc_2", 
                "type": "domain",
                "value": "malicious.example.com",
                "severity": "medium",
                "description": "Demo malicious domain",
                "created_at": "2024-01-15T11:00:00Z",
                "source": "demo_scraper"
            }
        ],
        "threats": [
            {
                "id": "demo_threat_1",
                "type": "malware",
                "title": "Demo Ransomware Campaign",
                "description": "Demo ransomware threat targeting healthcare sector",
                "severity": "critical",
                "created_at": "2024-01-15T09:00:00Z",
                "source": "demo_intel"
            }
        ],
        "alerts": [
            {
                "id": "demo_alert_1",
                "title": "Demo Security Alert",
                "description": "Demo alert for suspicious activity",
                "severity": "high",
                "status": "new",
                "created_at": "2024-01-15T12:00:00Z"
            }
        ]
    }
    
    import json
    with open("demo_data/demo_database.json", "w") as f:
        json.dump(demo_db, f, indent=2)
    
    print("✅ Demo data created")

def start_api_server():
    """Start the FastAPI server in demo mode."""
    print("🚀 Starting API server...")
    
    # Set demo environment variables
    os.environ['DEMO_MODE'] = 'true'
    os.environ['DEBUG'] = 'true'
    
    try:
        # Import and run the demo API server
        from ctms.api.demo_api import app
        import uvicorn
        
        # Start the server
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
            reload=False
        )
    except Exception as e:
        print(f"❌ Failed to start API server: {e}")
        return False
    
    return True

def start_dashboard():
    """Start the Streamlit dashboard."""
    print("📊 Starting dashboard...")
    
    try:
        # Set demo environment variables
        os.environ['DEMO_MODE'] = 'true'
        os.environ['STREAMLIT_SERVER_PORT'] = '8501'
        os.environ['STREAMLIT_SERVER_ADDRESS'] = '0.0.0.0'
        
        # Start Streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            "ctms/dashboard/main_dashboard.py",
            "--server.port=8501",
            "--server.address=0.0.0.0",
            "--server.headless=true"
        ])
    except Exception as e:
        print(f"❌ Failed to start dashboard: {e}")
        return False
    
    return True

def main():
    """Main function to start the demo."""
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Create demo data
    create_demo_data()
    
    print("\n🎯 Starting CTMS Demo System...")
    print("📡 API will be available at: http://localhost:8000")
    print("📊 Dashboard will be available at: http://localhost:8501")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop the demo\n")
    
    # Start API server in a separate thread
    api_thread = threading.Thread(target=start_api_server, daemon=True)
    api_thread.start()
    
    # Wait a moment for API to start
    time.sleep(3)
    
    # Start dashboard
    start_dashboard()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Demo stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        sys.exit(1)
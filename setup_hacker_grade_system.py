#!/usr/bin/env python3
"""
Hacker-Grade Threat Intelligence System Setup Script
Comprehensive setup and deployment for academic cybersecurity research
Educational purposes only - Defensive security research
"""

import os
import sys
import subprocess
import json
import shutil
from pathlib import Path
import platform

def print_banner():
    """Print setup banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    🛡️ Hacker-Grade Threat Intelligence System Setup        ║
    ║                                                              ║
    ║    Academic Cybersecurity Research Project                  ║
    ║    Educational purposes only - Defensive security research  ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Check Python version compatibility"""
    print("🔍 Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {version.major}.{version.minor}.{version.micro}")
        sys.exit(1)
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    directories = [
        "ctms/models",
        "ctms/logs",
        "ctms/data",
        "ctms/cache",
        "config",
        "scripts"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"   ✅ Created: {directory}")

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    
    # Check if pip is available
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("❌ Error: pip is not available")
        sys.exit(1)
    
    # Install core dependencies
    core_deps = [
        "fastapi==0.104.1",
        "uvicorn[standard]==0.24.0",
        "streamlit==1.28.1",
        "aiohttp==3.9.1",
        "requests==2.31.0",
        "pandas==2.1.3",
        "numpy==1.25.2",
        "beautifulsoup4==4.12.2",
        "feedparser==6.0.11",
        "lxml==4.9.3",
        "plotly==5.17.0",
        "scikit-learn==1.3.2",
        "python-dotenv==1.0.0",
        "pydantic==2.5.0"
    ]
    
    for dep in core_deps:
        try:
            print(f"   Installing: {dep}")
            subprocess.run([sys.executable, "-m", "pip", "install", dep], check=True, capture_output=True)
            print(f"   ✅ Installed: {dep}")
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Failed to install: {dep}")
            print(f"   Error: {e}")
    
    print("✅ Core dependencies installed")

def create_environment_file():
    """Create environment configuration file"""
    print("⚙️ Creating environment configuration...")
    
    env_content = """# Hacker-Grade Threat Intelligence System Environment Configuration
# Educational purposes only - Defensive security research

# API Configuration
API_HOST=localhost
API_PORT=8000
API_TOKEN=demo_token_for_development_12345

# Database Configuration (optional)
DATABASE_URL=sqlite:///ctms/data/threat_intelligence.db

# Email Alert Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_RECIPIENTS=security@company.com,admin@company.com

# Webhook Alert Configuration
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
WEBHOOK_HEADERS={"Content-Type": "application/json"}

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=ctms/logs/threat_intelligence.log

# Cache Configuration
CACHE_DURATION=300
CACHE_ENABLED=true

# Scraping Configuration
SCRAPING_INTERVAL=1800
MAX_CONCURRENT_REQUESTS=10
REQUEST_TIMEOUT=30

# Security Configuration
ENABLE_RATE_LIMITING=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600

# Development Configuration
DEBUG_MODE=false
ENABLE_METRICS=true
"""
    
    with open(".env", "w") as f:
        f.write(env_content)
    
    print("✅ Environment file created: .env")
    print("   ⚠️  Please update the .env file with your actual configuration")

def create_startup_scripts():
    """Create startup scripts for different platforms"""
    print("🚀 Creating startup scripts...")
    
    # Windows batch script
    windows_script = """@echo off
echo Starting Hacker-Grade Threat Intelligence System...
echo Educational purposes only - Defensive security research

REM Activate virtual environment if exists
if exist "venv\\Scripts\\activate.bat" (
    call venv\\Scripts\\activate.bat
)

REM Start the API server
start "API Server" cmd /k "python -m uvicorn ctms.main:app --host localhost --port 8000 --reload"

REM Wait a moment for API to start
timeout /t 3 /nobreak > nul

REM Start the dashboard
start "Dashboard" cmd /k "streamlit run hacker_grade_dashboard.py --server.port 8501"

echo System started successfully!
echo API: http://localhost:8000
echo Dashboard: http://localhost:8501
echo.
echo Press any key to exit...
pause > nul
"""
    
    with open("start_system.bat", "w") as f:
        f.write(windows_script)
    
    # Unix/Linux/Mac shell script
    unix_script = """#!/bin/bash
echo "Starting Hacker-Grade Threat Intelligence System..."
echo "Educational purposes only - Defensive security research"

# Activate virtual environment if exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Start the API server in background
echo "Starting API server..."
python -m uvicorn ctms.main:app --host localhost --port 8000 --reload &
API_PID=$!

# Wait a moment for API to start
sleep 3

# Start the dashboard
echo "Starting dashboard..."
streamlit run hacker_grade_dashboard.py --server.port 8501 &
DASHBOARD_PID=$!

echo "System started successfully!"
echo "API: http://localhost:8000"
echo "Dashboard: http://localhost:8501"
echo "Press Ctrl+C to stop all services"

# Wait for user interrupt
trap "echo 'Stopping services...'; kill $API_PID $DASHBOARD_PID; exit" INT
wait
"""
    
    with open("start_system.sh", "w") as f:
        f.write(unix_script)
    
    # Make shell script executable on Unix systems
    if platform.system() != "Windows":
        os.chmod("start_system.sh", 0o755)
    
    print("✅ Startup scripts created:")
    print("   - start_system.bat (Windows)")
    print("   - start_system.sh (Unix/Linux/Mac)")

def create_test_script():
    """Create a test script to verify the system"""
    print("🧪 Creating test script...")
    
    test_script = """#!/usr/bin/env python3
\"\"\"
Hacker-Grade Threat Intelligence System Test Script
Tests the system functionality and API endpoints
\"\"\"

import requests
import json
import time
from datetime import datetime

def test_api_health():
    \"\"\"Test API health endpoint\"\"\"
    print("🔍 Testing API health...")
    try:
        response = requests.get("http://localhost:8000/api/v1/hacker-grade/health", 
                              headers={"Authorization": "Bearer demo_token_for_development_12345"})
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Health: {data.get('status', 'Unknown')}")
            print(f"   Version: {data.get('version', 'Unknown')}")
            print(f"   Service: {data.get('service', 'Unknown')}")
            return True
        else:
            print(f"❌ API Health failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API Health error: {e}")
        return False

def test_threat_summary():
    \"\"\"Test threat summary endpoint\"\"\"
    print("📊 Testing threat summary...")
    try:
        response = requests.get("http://localhost:8000/api/v1/hacker-grade/threats/summary", 
                              headers={"Authorization": "Bearer demo_token_for_development_12345"})
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Threat Summary:")
            print(f"   Total Articles: {data.get('total_articles', 0)}")
            print(f"   High Severity: {data.get('high_severity_count', 0)}")
            print(f"   Avg Score: {data.get('avg_threat_score', 0):.2f}")
            return True
        else:
            print(f"❌ Threat Summary failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Threat Summary error: {e}")
        return False

def test_dashboard():
    \"\"\"Test dashboard accessibility\"\"\"
    print("📈 Testing dashboard...")
    try:
        response = requests.get("http://localhost:8501", timeout=10)
        if response.status_code == 200:
            print("✅ Dashboard is accessible")
            return True
        else:
            print(f"❌ Dashboard failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        return False

def main():
    \"\"\"Run all tests\"\"\"
    print("🧪 Hacker-Grade Threat Intelligence System Test")
    print("=" * 50)
    
    # Wait for services to start
    print("⏳ Waiting for services to start...")
    time.sleep(5)
    
    # Run tests
    tests = [
        test_api_health,
        test_threat_summary,
        test_dashboard
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test error: {e}")
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is ready.")
    else:
        print("⚠️  Some tests failed. Please check the system configuration.")

if __name__ == "__main__":
    main()
"""
    
    with open("test_system.py", "w") as f:
        f.write(test_script)
    
    print("✅ Test script created: test_system.py")

def create_documentation():
    """Create documentation files"""
    print("📚 Creating documentation...")
    
    # README file
    readme_content = """# Hacker-Grade Threat Intelligence System

## Overview

This is a comprehensive threat intelligence system designed for academic cybersecurity research. It monitors hacker forums, ransomware leak sites, paste sites, and GitHub repositories for emerging threats.

**⚠️ Educational purposes only - Defensive security research**

## Features

- **Hacker Forum Monitoring**: Scrapes multiple hacker forums for threat discussions
- **Ransomware Leak Sites**: Monitors ransomware group leak sites for data breach intelligence
- **Paste Site Analysis**: Scans paste sites for leaked credentials and exploit code
- **GitHub Exploit Detection**: Monitors GitHub for newly published exploit repositories
- **Advanced Threat Scoring**: ML-based threat classification and scoring
- **Real-time Alerting**: Email and webhook alerts for high-severity threats
- **Interactive Dashboard**: Streamlit-based visualization interface

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Internet connection for scraping

### Installation

1. **Clone or download the system**
2. **Run the setup script**:
   ```bash
   python setup_hacker_grade_system.py
   ```

3. **Configure the environment**:
   - Edit the `.env` file with your settings
   - Update email/webhook configurations

4. **Start the system**:
   - Windows: `start_system.bat`
   - Unix/Linux/Mac: `./start_system.sh`

5. **Access the system**:
   - API: http://localhost:8000
   - Dashboard: http://localhost:8501

### API Endpoints

- `GET /api/v1/hacker-grade/health` - System health check
- `GET /api/v1/hacker-grade/threats/summary` - Threat summary
- `GET /api/v1/hacker-grade/threats/intelligence` - Full threat data
- `GET /api/v1/hacker-grade/threats/zero-day` - Zero-day threats
- `GET /api/v1/hacker-grade/threats/ransomware` - Ransomware threats
- `GET /api/v1/hacker-grade/threats/github` - GitHub exploits

### Authentication

Use the demo token for development:
```
Authorization: Bearer demo_token_for_development_12345
```

## Configuration

### Environment Variables

- `API_HOST` - API server host (default: localhost)
- `API_PORT` - API server port (default: 8000)
- `SMTP_SERVER` - Email server for alerts
- `WEBHOOK_URL` - Webhook URL for alerts
- `CACHE_DURATION` - Cache duration in seconds

### Source Configuration

Edit `ctms/config/hacker_sources.py` to:
- Enable/disable specific sources
- Modify scraping intervals
- Add new sources
- Adjust trust levels

## Dashboard Features

- **Real-time Threat Feed**: Live threat intelligence display
- **Zero-Day Threats**: Dedicated zero-day vulnerability monitoring
- **Ransomware Threats**: Ransomware-specific threat analysis
- **GitHub Exploits**: GitHub repository exploit monitoring
- **Threat Indicators**: Extracted IOCs and indicators
- **Alert Configuration**: Email and webhook alert setup

## Security Considerations

- **Educational Use Only**: This system is for academic research
- **Legal Compliance**: Ensure compliance with applicable laws
- **Rate Limiting**: Respect website rate limits and robots.txt
- **Data Privacy**: Handle sensitive data appropriately
- **Access Control**: Implement proper authentication in production

## Testing

Run the test script to verify system functionality:
```bash
python test_system.py
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **API Connection**: Check if the API server is running
3. **Scraping Failures**: Verify internet connection and source availability
4. **Dashboard Issues**: Check Streamlit installation and port availability

### Logs

Check logs in `ctms/logs/` for detailed error information.

## Contributing

This is an academic project. Contributions should focus on:
- Improving threat detection algorithms
- Adding new legitimate sources
- Enhancing the user interface
- Bug fixes and performance improvements

## License

This project is for educational purposes only. Use responsibly and in compliance with applicable laws and regulations.

## Disclaimer

This system is designed for defensive security research and educational purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse of this system.
"""
    
    with open("README.md", "w") as f:
        f.write(readme_content)
    
    # API Documentation
    api_docs = """# Hacker-Grade Threat Intelligence API Documentation

## Authentication

All API endpoints require authentication using a Bearer token:

```
Authorization: Bearer demo_token_for_development_12345
```

## Base URL

```
http://localhost:8000/api/v1/hacker-grade
```

## Endpoints

### Health Check

**GET** `/health`

Check system health and status.

**Response:**
```json
{
  "status": "healthy",
  "service": "Hacker-Grade Threat Intelligence",
  "version": "3.0.0",
  "timestamp": "2024-01-01T12:00:00"
}
```

### Threat Summary

**GET** `/threats/summary`

Get summary statistics of collected threats.

**Response:**
```json
{
  "total_articles": 150,
  "high_severity_count": 25,
  "avg_threat_score": 0.65,
  "sources_used": 4,
  "top_threats": [...],
  "threat_categories": {...},
  "source_categories": {...}
}
```

### Full Threat Intelligence

**GET** `/threats/intelligence`

Get complete threat intelligence data.

**Parameters:**
- `force_refresh` (boolean): Force fresh data collection

**Response:**
```json
{
  "threat_articles": [...],
  "total_articles": 150,
  "high_severity_count": 25,
  "source_types": [...],
  "threat_types": [...],
  "threat_report": {...}
}
```

### Zero-Day Threats

**GET** `/threats/zero-day`

Get zero-day specific threats.

**Response:**
```json
{
  "zero_day_threats": [...],
  "total_zero_day": 5,
  "high_severity_zero_day": 2
}
```

### Ransomware Threats

**GET** `/threats/ransomware`

Get ransomware-specific threats.

**Response:**
```json
{
  "ransomware_threats": [...],
  "total_ransomware": 20,
  "high_severity_ransomware": 8
}
```

### GitHub Exploits

**GET** `/threats/github`

Get GitHub exploit threats.

**Response:**
```json
{
  "github_threats": [...],
  "total_github": 30,
  "high_severity_github": 12
}
```

### Threat Indicators

**GET** `/threats/indicators`

Get extracted threat indicators.

**Response:**
```json
{
  "cve_ids": [...],
  "ip_addresses": [...],
  "domains": [...],
  "github_repos": [...],
  "company_names": [...],
  "total_indicators": 150
}
```

### Threat Filtering

**POST** `/threats/filter`

Filter threats based on criteria.

**Request Body:**
```json
{
  "min_score": 0.5,
  "max_score": 1.0,
  "threat_types": ["zero_day", "exploit"],
  "source_types": ["github", "hacker_forum"],
  "time_range_hours": 24
}
```

### Alert Configuration

**POST** `/alerts/configure`

Configure alert settings.

**Request Body:**
```json
{
  "email_recipients": ["security@company.com"],
  "webhook_url": "https://hooks.slack.com/services/...",
  "threshold": 0.8,
  "enabled": true
}
```

### Test Alerts

**POST** `/alerts/test`

Test alert configuration.

### Clear Cache

**POST** `/clear-cache`

Clear system cache.

## Error Responses

All endpoints return standard HTTP status codes:

- `200` - Success
- `401` - Unauthorized (invalid token)
- `500` - Internal server error

Error response format:
```json
{
  "detail": "Error message"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse. Limits are configurable in the environment settings.

## Data Formats

### Threat Article Format

```json
{
  "title": "Threat Title",
  "content": "Threat content...",
  "link": "https://source.com/article",
  "source": "Source Name",
  "source_type": "hacker_forum",
  "published": "2024-01-01T12:00:00",
  "threat_score": 0.85,
  "threat_type": "zero_day",
  "tags": ["exploit", "vulnerability"],
  "indicators": {
    "cve_ids": ["CVE-2024-1234"],
    "ip_addresses": ["192.168.1.1"],
    "domains": ["malicious.com"]
  }
}
```

### Threat Report Format

```json
{
  "report_metadata": {...},
  "executive_summary": {...},
  "threat_analysis": {...},
  "top_threats": [...],
  "critical_threats": [...],
  "recommendations": [...]
}
```
"""
    
    with open("API_DOCUMENTATION.md", "w") as f:
        f.write(api_docs)
    
    print("✅ Documentation created:")
    print("   - README.md")
    print("   - API_DOCUMENTATION.md")

def main():
    """Main setup function"""
    print_banner()
    
    print("🚀 Starting Hacker-Grade Threat Intelligence System Setup")
    print("=" * 60)
    
    # Run setup steps
    steps = [
        ("Checking Python version", check_python_version),
        ("Creating directories", create_directories),
        ("Installing dependencies", install_dependencies),
        ("Creating environment file", create_environment_file),
        ("Creating startup scripts", create_startup_scripts),
        ("Creating test script", create_test_script),
        ("Creating documentation", create_documentation)
    ]
    
    for step_name, step_func in steps:
        print(f"\n📋 {step_name}...")
        try:
            step_func()
        except Exception as e:
            print(f"❌ Error in {step_name}: {e}")
            return False
    
    print("\n" + "=" * 60)
    print("🎉 Setup completed successfully!")
    print("\n📋 Next Steps:")
    print("1. Update the .env file with your configuration")
    print("2. Start the system using the provided scripts")
    print("3. Access the dashboard at http://localhost:8501")
    print("4. Test the system using test_system.py")
    print("\n⚠️  Remember: This system is for educational purposes only!")
    print("   Ensure compliance with applicable laws and regulations.")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
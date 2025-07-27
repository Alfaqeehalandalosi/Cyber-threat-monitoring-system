# 🍎 macOS Setup Guide - Cyber Threat Monitoring System

This guide provides step-by-step instructions for setting up and running the Cyber Threat Monitoring System on macOS.

## 📋 Prerequisites

### 1. Install Homebrew (if not already installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Install Required Software
```bash
# Install Python 3.8+
brew install python@3.11

# Install Docker Desktop for Mac
brew install --cask docker

# Install Git (if not already installed)
brew install git

# Install additional tools
brew install wget curl
```

### 3. Start Docker Desktop
1. Open Docker Desktop from Applications
2. Wait for Docker to start (you'll see the whale icon in the menu bar)
3. Verify Docker is running:
```bash
docker --version
docker-compose --version
```

## 🚀 Quick Setup for macOS

### Step 1: Clone and Setup Project
```bash
# Clone the repository
git clone <repository-url>
cd cyber-threat-monitoring-system

# Create virtual environment using Python 3
python3 -m venv venv

# Activate virtual environment (macOS/Linux)
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit configuration with your preferred editor
nano .env
# OR
vim .env
# OR
code .env  # if you have VS Code
```

**Required Configuration for macOS:**
```bash
# Application Settings
SECRET_KEY=your-super-secret-key-change-this-now
JWT_SECRET_KEY=your-jwt-secret-key-change-this-now
DEBUG=false

# Database Configuration
MONGODB_URL=mongodb://admin:secure_mongo_password@localhost:27017/threat_monitoring?authSource=admin
MONGODB_DATABASE=threat_monitoring

# Elasticsearch
ELASTICSEARCH_URL=http://localhost:9200

# TOR Proxy (works on macOS)
USE_TOR_PROXY=true
TOR_PROXY_HOST=localhost
TOR_PROXY_PORT=9050

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Dashboard
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8501

# Logging (macOS paths)
LOG_FILE=logs/ctms.log
LOG_LEVEL=INFO
```

### Step 3: Start Infrastructure Services
```bash
# Start all services with Docker Compose
docker-compose up -d

# Wait for services to initialize
echo "Waiting for services to start..."
sleep 30

# Check service status
docker-compose ps

# You should see all services running:
# - ctms_mongodb
# - ctms_elasticsearch  
# - ctms_tor_proxy
# - ctms_redis
```

### Step 4: Install NLP Models
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Install spaCy English model
python -m spacy download en_core_web_sm

# Verify installation
python -c "import spacy; nlp = spacy.load('en_core_web_sm'); print('✅ spaCy model installed successfully')"
```

### Step 5: Initialize Database
```bash
# Test database connection and create indexes
python -c "
import asyncio
from ctms.database.connection import initialize_databases

async def main():
    try:
        await initialize_databases()
        print('✅ Database initialized successfully!')
    except Exception as e:
        print(f'❌ Database initialization failed: {e}')

asyncio.run(main())
"
```

### Step 6: Launch the Application

#### Option A: Using Individual Terminal Windows

**Terminal 1 - API Server:**
```bash
cd /path/to/cyber-threat-monitoring-system
source venv/bin/activate
python -m ctms.api.main
```

**Terminal 2 - Dashboard:**
```bash
cd /path/to/cyber-threat-monitoring-system
source venv/bin/activate
streamlit run ctms/dashboard/main_dashboard.py
```

#### Option B: Using the Startup Script (Recommended)

```bash
# Make the startup script executable
chmod +x scripts/start_macos.sh

# Run the startup script
./scripts/start_macos.sh
```

### Step 7: Access the System

- **Dashboard**: http://localhost:8501
- **API Documentation**: http://localhost:8000/docs
- **API Health Check**: http://localhost:8000/health

**Default Login Credentials:**
- Username: `admin`
- Password: `admin`

## 🛠 macOS-Specific Scripts

### Startup Script (`scripts/start_macos.sh`)
```bash
#!/bin/bash
# macOS Startup Script for CTMS

set -e

echo "🍎 Starting Cyber Threat Monitoring System on macOS..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop first."
    echo "   You can find it in Applications or click the Docker whale icon in the menu bar"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found. Please copy .env.example to .env and configure it."
    exit 1
fi

# Start infrastructure services
echo "🚀 Starting infrastructure services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to initialize..."
sleep 20

# Check service health
echo "🔍 Checking service health..."
for i in {1..30}; do
    if curl -s http://localhost:9200/_cluster/health > /dev/null; then
        echo "✅ Elasticsearch is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Elasticsearch failed to start"
        exit 1
    fi
    sleep 2
done

# Start API in background
echo "🚀 Starting API server..."
python -m ctms.api.main &
API_PID=$!

# Wait for API to be ready
echo "⏳ Waiting for API to start..."
sleep 10

# Check API health
for i in {1..15}; do
    if curl -s http://localhost:8000/health > /dev/null; then
        echo "✅ API server is ready"
        break
    fi
    if [ $i -eq 15 ]; then
        echo "❌ API server failed to start"
        kill $API_PID 2>/dev/null || true
        exit 1
    fi
    sleep 2
done

# Start Dashboard
echo "🚀 Starting dashboard..."
echo "📊 Dashboard will open in your browser shortly..."
echo ""
echo "🌐 Access URLs:"
echo "   Dashboard: http://localhost:8501"
echo "   API Docs:  http://localhost:8000/docs"
echo "   Health:    http://localhost:8000/health"
echo ""
echo "🔑 Default login: admin/admin"
echo ""
echo "Press Ctrl+C to stop all services"

# Start Streamlit dashboard
streamlit run ctms/dashboard/main_dashboard.py

# Cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    kill $API_PID 2>/dev/null || true
    docker-compose down
    echo "✅ Shutdown complete"
}

trap cleanup EXIT INT TERM
```

### Stop Script (`scripts/stop_macos.sh`)
```bash
#!/bin/bash
# macOS Stop Script for CTMS

echo "🛑 Stopping Cyber Threat Monitoring System..."

# Stop Docker services
docker-compose down

# Kill any remaining Python processes (be careful with this)
echo "🔍 Checking for running CTMS processes..."

# Find and kill API processes
API_PIDS=$(ps aux | grep "ctms.api.main" | grep -v grep | awk '{print $2}')
if [ ! -z "$API_PIDS" ]; then
    echo "🔻 Stopping API server processes..."
    echo $API_PIDS | xargs kill
fi

# Find and kill Streamlit processes
STREAMLIT_PIDS=$(ps aux | grep "streamlit run ctms/dashboard" | grep -v grep | awk '{print $2}')
if [ ! -z "$STREAMLIT_PIDS" ]; then
    echo "🔻 Stopping dashboard processes..."
    echo $STREAMLIT_PIDS | xargs kill
fi

echo "✅ All services stopped"
```

### Health Check Script (`scripts/health_check_macos.sh`)
```bash
#!/bin/bash
# macOS Health Check Script for CTMS

echo "🔍 CTMS Health Check on macOS"
echo "==============================="

# Check Docker
echo "📦 Docker Status:"
if docker info > /dev/null 2>&1; then
    echo "   ✅ Docker is running"
    echo "   📊 Docker version: $(docker --version)"
else
    echo "   ❌ Docker is not running"
fi

echo ""

# Check Docker services
echo "🐳 Docker Services:"
if docker-compose ps | grep -q "Up"; then
    docker-compose ps | grep "Up" | while read line; do
        service=$(echo $line | awk '{print $1}')
        echo "   ✅ $service"
    done
else
    echo "   ❌ No Docker services running"
fi

echo ""

# Check API
echo "🌐 API Server:"
if curl -s http://localhost:8000/health > /dev/null; then
    echo "   ✅ API server is responding"
    health=$(curl -s http://localhost:8000/health | python3 -c "import sys, json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unknown")
    echo "   📊 Health status: $health"
else
    echo "   ❌ API server is not responding"
fi

echo ""

# Check Dashboard
echo "📊 Dashboard:"
if curl -s http://localhost:8501 > /dev/null; then
    echo "   ✅ Dashboard is accessible"
else
    echo "   ❌ Dashboard is not accessible"
fi

echo ""

# Check databases
echo "💾 Databases:"

# MongoDB
if curl -s http://localhost:27017 > /dev/null; then
    echo "   ✅ MongoDB is accessible"
else
    echo "   ❌ MongoDB is not accessible"
fi

# Elasticsearch
if curl -s http://localhost:9200/_cluster/health > /dev/null; then
    echo "   ✅ Elasticsearch is accessible"
    health=$(curl -s http://localhost:9200/_cluster/health | python3 -c "import sys, json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unknown")
    echo "   📊 Elasticsearch status: $health"
else
    echo "   ❌ Elasticsearch is not accessible"
fi

echo ""

# Check Python environment
echo "🐍 Python Environment:"
if [ -f "venv/bin/activate" ]; then
    echo "   ✅ Virtual environment exists"
    source venv/bin/activate
    echo "   📊 Python version: $(python --version)"
    
    # Check key packages
    if python -c "import spacy" 2>/dev/null; then
        echo "   ✅ spaCy is installed"
    else
        echo "   ❌ spaCy is not installed"
    fi
    
    if python -c "import fastapi" 2>/dev/null; then
        echo "   ✅ FastAPI is installed"
    else
        echo "   ❌ FastAPI is not installed"
    fi
    
    if python -c "import streamlit" 2>/dev/null; then
        echo "   ✅ Streamlit is installed"
    else
        echo "   ❌ Streamlit is not installed"
    fi
else
    echo "   ❌ Virtual environment not found"
fi

echo ""
echo "==============================="
echo "Health check complete!"
```

## 🔧 macOS-Specific Troubleshooting

### Common macOS Issues

#### 1. Docker Desktop Not Starting
```bash
# Reset Docker Desktop
rm -rf ~/Library/Group\ Containers/group.com.docker
rm -rf ~/Library/Containers/com.docker.docker
rm -rf ~/.docker

# Restart Docker Desktop from Applications
```

#### 2. Port Conflicts on macOS
```bash
# Check what's using the ports
lsof -i :8000  # API port
lsof -i :8501  # Dashboard port
lsof -i :9200  # Elasticsearch port
lsof -i :27017 # MongoDB port

# Kill processes if needed
sudo kill -9 <PID>
```

#### 3. Permission Issues
```bash
# Fix file permissions
chmod +x scripts/*.sh
chmod 600 .env
chmod -R 755 logs/

# If you get permission denied for Docker
sudo chown -R $(whoami) ~/.docker
```

#### 4. Python/Pip Issues on macOS
```bash
# If pip install fails, try:
pip install --upgrade pip setuptools wheel

# For M1/M2 Macs, you might need:
pip install --no-cache-dir -r requirements.txt

# If spaCy model download fails:
python -m pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.0/en_core_web_sm-3.7.0-py3-none-any.whl
```

#### 5. macOS Firewall Issues
```bash
# Check if firewall is blocking connections
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Add Python to firewall exceptions if needed
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/bin/python3
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblock /usr/bin/python3
```

### Performance Optimization for macOS

#### 1. Docker Desktop Settings
1. Open Docker Desktop
2. Go to Settings → Resources
3. Set Memory to at least 4GB
4. Set CPU to at least 2 cores
5. Click "Apply & Restart"

#### 2. macOS System Settings
```bash
# Increase file descriptor limits
echo "kern.maxfiles=65536" | sudo tee -a /etc/sysctl.conf
echo "kern.maxfilesperproc=32768" | sudo tee -a /etc/sysctl.conf

# Apply changes (requires restart)
sudo sysctl -w kern.maxfiles=65536
sudo sysctl -w kern.maxfilesperproc=32768
```

## 📱 macOS Menu Bar Integration

### Create Launch Agents (Optional)

Create a macOS Launch Agent for auto-startup:

```bash
# Create launch agent directory
mkdir -p ~/Library/LaunchAgents

# Create plist file
cat > ~/Library/LaunchAgents/com.ctms.api.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ctms.api</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/your/project/scripts/start_macos.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load the launch agent
launchctl load ~/Library/LaunchAgents/com.ctms.api.plist
```

## 🚀 Quick Start Commands for macOS

```bash
# One-line setup (after cloning repo)
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && cp .env.example .env

# One-line start (after configuration)
docker-compose up -d && sleep 20 && python -m ctms.api.main &; streamlit run ctms/dashboard/main_dashboard.py

# One-line stop
docker-compose down && pkill -f "ctms.api.main" && pkill -f "streamlit"

# One-line health check
curl http://localhost:8000/health && echo ""
```

## 🎯 macOS Native Features

### Use with macOS Shortcuts
Create a Shortcuts app automation:
1. Open Shortcuts app
2. Create new shortcut
3. Add "Run Shell Script" action
4. Paste: `cd /path/to/ctms && ./scripts/start_macos.sh`
5. Save as "Start CTMS"

### Integration with macOS Notifications
The system can send native macOS notifications. Configure in your `.env`:

```bash
# Enable macOS notifications
MACOS_NOTIFICATIONS=true
```

This guide should get you up and running on macOS smoothly! Let me know if you encounter any Mac-specific issues.
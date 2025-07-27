#!/bin/bash

# =============================================================================
# CYBER THREAT MONITORING SYSTEM - LINUX START SCRIPT
# =============================================================================
# Professional startup script for Linux environments

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐧 Starting Cyber Threat Monitoring System on Linux...${NC}"
echo "======================================================="

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${YELLOW}🐳 Starting Docker service...${NC}"
    sudo systemctl start docker
    sleep 5
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}❌ Virtual environment not found! Please run ./scripts/setup_linux.sh first${NC}"
    exit 1
fi

# Activate virtual environment
echo -e "${YELLOW}🐍 Activating Python virtual environment...${NC}"
source venv/bin/activate

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}🔑 Creating .env file from template...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${YELLOW}⚠️  Please edit .env file with your configuration${NC}"
    else
        echo -e "${RED}❌ .env.example file not found!${NC}"
        exit 1
    fi
fi

# Check if spaCy model is downloaded
echo -e "${YELLOW}🧠 Checking spaCy language model...${NC}"
if ! python -c "import spacy; spacy.load('en_core_web_sm')" >/dev/null 2>&1; then
    echo -e "${YELLOW}📥 Downloading spaCy language model...${NC}"
    python -m spacy download en_core_web_sm
fi

# Start Docker services
echo -e "${YELLOW}🐳 Starting Docker services...${NC}"
docker-compose up -d

# Wait for services to be ready
echo -e "${YELLOW}⏳ Waiting for services to start...${NC}"
sleep 10

# Check service health
echo -e "${YELLOW}🏥 Checking service health...${NC}"

# Check MongoDB
echo -n "  📊 MongoDB: "
if docker-compose exec mongodb mongosh --eval "db.runCommand('ping')" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Running${NC}"
else
    echo -e "${RED}❌ Not responding${NC}"
fi

# Check Elasticsearch
echo -n "  🔍 Elasticsearch: "
if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Running${NC}"
else
    echo -e "${RED}❌ Not responding${NC}"
fi

# Check Redis
echo -n "  💾 Redis: "
if docker-compose exec redis redis-cli ping >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Running${NC}"
else
    echo -e "${RED}❌ Not responding${NC}"
fi

# Check TOR Proxy
echo -n "  🌐 TOR Proxy: "
if docker-compose ps tor-proxy | grep -q "Up"; then
    echo -e "${GREEN}✅ Running${NC}"
else
    echo -e "${RED}❌ Not responding${NC}"
fi

# Initialize database if needed
echo -e "${YELLOW}🔧 Initializing database...${NC}"
python -c "
import asyncio
from ctms.database.connection import initialize_database

async def init():
    try:
        await initialize_database()
        print('✅ Database initialized successfully')
    except Exception as e:
        print(f'❌ Database initialization failed: {e}')

asyncio.run(init())
" || echo -e "${YELLOW}⚠️  Database may need manual initialization${NC}"

# Start API server in background
echo -e "${YELLOW}🚀 Starting API server...${NC}"
uvicorn ctms.api.main:app --host 0.0.0.0 --port 8000 --reload > logs/api.log 2>&1 &
API_PID=$!
echo "API server PID: $API_PID"

# Wait for API to start
sleep 5

# Check API health
echo -n "  🌐 API Server: "
if curl -s http://localhost:8000/health >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Running (http://localhost:8000)${NC}"
else
    echo -e "${RED}❌ Not responding${NC}"
fi

# Start Dashboard in background
echo -e "${YELLOW}📊 Starting Dashboard...${NC}"
streamlit run ctms/dashboard/main.py --server.port 8501 --server.address 0.0.0.0 > logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "Dashboard PID: $DASHBOARD_PID"

# Wait for Dashboard to start
sleep 10

# Check Dashboard health
echo -n "  📈 Dashboard: "
if curl -s http://localhost:8501 >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Running (http://localhost:8501)${NC}"
else
    echo -e "${RED}❌ Not responding${NC}"
fi

# Save PIDs for later cleanup
echo "$API_PID" > .api.pid
echo "$DASHBOARD_PID" > .dashboard.pid

echo ""
echo -e "${GREEN}🎉 Cyber Threat Monitoring System started successfully!${NC}"
echo ""
echo -e "${BLUE}📋 System Information:${NC}"
echo "  🌐 API Server:    http://localhost:8000"
echo "  📊 Dashboard:     http://localhost:8501"
echo "  📚 API Docs:      http://localhost:8000/docs"
echo "  🏥 Health Check:  http://localhost:8000/health"
echo ""
echo -e "${BLUE}🔧 Management Commands:${NC}"
echo "  Stop System:      ./scripts/stop_linux.sh"
echo "  Health Check:     ./scripts/health_check_linux.sh"
echo "  View API Logs:    tail -f logs/api.log"
echo "  View Dashboard:   tail -f logs/dashboard.log"
echo ""
echo -e "${BLUE}🎯 OpenCTI-Inspired Features:${NC}"
echo "  📦 STIX Import:   POST /api/v1/stix/import"
echo "  📤 STIX Export:   GET /api/v1/stix/export"
echo "  🔌 Connectors:    GET /api/v1/connectors"
echo "  🎯 MITRE ATT&CK:  POST /api/v1/connectors/mitre/start"
echo ""
echo -e "${YELLOW}💡 To stop the system, run: ./scripts/stop_linux.sh${NC}"
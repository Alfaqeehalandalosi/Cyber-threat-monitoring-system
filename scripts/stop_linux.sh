#!/bin/bash

# =============================================================================
# CYBER THREAT MONITORING SYSTEM - LINUX STOP SCRIPT
# =============================================================================
# Professional stop script for Linux environments

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐧 Stopping Cyber Threat Monitoring System on Linux...${NC}"
echo "======================================================="

# Stop API server
if [ -f ".api.pid" ]; then
    API_PID=$(cat .api.pid)
    echo -e "${YELLOW}🛑 Stopping API server (PID: $API_PID)...${NC}"
    if kill $API_PID 2>/dev/null; then
        echo -e "${GREEN}✅ API server stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  API server was not running${NC}"
    fi
    rm -f .api.pid
else
    echo -e "${YELLOW}⚠️  No API PID file found${NC}"
fi

# Stop Dashboard
if [ -f ".dashboard.pid" ]; then
    DASHBOARD_PID=$(cat .dashboard.pid)
    echo -e "${YELLOW}🛑 Stopping Dashboard (PID: $DASHBOARD_PID)...${NC}"
    if kill $DASHBOARD_PID 2>/dev/null; then
        echo -e "${GREEN}✅ Dashboard stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  Dashboard was not running${NC}"
    fi
    rm -f .dashboard.pid
else
    echo -e "${YELLOW}⚠️  No Dashboard PID file found${NC}"
fi

# Stop any remaining Python processes
echo -e "${YELLOW}🔄 Stopping remaining Python processes...${NC}"
pkill -f "uvicorn ctms.api.main:app" 2>/dev/null || true
pkill -f "streamlit run ctms/dashboard/main.py" 2>/dev/null || true

# Stop Docker services
echo -e "${YELLOW}🐳 Stopping Docker services...${NC}"
docker-compose down

# Clean up log files if requested
read -p "Do you want to clear log files? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}🧹 Clearing log files...${NC}"
    rm -f logs/*.log
    echo -e "${GREEN}✅ Log files cleared${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Cyber Threat Monitoring System stopped successfully!${NC}"
echo ""
echo -e "${BLUE}📋 System Status:${NC}"
echo "  🌐 API Server:    ❌ Stopped"
echo "  📊 Dashboard:     ❌ Stopped"
echo "  🐳 Docker:        ❌ Stopped"
echo ""
echo -e "${YELLOW}💡 To start the system again, run: ./scripts/start_linux.sh${NC}"
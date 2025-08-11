#!/bin/bash

# =============================================================================
# REAL DATA DASHBOARD STARTUP SCRIPT
# =============================================================================
# This script starts the real data dashboard with web scraping capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  Cyber Threat Monitoring System - Real Data Dashboard${NC}"
echo -e "${BLUE}=====================================================${NC}"

# Check if we're in the right directory
if [ ! -f "ctms/dashboard/real_data_dashboard.py" ]; then
    echo -e "${RED}❌ Error: real_data_dashboard.py not found${NC}"
    echo -e "${YELLOW}💡 Make sure you're in the project root directory${NC}"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "ctms_env" ]; then
    echo -e "${YELLOW}📦 Creating virtual environment...${NC}"
    python3 -m venv ctms_env
fi

# Activate virtual environment
echo -e "${BLUE}🔧 Activating virtual environment...${NC}"
source ctms_env/bin/activate

# Install additional dependencies for web scraping
echo -e "${BLUE}📦 Installing web scraping dependencies...${NC}"
pip install --upgrade pip
pip install aiohttp==3.9.1 feedparser==6.0.10 beautifulsoup4==4.12.2 lxml==4.9.3 requests==2.31.0

# Install dashboard dependencies
echo -e "${BLUE}📦 Installing dashboard dependencies...${NC}"
pip install streamlit plotly pandas numpy altair seaborn matplotlib

# Install spaCy for NLP
echo -e "${BLUE}🧠 Installing spaCy and language model...${NC}"
pip install spacy==3.7.2
python -m spacy download en_core_web_sm

# Check if API is running
echo -e "${BLUE}🔍 Checking API status...${NC}"
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API is running on http://localhost:8000${NC}"
else
    echo -e "${YELLOW}⚠️  API not detected on http://localhost:8000${NC}"
    echo -e "${YELLOW}💡 Make sure to start the API first with: python -m ctms.api.main${NC}"
    echo -e "${YELLOW}💡 Or use: ./start_all.sh${NC}"
fi

# Start the real data dashboard
echo -e "${GREEN}🚀 Starting Real Data Dashboard...${NC}"
echo -e "${BLUE}📊 Dashboard will be available at: http://localhost:8501${NC}"
echo -e "${BLUE}🔗 API should be running at: http://localhost:8000${NC}"
echo -e "${YELLOW}💡 Press Ctrl+C to stop the dashboard${NC}"
echo ""

# Start Streamlit with specific configuration
streamlit run ctms/dashboard/real_data_dashboard.py \
    --server.port 8501 \
    --server.address localhost \
    --server.headless true \
    --browser.gatherUsageStats false \
    --theme.base light \
    --theme.primaryColor "#1f77b4" \
    --theme.backgroundColor "#ffffff" \
    --theme.secondaryBackgroundColor "#f0f2f6" \
    --theme.textColor "#262730"
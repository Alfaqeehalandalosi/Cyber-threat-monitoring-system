#!/bin/bash

# Advanced Cyber Threat Monitoring Dashboard Startup Script
# ========================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️ Advanced Cyber Threat Monitoring Dashboard${NC}"
echo -e "${BLUE}===============================================${NC}"

# Check if virtual environment exists
if [ ! -d "ctms_env" ]; then
    echo -e "${YELLOW}⚠️ Virtual environment not found. Creating one...${NC}"
    python3 -m venv ctms_env
fi

# Activate virtual environment
echo -e "${BLUE}📦 Activating virtual environment...${NC}"
source ctms_env/bin/activate

# Install additional dependencies for advanced dashboard
echo -e "${BLUE}📦 Installing advanced dashboard dependencies...${NC}"
pip install --upgrade pip
pip install streamlit plotly pandas numpy altair

# Check if spaCy model is installed
if ! python -c "import spacy; spacy.load('en_core_web_sm')" 2>/dev/null; then
    echo -e "${YELLOW}⚠️ spaCy English model not found. Installing...${NC}"
    python -m spacy download en_core_web_sm
fi

# Start the advanced dashboard
echo -e "${GREEN}🚀 Starting Advanced Cyber Threat Monitoring Dashboard...${NC}"
echo -e "${BLUE}📍 Dashboard will be available at: http://localhost:8501${NC}"
echo -e "${BLUE}🔧 API should be running at: http://localhost:8000${NC}"
echo -e "${YELLOW}💡 Make sure the API server is running in another terminal${NC}"
echo ""

# Start Streamlit with advanced dashboard
streamlit run ctms/dashboard/advanced_dashboard.py \
    --server.port 8501 \
    --server.address localhost \
    --server.headless true \
    --browser.gatherUsageStats false \
    --theme.base light \
    --theme.primaryColor "#667eea" \
    --theme.backgroundColor "#ffffff" \
    --theme.secondaryBackgroundColor "#f0f2f6" \
    --theme.textColor "#262730"
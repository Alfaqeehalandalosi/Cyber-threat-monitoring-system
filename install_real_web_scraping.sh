#!/bin/bash

# =============================================================================
# REAL WEB SCRAPING INSTALLATION SCRIPT
# =============================================================================
# This script adds real web scraping capabilities to your existing CTMS project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🕷️  Installing Real Web Scraping for CTMS${NC}"
echo -e "${BLUE}=============================================${NC}"

# Check if we're in the right directory
if [ ! -f "ctms/api/main.py" ]; then
    echo -e "${RED}❌ Error: CTMS project not found${NC}"
    echo -e "${YELLOW}💡 Make sure you're in the project root directory${NC}"
    exit 1
fi

# Activate virtual environment if it exists
if [ -d "ctms_env" ]; then
    echo -e "${BLUE}🔧 Activating virtual environment...${NC}"
    source ctms_env/bin/activate
else
    echo -e "${YELLOW}⚠️  Virtual environment not found. Creating one...${NC}"
    python3 -m venv ctms_env
    source ctms_env/bin/activate
fi

# Install web scraping dependencies
echo -e "${BLUE}📦 Installing web scraping dependencies...${NC}"
pip install --upgrade pip
pip install aiohttp==3.9.1 feedparser==6.0.10 beautifulsoup4==4.12.2 lxml==4.9.3 requests==2.31.0

# Create necessary directories
echo -e "${BLUE}📁 Creating directories...${NC}"
mkdir -p ctms/config
mkdir -p ctms/scraping
mkdir -p ctms/api

echo -e "${GREEN}✅ Installation completed!${NC}"
echo ""
echo -e "${BLUE}🚀 Next steps:${NC}"
echo -e "${YELLOW}1. Start the API: python -m ctms.api.main${NC}"
echo -e "${YELLOW}2. Start real data dashboard: ./start_real_data_dashboard.sh${NC}"
echo -e "${YELLOW}3. Or use: streamlit run ctms/dashboard/real_data_dashboard.py${NC}"
echo ""
echo -e "${GREEN}🎉 Real web scraping is now ready!${NC}"
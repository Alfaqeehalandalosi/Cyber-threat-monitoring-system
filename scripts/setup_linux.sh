#!/bin/bash

# =============================================================================
# CYBER THREAT MONITORING SYSTEM - LINUX SETUP SCRIPT
# =============================================================================
# Professional setup script for Linux environments

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐧 Setting up Cyber Threat Monitoring System on Linux...${NC}"
echo "========================================================"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ This script should not be run as root${NC}"
   exit 1
fi

# Update system packages
echo -e "${YELLOW}📦 Updating system packages...${NC}"
sudo apt update

# Install required system packages
echo -e "${YELLOW}🔧 Installing system dependencies...${NC}"
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    curl \
    wget \
    docker.io \
    docker-compose \
    build-essential \
    libssl-dev \
    libffi-dev \
    pkg-config \
    libpq-dev

# Start and enable Docker
echo -e "${YELLOW}🐳 Starting Docker service...${NC}"
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER

# Create Python virtual environment
echo -e "${YELLOW}🐍 Creating Python virtual environment...${NC}"
python3 -m venv venv

# Activate virtual environment
echo -e "${YELLOW}🔄 Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip and setuptools
echo -e "${YELLOW}⬆️ Upgrading pip and setuptools...${NC}"
pip install --upgrade pip setuptools wheel

# Install Python dependencies
echo -e "${YELLOW}📚 Installing Python dependencies...${NC}"
if [ -f "requirements-macos.txt" ]; then
    echo "Using requirements-macos.txt (flexible versions)..."
    pip install -r requirements-macos.txt
elif [ -f "requirements.txt" ]; then
    echo "Using requirements.txt..."
    pip install -r requirements.txt
else
    echo -e "${RED}❌ No requirements file found!${NC}"
    exit 1
fi

# Download spaCy model
echo -e "${YELLOW}🧠 Downloading spaCy language model...${NC}"
python -m spacy download en_core_web_sm

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}🔑 Creating .env configuration file...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        
        # Generate secure keys
        JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
        ENCRYPTION_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
        
        # Update .env with generated keys
        sed -i "s/your-secret-jwt-key-here/$JWT_SECRET/g" .env
        sed -i "s/your-encryption-key-here/$ENCRYPTION_KEY/g" .env
        
        echo -e "${GREEN}✅ Generated secure JWT and encryption keys${NC}"
    else
        echo -e "${RED}❌ .env.example file not found!${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ .env file already exists${NC}"
fi

# Make scripts executable
echo -e "${YELLOW}🔧 Making scripts executable...${NC}"
chmod +x scripts/*.sh

# Create necessary directories
echo -e "${YELLOW}📁 Creating necessary directories...${NC}"
mkdir -p logs data/scraped data/models

# Test Python environment
echo -e "${YELLOW}🧪 Testing Python environment...${NC}"
python -c "
import sys
print(f'Python version: {sys.version}')

# Test core imports
try:
    import fastapi
    import uvicorn
    import streamlit
    import pymongo
    import elasticsearch
    import spacy
    print('✅ All core dependencies imported successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"

echo ""
echo -e "${GREEN}🎉 Setup completed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "1. Start Docker services: docker-compose up -d"
echo "2. Start the system: ./scripts/start_linux.sh"
echo "3. Access the dashboard: http://localhost:8501"
echo "4. Access the API: http://localhost:8000"
echo ""
echo -e "${YELLOW}⚠️  Note: You may need to log out and back in for Docker group permissions to take effect${NC}"
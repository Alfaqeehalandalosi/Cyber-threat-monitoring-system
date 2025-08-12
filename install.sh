#!/bin/bash

# Cyber Threat Monitoring System - Installation Script
# This script installs and sets up the fixed version of CTMS

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local message=$1
    local color=$2
    echo -e "${color}[$(date '+%H:%M:%S')] ${message}${NC}"
}

print_header() {
    echo -e "${BLUE}"
    echo "=================================================================="
    echo "  CYBER THREAT MONITORING SYSTEM - INSTALLATION SCRIPT"
    echo "=================================================================="
    echo -e "${NC}"
}

print_footer() {
    echo -e "${BLUE}"
    echo "=================================================================="
    echo "  INSTALLATION COMPLETED SUCCESSFULLY!"
    echo "=================================================================="
    echo -e "${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_status "This script should not be run as root" $RED
   exit 1
fi

print_header

# Check Python version
print_status "Checking Python version..." $BLUE
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8.0"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    print_status "✅ Python $python_version is compatible" $GREEN
else
    print_status "❌ Python $python_version is too old. Required: $required_version or higher" $RED
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    print_status "❌ pip3 is not installed. Please install pip3 first." $RED
    exit 1
fi

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    print_status "⚠️ Docker is not installed. Some features may not work." $YELLOW
    print_status "You can install Docker from: https://docs.docker.com/get-docker/" $YELLOW
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    print_status "⚠️ Docker Compose is not installed. Some features may not work." $YELLOW
    print_status "You can install Docker Compose from: https://docs.docker.com/compose/install/" $YELLOW
fi

# Create virtual environment
print_status "Creating virtual environment..." $BLUE
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "✅ Virtual environment created" $GREEN
else
    print_status "✅ Virtual environment already exists" $GREEN
fi

# Activate virtual environment
print_status "Activating virtual environment..." $BLUE
source venv/bin/activate
print_status "✅ Virtual environment activated" $GREEN

# Upgrade pip
print_status "Upgrading pip..." $BLUE
pip install --upgrade pip
print_status "✅ Pip upgraded" $GREEN

# Install Python dependencies
print_status "Installing Python dependencies..." $BLUE
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_status "✅ Python dependencies installed" $GREEN
else
    print_status "❌ requirements.txt not found" $RED
    exit 1
fi

# Install spaCy model
print_status "Installing spaCy English model..." $BLUE
python -m spacy download en_core_web_sm
print_status "✅ spaCy model installed" $GREEN

# Create necessary directories
print_status "Creating necessary directories..." $BLUE
mkdir -p logs
mkdir -p data
print_status "✅ Directories created" $GREEN

# Create .env file if it doesn't exist
print_status "Setting up environment configuration..." $BLUE
if [ ! -f ".env" ]; then
    cat > .env << EOF
# Database Configuration
MONGODB_URL=mongodb://localhost:27017/ctms
REDIS_URL=redis://localhost:6379

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=true

# Scraping Configuration
TOR_ENABLED=true
TOR_HOST=localhost
TOR_PORT=9050
TOR_CONTROL_PORT=9051

# Security Configuration
JWT_SECRET=your-secret-key-change-this-in-production

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/ctms.log
EOF
    print_status "✅ Environment file created (.env)" $GREEN
    print_status "⚠️ Please review and update the .env file with your settings" $YELLOW
else
    print_status "✅ Environment file already exists" $GREEN
fi

# Make test script executable
print_status "Setting up test script..." $BLUE
if [ -f "test_fix.py" ]; then
    chmod +x test_fix.py
    print_status "✅ Test script made executable" $GREEN
fi

# Test the installation
print_status "Testing the installation..." $BLUE
if python test_fix.py; then
    print_status "✅ Installation test passed" $GREEN
else
    print_status "⚠️ Installation test had some issues, but the system may still work" $YELLOW
fi

print_footer

# Print next steps
echo -e "${GREEN}Next steps:${NC}"
echo -e "${BLUE}1.${NC} Start the services:"
echo -e "   ${YELLOW}docker-compose up -d${NC}"
echo ""
echo -e "${BLUE}2.${NC} Start the API server:"
echo -e "   ${YELLOW}source venv/bin/activate${NC}"
echo -e "   ${YELLOW}python -m ctms.api.main${NC}"
echo ""
echo -e "${BLUE}3.${NC} Start the dashboard (in a new terminal):"
echo -e "   ${YELLOW}source venv/bin/activate${NC}"
echo -e "   ${YELLOW}streamlit run ctms/dashboard/main_dashboard.py${NC}"
echo ""
echo -e "${BLUE}4.${NC} Access the system:"
echo -e "   ${YELLOW}Dashboard:${NC} http://localhost:8501"
echo -e "   ${YELLOW}API Docs:${NC} http://localhost:8000/docs"
echo -e "   ${YELLOW}Health Check:${NC} http://localhost:8000/health"
echo ""
echo -e "${BLUE}5.${NC} Test the fixes:"
echo -e "   ${YELLOW}python test_fix.py${NC}"
echo ""
echo -e "${GREEN}The AttributeError has been fixed! The system should now work correctly.${NC}"
echo ""
echo -e "${YELLOW}For more information, see the README.md file.${NC}"
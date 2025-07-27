#!/bin/bash
# =============================================================================
# macOS One-Time Setup Script for Cyber Threat Monitoring System
# =============================================================================

set -e

echo "🍎 macOS Setup for Cyber Threat Monitoring System"
echo "=================================================="
echo ""

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ This script is designed for macOS only"
    exit 1
fi

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "📦 Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for M1/M2 Macs
    if [[ $(uname -m) == "arm64" ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
    echo "✅ Homebrew installed"
else
    echo "✅ Homebrew already installed"
fi

# Install required tools
echo "🔧 Installing required tools..."

# Install Python 3.11
if ! brew list python@3.11 &> /dev/null; then
    echo "🐍 Installing Python 3.11..."
    brew install python@3.11
else
    echo "✅ Python 3.11 already installed"
fi

# Install Docker Desktop
if ! brew list --cask docker &> /dev/null; then
    echo "🐳 Installing Docker Desktop..."
    brew install --cask docker
    echo "⚠️  Please start Docker Desktop manually from Applications"
    echo "   Look for the Docker whale icon in your menu bar"
else
    echo "✅ Docker Desktop already installed"
fi

# Install Git
if ! command -v git &> /dev/null; then
    echo "📂 Installing Git..."
    brew install git
else
    echo "✅ Git already installed"
fi

# Install additional tools
echo "🛠️ Installing additional tools..."
brew install curl wget || echo "Tools already installed"

echo ""
echo "🎯 Project Setup"
echo "================"

# Change to script directory
cd "$(dirname "$0")/.."

# Create Python virtual environment
if [ ! -d "venv" ]; then
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# Download spaCy model
echo "🧠 Installing spaCy English model..."
python -m spacy download en_core_web_sm

# Create environment file
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment configuration..."
    cp .env.example .env
    
    # Generate secure keys
    echo "🔐 Generating secure keys..."
    SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
    JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
    
    # Update .env file with generated keys
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/SECRET_KEY=your-super-secret-key-here-change-this-in-production/SECRET_KEY=$SECRET_KEY/" .env
        sed -i '' "s/JWT_SECRET_KEY=your-jwt-secret-key-change-this/JWT_SECRET_KEY=$JWT_SECRET_KEY/" .env
    fi
    
    echo "✅ Environment file created with secure keys"
else
    echo "✅ Environment file already exists"
fi

# Create logs directory
mkdir -p logs

# Make scripts executable
chmod +x scripts/*.sh

echo ""
echo "🐳 Docker Setup Check"
echo "====================="

# Check if Docker is running
if docker info > /dev/null 2>&1; then
    echo "✅ Docker is running"
    
    # Test Docker Compose
    echo "🧪 Testing Docker Compose..."
    docker-compose --version
    echo "✅ Docker Compose is working"
    
else
    echo "⚠️  Docker is not running"
    echo "   Please start Docker Desktop from Applications"
    echo "   Wait for the whale icon to appear in your menu bar"
    echo "   Then run this script again or proceed to start the system"
fi

echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "Next steps:"
echo "1. Make sure Docker Desktop is running (whale icon in menu bar)"
echo "2. Review and customize .env file if needed:"
echo "   nano .env"
echo ""
echo "3. Start the system:"
echo "   ./scripts/start_macos.sh"
echo ""
echo "🌐 Once running, access:"
echo "   Dashboard: http://localhost:8501"
echo "   API Docs:  http://localhost:8000/docs"
echo ""
echo "🔑 Default login: admin/admin"
echo ""

# Optional: Open Docker Desktop if not running
if ! docker info > /dev/null 2>&1; then
    echo "🚀 Would you like to open Docker Desktop now? (y/n)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        open -a Docker
        echo "🐳 Docker Desktop is starting..."
        echo "   Wait for the whale icon to appear and stop animating"
        echo "   Then run: ./scripts/start_macos.sh"
    fi
fi
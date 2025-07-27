#!/bin/bash
# =============================================================================
# macOS Startup Script for Cyber Threat Monitoring System
# =============================================================================

set -e

echo "🍎 Starting Cyber Threat Monitoring System on macOS..."
echo "======================================================="

# Change to script directory
cd "$(dirname "$0")/.."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop first."
    echo "   You can find it in Applications or click the Docker whale icon in the menu bar"
    echo "   After starting Docker Desktop, wait for the whale icon to stop animating"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Creating one now..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
echo "🐍 Activating Python virtual environment..."
source venv/bin/activate

# Check if requirements are installed
if ! python -c "import fastapi, streamlit, spacy" 2>/dev/null; then
    echo "📦 Installing Python dependencies..."
    pip install --upgrade pip setuptools wheel
    
    # Try macOS-specific requirements first, fall back to main requirements
    if [ -f "requirements-macos.txt" ]; then
        echo "Using macOS-optimized requirements..."
        pip install -r requirements-macos.txt
    else
        echo "Using standard requirements..."
        pip install -r requirements.txt
    fi
    echo "✅ Dependencies installed"
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚙️ Environment file not found. Creating from template..."
    cp .env.example .env
    echo "❗ IMPORTANT: Please edit .env file with your configuration before continuing"
    echo "   Required changes:"
    echo "   - SECRET_KEY: Set a secure secret key"
    echo "   - JWT_SECRET_KEY: Set a secure JWT key"
    echo "   - MONGODB_URL: Update if needed"
    echo ""
    read -p "Press Enter after configuring .env file..."
fi

# Check if spaCy model is installed
if ! python -c "import spacy; nlp = spacy.load('en_core_web_sm')" 2>/dev/null; then
    echo "📚 Installing spaCy English model..."
    python -m spacy download en_core_web_sm
    echo "✅ spaCy model installed"
fi

# Create logs directory if it doesn't exist
mkdir -p logs

# Start infrastructure services
echo "🚀 Starting infrastructure services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to initialize..."
sleep 10

# Function to check service health
check_service() {
    local service_name=$1
    local url=$2
    local max_attempts=30
    local attempt=1
    
    echo "🔍 Checking $service_name..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$url" > /dev/null 2>&1; then
            echo "✅ $service_name is ready"
            return 0
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            echo "❌ $service_name failed to start after $max_attempts attempts"
            return 1
        fi
        
        echo "   Attempt $attempt/$max_attempts - waiting for $service_name..."
        sleep 2
        ((attempt++))
    done
}

# Check Elasticsearch
if ! check_service "Elasticsearch" "http://localhost:9200/_cluster/health"; then
    echo "❌ Failed to start Elasticsearch. Check Docker logs:"
    echo "   docker-compose logs elasticsearch"
    exit 1
fi

# Check MongoDB
if ! check_service "MongoDB" "http://localhost:27017"; then
    echo "❌ Failed to start MongoDB. Check Docker logs:"
    echo "   docker-compose logs mongodb"
    exit 1
fi

# Initialize database
echo "💾 Initializing database..."
python -c "
import asyncio
from ctms.database.connection import initialize_databases

async def main():
    try:
        await initialize_databases()
        print('✅ Database initialized successfully!')
    except Exception as e:
        print(f'❌ Database initialization failed: {e}')
        exit(1)

asyncio.run(main())
" || {
    echo "❌ Database initialization failed"
    exit 1
}

# Start API server in background
echo "🚀 Starting API server..."
python -m ctms.api.main > logs/api.log 2>&1 &
API_PID=$!

# Wait for API to be ready
echo "⏳ Waiting for API server to start..."
sleep 5

if ! check_service "API Server" "http://localhost:8000/health"; then
    echo "❌ API server failed to start. Check logs:"
    echo "   tail -f logs/api.log"
    kill $API_PID 2>/dev/null || true
    exit 1
fi

# Display system information
echo ""
echo "🌐 System URLs:"
echo "   Dashboard:  http://localhost:8501"
echo "   API Docs:   http://localhost:8000/docs"
echo "   API Health: http://localhost:8000/health"
echo ""
echo "🔑 Default Login:"
echo "   Username: admin"
echo "   Password: admin"
echo ""
echo "📊 Starting Streamlit dashboard..."
echo "   The dashboard will open in your browser automatically"
echo ""
echo "💡 Tips:"
echo "   - Press Ctrl+C to stop all services"
echo "   - Check logs/ directory for application logs"
echo "   - Use 'docker-compose logs' to view service logs"
echo ""

# Start Streamlit dashboard (this will block)
streamlit run ctms/dashboard/main_dashboard.py

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    
    # Kill API server
    if [ ! -z "$API_PID" ]; then
        kill $API_PID 2>/dev/null || true
        echo "   ✅ API server stopped"
    fi
    
    # Stop Docker services
    docker-compose down
    echo "   ✅ Docker services stopped"
    
    echo "✅ Shutdown complete"
    echo "   Thanks for using Cyber Threat Monitoring System!"
}

# Set up cleanup on script exit
trap cleanup EXIT INT TERM
# 🍎 Quick Start for macOS

## Super Simple Setup (5 minutes)

### 1. One-Time Setup
```bash
# Clone the repo
git clone <this-repo>
cd cyber-threat-monitoring-system

# Run the setup script (installs everything automatically)
./scripts/setup_macos.sh
```

The setup script will:
- ✅ Install Homebrew (if needed)
- ✅ Install Python, Docker, Git
- ✅ Create virtual environment
- ✅ Install all Python packages
- ✅ Download AI models
- ✅ Generate secure configuration
- ✅ Make everything ready to run

### 2. Start the System
```bash
# Start everything with one command
./scripts/start_macos.sh
```

This will:
- ✅ Start all databases and services
- ✅ Launch the API server
- ✅ Open the dashboard in your browser
- ✅ Show you all the URLs

### 3. Access the System

The dashboard will automatically open at: **http://localhost:8501**

- **Username**: `admin`
- **Password**: `admin`

### 4. Stop the System
Press `Ctrl+C` in the terminal where you ran the start script.

## 🎯 That's It!

No configuration needed, no Docker commands to remember, no complex setup.

## 📱 What You Get

### Dashboard Features
- 📊 Real-time threat monitoring
- 🔍 IOC (Indicator of Compromise) analysis  
- 🧠 AI-powered text analysis for threats
- 📈 Threat trend visualization
- 🚨 Alert management
- ⚙️ System administration

### Example: Analyze Text for Threats
1. Go to **IOC Analysis** → **Quick Analysis**
2. Paste any suspicious text, email, or log
3. Get instant threat detection and IOC extraction

### Example: Monitor Threats
1. Go to **Overview** to see threat statistics
2. Check **Threat Intelligence** for detailed analysis
3. View **Alerts** for active security incidents

## 🛠 Troubleshooting

### Docker Not Starting?
```bash
# Open Docker Desktop manually
open -a Docker

# Wait for whale icon in menu bar, then try again
./scripts/start_macos.sh
```

### Port Already in Use?
```bash
# Check what's using the port
lsof -i :8000
lsof -i :8501

# Kill the process and try again
sudo kill -9 <PID>
```

### Python Package Issues (cryptography, etc.)?
```bash
# Fix dependency issues automatically
./scripts/fix_dependencies_macos.sh

# Or try manual fix
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install "cryptography>=40.0.0" --no-cache-dir
pip install -r requirements-macos.txt
```

### Need to Reset Everything?
```bash
# Stop all services
docker-compose down

# Remove virtual environment
rm -rf venv

# Run setup again
./scripts/setup_macos.sh
```

## 🚀 Advanced Usage

### Add Your Own Threat Sources
1. Go to **Administration** → **Sources**
2. Click **Add New Source**
3. Enter URL and configuration
4. Enable and run scraping

### Configure Notifications
Edit `.env` file:
```bash
# Email alerts
SMTP_SERVER=smtp.gmail.com
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Slack alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

### API Access
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

Example API usage:
```bash
# Get system health
curl http://localhost:8000/health

# Search for threats (need auth token)
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     "http://localhost:8000/api/v1/search?q=malware"
```

## 📞 Need Help?

1. Check the logs: `tail -f logs/ctms.log`
2. Check Docker logs: `docker-compose logs`
3. Run health check: `./scripts/health_check_macos.sh`
4. See full documentation: [README.md](README.md)

---

**🔒 Security Note**: This setup uses default credentials and is intended for development/testing. For production use, change all passwords and API keys in the `.env` file.
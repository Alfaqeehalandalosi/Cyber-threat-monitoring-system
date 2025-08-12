# 🚀 Download & Setup Instructions

## Quick Start Guide for Hacker-Grade Threat Intelligence System

### 📋 What You Need
- **Git** installed on your computer
- **GitHub account** (free)
- **Python 3.8 or higher**
- **Basic command line knowledge**

---

## 🎯 Method 1: Create Your Own Repository (Recommended)

### Step 1: Create GitHub Repository
1. Go to [GitHub.com](https://github.com) and sign in
2. Click the **"+"** button → **"New repository"**
3. Fill in:
   - **Repository name**: `hacker-grade-threat-intelligence`
   - **Description**: `Advanced threat monitoring for cybersecurity research`
   - **Visibility**: Public or Private
   - **Check**: "Add a README file"
   - **License**: MIT License
4. Click **"Create repository"**

### Step 2: Download to Your Computer
```bash
# Download the repository
git clone https://github.com/YOUR_USERNAME/hacker-grade-threat-intelligence.git

# Go into the folder
cd hacker-grade-threat-intelligence
```

### Step 3: Add All Files
Copy all the files from this conversation into your folder. You need to create these files:

**Main Files:**
- `README.md` - Project overview
- `requirements.txt` - Python packages needed
- `setup_hacker_grade_system.py` - Setup script
- `run_hacker_grade_system.py` - System runner
- `hacker_grade_dashboard.py` - Dashboard
- `.env.example` - Configuration template
- `.gitignore` - Git ignore rules

**Core System Files:**
- `ctms/main.py` - Main application
- `ctms/config/hacker_sources.py` - Source configurations
- `ctms/scraping/hacker_grade_scraper.py` - Advanced scraper
- `ctms/analysis/hacker_grade_analyzer.py` - Threat analyzer
- `ctms/api/hacker_grade_endpoints.py` - API endpoints

**Documentation:**
- `DEPLOYMENT_GUIDE.md` - How to use the system
- `CONTRIBUTING.md` - How to contribute
- `GITHUB_SETUP.md` - GitHub setup guide

### Step 4: Upload to GitHub
```bash
# Add all files
git add .

# Save changes
git commit -m "Add Hacker-Grade Threat Intelligence System"

# Upload to GitHub
git push origin main
```

---

## 🎯 Method 2: Manual Setup

### Step 1: Create Folder Structure
```bash
# Create main folder
mkdir hacker-grade-threat-intelligence
cd hacker-grade-threat-intelligence

# Create subfolders
mkdir -p ctms/{config,scraping,analysis,api,database,logs,models,data,cache}
mkdir scripts config docs
```

### Step 2: Create Each File
Create each file with the content from this conversation. Start with:

1. **Copy the content** from each file in this conversation
2. **Create the file** in your folder
3. **Paste the content** and save

### Step 3: Initialize Git
```bash
# Start git repository
git init

# Add all files
git add .

# First save
git commit -m "Initial commit: Hacker-Grade Threat Intelligence System"
```

---

## 🚀 Quick Setup After Download

### Step 1: Install Dependencies
```bash
# Install Python packages
pip install -r requirements.txt
```

### Step 2: Configure System
```bash
# Copy configuration template
cp .env.example .env

# Edit configuration (use any text editor)
nano .env
# or
code .env
# or
notepad .env
```

### Step 3: Run Setup
```bash
# Run automated setup
python setup_hacker_grade_system.py
```

### Step 4: Start System
```bash
# Start everything
python run_hacker_grade_system.py
```

### Step 5: Access System
- **Dashboard**: http://localhost:8501
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

---

## 📁 What You Get

After setup, you'll have:

✅ **40+ Threat Sources** - Hacker forums, ransomware leaks, paste sites, GitHub  
✅ **Advanced Analysis** - ML-based threat detection and scoring  
✅ **Real-time Alerts** - Email and webhook notifications  
✅ **Interactive Dashboard** - Beautiful threat visualization  
✅ **Complete API** - 15+ endpoints for integration  
✅ **Full Documentation** - Setup, deployment, and usage guides  

---

## 🔧 Configuration Options

### Basic Configuration (.env file)
```env
# API Settings
API_HOST=localhost
API_PORT=8000
API_TOKEN=demo_token_for_development_12345

# Email Alerts
SMTP_SERVER=smtp.gmail.com
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_RECIPIENTS=security@company.com

# Webhook Alerts
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK
```

### Source Configuration
Edit `ctms/config/hacker_sources.py` to:
- Enable/disable specific sources
- Change scraping intervals
- Adjust trust levels
- Add new sources

---

## 🛠️ Troubleshooting

### Common Issues

**"Module not found" errors:**
```bash
pip install -r requirements.txt
```

**Port already in use:**
```bash
# Change ports in .env file
API_PORT=8001
DASHBOARD_PORT=8502
```

**Permission errors:**
```bash
# On Linux/Mac, make scripts executable
chmod +x run_hacker_grade_system.py
chmod +x setup_hacker_grade_system.py
```

**Python version issues:**
```bash
# Check Python version
python --version  # Should be 3.8+
```

---

## 📞 Need Help?

1. **Check the logs**: Look in `ctms/logs/` folder
2. **Read documentation**: Check `DEPLOYMENT_GUIDE.md`
3. **Test the system**: Run `python test_system.py`
4. **Check health**: Visit http://localhost:8000/health

---

## ⚠️ Important Notes

- **Educational purposes only** - Defensive security research
- **Respect rate limits** - Built-in delays for ethical scraping
- **Legal compliance** - Follow applicable laws and regulations
- **Security** - Change default tokens in production

---

## 🎉 You're Ready!

Your Hacker-Grade Threat Intelligence System is now ready to:

🔍 **Monitor 40+ threat sources**  
🚨 **Detect zero-day vulnerabilities**  
📊 **Analyze threat trends**  
⚡ **Send real-time alerts**  
📈 **Visualize threat data**  
🔧 **Integrate with other tools**  

**Happy threat hunting! 🛡️**

---

**Educational purposes only - Defensive security research**
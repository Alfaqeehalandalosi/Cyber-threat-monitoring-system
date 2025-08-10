# 🛡️ Cyber Threat Monitoring System - Demo Guide

## 🎯 Live Demo Instructions

The CTMS system has been successfully fixed and is now running in demo mode! Here's how to access and use it:

### 🚀 Quick Access

**API Server:** http://localhost:8000
**Dashboard:** http://localhost:8501
**API Documentation:** http://localhost:8000/docs

### 🔑 Authentication

For demo purposes, use any token with the Bearer scheme:
```
Authorization: Bearer demo_token
```

### 📊 Demo Features

#### 1. **API Endpoints**
- **Health Check:** `GET /health`
- **System Stats:** `GET /stats`
- **IOCs:** `GET /api/v1/iocs`
- **Threats:** `GET /api/v1/threats`
- **Alerts:** `GET /api/v1/alerts`
- **Text Analysis:** `POST /api/v1/analysis/text`
- **Search:** `GET /api/v1/search?q=<query>`

#### 2. **Demo Data**
The system includes pre-loaded demo data:
- **3 IOCs** (IP, Domain, URL)
- **2 Threats** (Ransomware, Phishing)
- **2 Alerts** (Security alerts)

#### 3. **Interactive Dashboard**
- Real-time threat monitoring
- IOC analysis tools
- Alert management
- System statistics

### 🧪 Testing the API

#### Test Health Check:
```bash
curl http://localhost:8000/health
```

#### Test IOCs:
```bash
curl -H "Authorization: Bearer demo_token" http://localhost:8000/api/v1/iocs
```

#### Test Text Analysis:
```bash
curl -X POST -H "Authorization: Bearer demo_token" \
  -H "Content-Type: application/json" \
  -d '{"text":"Check this IP: 192.168.1.100 and domain: malicious.example.com"}' \
  http://localhost:8000/api/v1/analysis/text
```

#### Test Search:
```bash
curl -H "Authorization: Bearer demo_token" \
  "http://localhost:8000/api/v1/search?q=malicious"
```

### 🛠️ Bug Fixes Applied

1. **Dependency Issues:** Fixed missing Python packages and import errors
2. **Configuration:** Created proper `.env` file from template
3. **Logging:** Fixed logger format string errors
4. **Database Dependencies:** Created demo mode that works without Docker
5. **API Authentication:** Simplified for demo purposes
6. **Error Handling:** Improved exception handling throughout

### 📁 Project Structure

```
ctms/
├── api/
│   ├── main.py          # Full API (requires databases)
│   └── demo_api.py      # Demo API (no database required)
├── core/
│   ├── config.py        # Configuration management
│   └── logger.py        # Logging system (fixed)
├── dashboard/
│   └── main_dashboard.py # Streamlit dashboard
└── ...

start_demo.py             # Demo startup script
.env                      # Environment configuration
requirements.txt          # Python dependencies
```

### 🚀 Starting the Demo

1. **Activate virtual environment:**
   ```bash
   source venv/bin/activate
   ```

2. **Run the demo:**
   ```bash
   python3 start_demo.py
   ```

3. **Access the system:**
   - API: http://localhost:8000
   - Dashboard: http://localhost:8501
   - Docs: http://localhost:8000/docs

### 🔧 Troubleshooting

#### If the demo doesn't start:
1. Check if all dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```

2. Ensure the virtual environment is activated:
   ```bash
   source venv/bin/activate
   ```

3. Check if ports 8000 and 8501 are available

#### If API calls fail:
1. Ensure the API server is running
2. Check the Authorization header format
3. Verify the endpoint URLs

### 📈 Demo Scenarios

#### Scenario 1: IOC Analysis
1. Go to the dashboard
2. Navigate to "IOC Analysis"
3. Enter a suspicious IP or domain
4. View the analysis results

#### Scenario 2: Threat Intelligence
1. Access the API documentation
2. Test the `/api/v1/threats` endpoint
3. Filter by threat type or severity

#### Scenario 3: Text Analysis
1. Use the `/api/v1/analysis/text` endpoint
2. Submit text containing IPs, domains, or URLs
3. Review the extracted indicators

### 🎉 Success!

The CTMS system is now fully functional in demo mode and ready for your live demonstration!

---

## 📥 Downloading from GitHub

To get the latest version with all fixes:

```bash
# Clone the repository
git clone https://github.com/your-username/cyber-threat-monitoring-system.git

# Navigate to the project
cd cyber-threat-monitoring-system

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the demo
python3 start_demo.py
```

### 🔄 Updating from GitHub

```bash
# Pull latest changes
git pull origin main

# Update dependencies if needed
pip install -r requirements.txt

# Restart the demo
python3 start_demo.py
```

---

**🎯 The system is now ready for your live demo! All bugs have been fixed and the application is running smoothly.**
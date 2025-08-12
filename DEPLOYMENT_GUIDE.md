# Hacker-Grade Threat Intelligence System - Deployment Guide

## 🛡️ System Overview

The Hacker-Grade Threat Intelligence System is a comprehensive threat monitoring platform designed for academic cybersecurity research. It provides advanced threat intelligence by monitoring hacker forums, ransomware leak sites, paste sites, and GitHub repositories.

**⚠️ Educational purposes only - Defensive security research**

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows
- **Python**: 3.8 or higher
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: Minimum 2GB free space
- **Network**: Internet connection for scraping

### Software Dependencies
- Python 3.8+
- pip package manager
- Git (optional, for version control)

## 🚀 Quick Start

### 1. System Setup

```bash
# Clone or download the system
git clone <repository-url>
cd hacker-grade-threat-intelligence

# Run the automated setup script
python setup_hacker_grade_system.py
```

### 2. Environment Configuration

Edit the `.env` file with your settings:

```env
# API Configuration
API_HOST=localhost
API_PORT=8000
API_TOKEN=demo_token_for_development_12345

# Email Alert Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
EMAIL_RECIPIENTS=security@company.com,admin@company.com

# Webhook Alert Configuration
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
WEBHOOK_HEADERS={"Content-Type": "application/json"}

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=ctms/logs/threat_intelligence.log

# Cache Configuration
CACHE_DURATION=300
CACHE_ENABLED=true
```

### 3. Start the System

#### Option A: Automated Startup
```bash
# Windows
start_system.bat

# Unix/Linux/Mac
./start_system.sh
```

#### Option B: Manual Startup
```bash
# Terminal 1: Start API Server
python -m uvicorn ctms.main:app --host localhost --port 8000 --reload

# Terminal 2: Start Dashboard
streamlit run hacker_grade_dashboard.py --server.port 8501
```

#### Option C: Python Runner
```bash
python run_hacker_grade_system.py
```

### 4. Access the System

- **API Documentation**: http://localhost:8000/docs
- **Dashboard**: http://localhost:8501
- **Health Check**: http://localhost:8000/health

## 🔧 Configuration

### Source Configuration

Edit `ctms/config/hacker_sources.py` to customize monitoring sources:

```python
# Enable/disable source types
HACKER_SOURCES_CONFIG = {
    "hacker_forums": {
        "enabled": True,
        "scraping_interval": 1800,  # 30 minutes
        # ... source configurations
    },
    "ransomware_leak_sites": {
        "enabled": True,
        "scraping_interval": 3600,  # 1 hour
        # ... source configurations
    },
    # ... other source types
}
```

### Threat Scoring Configuration

Customize threat scoring in `ctms/config/hacker_sources.py`:

```python
# Trust level scoring
TRUST_LEVELS = {
    "ransomware_leak": 0.9,
    "exploit_db": 0.8,
    "hacker_forum": 0.5,
    "paste_site": 0.4,
    "github": 0.7
}

# Severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 0.9,
    "high": 0.7,
    "medium": 0.5,
    "low": 0.3
}
```

### Alert Configuration

Configure alerts via the dashboard or API:

```bash
# Configure email alerts
curl -X POST "http://localhost:8000/api/v1/hacker-grade/alerts/configure" \
  -H "Authorization: Bearer demo_token_for_development_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "email_recipients": ["security@company.com"],
    "threshold": 0.8,
    "enabled": true
  }'

# Test alerts
curl -X POST "http://localhost:8000/api/v1/hacker-grade/alerts/test" \
  -H "Authorization: Bearer demo_token_for_development_12345"
```

## 📊 API Usage

### Authentication

All API endpoints require authentication:

```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
  http://localhost:8000/api/v1/hacker-grade/health
```

### Key Endpoints

#### Get Threat Intelligence
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
  http://localhost:8000/api/v1/hacker-grade/threats/intelligence
```

#### Get Zero-Day Threats
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
  http://localhost:8000/api/v1/hacker-grade/threats/zero-day
```

#### Get Ransomware Threats
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
  http://localhost:8000/api/v1/hacker-grade/threats/ransomware
```

#### Get GitHub Exploits
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
  http://localhost:8000/api/v1/hacker-grade/threats/github
```

#### Filter Threats
```bash
curl -X POST "http://localhost:8000/api/v1/hacker-grade/threats/filter" \
  -H "Authorization: Bearer demo_token_for_development_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "min_score": 0.8,
    "threat_types": ["zero_day", "exploit"],
    "time_range_hours": 24
  }'
```

## 🧪 Testing

### Run System Tests
```bash
python test_system.py
```

### Manual Testing

1. **API Health Check**:
   ```bash
   curl http://localhost:8000/health
   ```

2. **Dashboard Access**:
   - Open http://localhost:8501 in browser
   - Verify all pages load correctly

3. **Data Collection**:
   - Check logs in `ctms/logs/`
   - Verify threat data is being collected

## 🔍 Monitoring and Logs

### Log Files
- **Application Logs**: `ctms/logs/app.log`
- **System Logs**: `ctms/logs/system.log`
- **Threat Intelligence Logs**: `ctms/logs/threat_intelligence.log`

### Monitoring Dashboard
Access the dashboard at http://localhost:8501 for:
- Real-time threat feed
- System status monitoring
- Threat analysis and reports
- Alert configuration

### Health Monitoring
```bash
# Check system health
curl http://localhost:8000/health

# Check API status
curl -H "Authorization: Bearer demo_token_for_development_12345" \
  http://localhost:8000/api/v1/hacker-grade/health
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Import Errors
```bash
# Install missing dependencies
pip install -r requirements.txt

# Check Python version
python --version  # Should be 3.8+
```

#### 2. Port Conflicts
```bash
# Check if ports are in use
netstat -tulpn | grep :8000
netstat -tulpn | grep :8501

# Change ports in .env file
API_PORT=8001
DASHBOARD_PORT=8502
```

#### 3. API Connection Issues
```bash
# Check if API server is running
ps aux | grep uvicorn

# Restart API server
pkill -f uvicorn
python -m uvicorn ctms.main:app --host localhost --port 8000 --reload
```

#### 4. Dashboard Issues
```bash
# Check if Streamlit is running
ps aux | grep streamlit

# Restart dashboard
pkill -f streamlit
streamlit run hacker_grade_dashboard.py --server.port 8501
```

#### 5. Scraping Failures
- Check internet connection
- Verify source URLs are accessible
- Check rate limiting settings
- Review logs for specific errors

### Performance Optimization

#### 1. Increase Cache Duration
```env
CACHE_DURATION=600  # 10 minutes
```

#### 2. Adjust Scraping Intervals
```python
# In ctms/config/hacker_sources.py
"scraping_interval": 3600,  # 1 hour instead of 30 minutes
```

#### 3. Limit Concurrent Requests
```env
MAX_CONCURRENT_REQUESTS=5
```

## 🔒 Security Considerations

### Production Deployment

1. **Change Default Token**:
   ```env
   API_TOKEN=your_secure_token_here
   ```

2. **Enable HTTPS**:
   ```bash
   # Use reverse proxy (nginx/apache) with SSL
   # Configure uvicorn with SSL certificates
   ```

3. **Restrict Access**:
   ```env
   API_HOST=127.0.0.1  # Local access only
   ```

4. **Database Security**:
   - Use secure database credentials
   - Enable database encryption
   - Regular backups

### Legal Compliance

- **Educational Use Only**: This system is for academic research
- **Rate Limiting**: Respect website rate limits and robots.txt
- **Data Privacy**: Handle sensitive data appropriately
- **Access Control**: Implement proper authentication
- **Logging**: Maintain audit trails for compliance

## 📈 Scaling

### Horizontal Scaling
- Deploy multiple API instances behind a load balancer
- Use Redis for shared caching
- Implement database clustering

### Vertical Scaling
- Increase server resources (CPU, RAM, Storage)
- Optimize database queries
- Use SSD storage for better I/O performance

## 🔄 Maintenance

### Regular Tasks

1. **Update Dependencies**:
   ```bash
   pip install --upgrade -r requirements.txt
   ```

2. **Clear Cache**:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/hacker-grade/clear-cache" \
     -H "Authorization: Bearer demo_token_for_development_12345"
   ```

3. **Backup Data**:
   ```bash
   # Backup database
   cp ctms/data/threat_intelligence.db backup/
   
   # Backup logs
   tar -czf logs_backup_$(date +%Y%m%d).tar.gz ctms/logs/
   ```

4. **Monitor Disk Space**:
   ```bash
   # Check log file sizes
   du -sh ctms/logs/
   
   # Rotate logs if needed
   logrotate /etc/logrotate.d/hacker_grade_system
   ```

### Updates and Patches

1. **Backup Current System**
2. **Update Source Code**
3. **Run Setup Script**
4. **Test System Functionality**
5. **Deploy Updates**

## 📞 Support

### Documentation
- **API Documentation**: http://localhost:8000/docs
- **README**: README.md
- **Configuration**: ctms/config/

### Logs and Debugging
- Check `ctms/logs/` for detailed error information
- Use `python test_system.py` for system diagnostics
- Monitor system health via dashboard

### Community
- Report issues through the project repository
- Contribute improvements and bug fixes
- Share threat intelligence insights

## ⚠️ Disclaimer

This system is designed for defensive security research and educational purposes only. Users are responsible for:

- Ensuring compliance with all applicable laws and regulations
- Respecting website terms of service and rate limits
- Using the system responsibly and ethically
- Implementing appropriate security measures

The authors are not responsible for any misuse of this system.

---

**🎓 Educational purposes only - Defensive security research**
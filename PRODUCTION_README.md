# 🛡️ Hacker-Grade Threat Intelligence System - Production Guide

## Overview

This is a **production-ready** hacker-grade threat intelligence system designed for academic cybersecurity research. The system provides real-time threat monitoring from multiple sources including hacker forums, ransomware leak sites, paste sites, and GitHub repositories.

**⚠️ Educational Purposes Only - Defensive Security Research**

## 🏗️ Architecture

### Production Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data Sources  │    │  Data Collector │    │   SQLite DB     │
│                 │    │   (Background)  │    │                 │
│ • Hacker Forums │───▶│ • Async Scraping│───▶│ • Threats Table │
│ • Ransomware    │    │ • 5min Intervals│    │ • Collection Log│
│ • Paste Sites   │    │ • Error Handling│    │ • System Status │
│ • GitHub        │    │ • Deduplication │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │  Production DB  │    │   Streamlit     │
│   (API Server)  │◀───│   Service       │───▶│   Dashboard     │
│                 │    │                 │    │                 │
│ • Fast Response │    │ • Fast Queries  │    │ • Real-time UI  │
│ • Authentication│    │ • Caching       │    │ • Interactive   │
│ • Rate Limiting │    │ • Search        │    │ • Visualizations│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Create virtual environment
python3 -m venv ctms_env_new
source ctms_env_new/bin/activate

# Install requirements
pip install -r requirements_simple.txt
```

### 2. Start Production System

```bash
# Start the complete production system
python start_production_system.py
```

This will start:
- **Data Collector Service** (Background)
- **API Server** (http://localhost:8000)
- **Dashboard** (http://localhost:8501)

### 3. Access the System

- **API Documentation**: http://localhost:8000/docs
- **Dashboard**: http://localhost:8501
- **Health Check**: http://localhost:8000/health
- **Hacker-Grade API**: http://localhost:8000/api/v1/hacker-grade/health

## 🔧 API Authentication

For development, use this token:
```
Bearer demo_token_for_development_12345
```

## 📊 API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/hacker-grade/health` | GET | System health check |
| `/api/v1/hacker-grade/threats/summary` | GET | Threat summary statistics |
| `/api/v1/hacker-grade/threats/intelligence` | GET | Full threat intelligence data |
| `/api/v1/hacker-grade/system/status` | GET | Detailed system status |

### Search & Filter Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/hacker-grade/threats/search?query=...` | GET | Search threats by query |
| `/api/v1/hacker-grade/threats/by-type/{type}` | GET | Get threats by type |
| `/api/v1/hacker-grade/threats/by-source/{source}` | GET | Get threats by source |

## 🗄️ Database Schema

### Threats Table
```sql
CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    threat_score REAL DEFAULT 0.0,
    threat_type TEXT,
    source TEXT,
    source_type TEXT,
    published_at TEXT,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    indicators TEXT,
    hash_id TEXT UNIQUE,
    status TEXT DEFAULT 'active'
);
```

### Collection Log Table
```sql
CREATE TABLE collection_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_type TEXT,
    articles_collected INTEGER,
    articles_new INTEGER,
    duration_seconds REAL,
    status TEXT,
    error_message TEXT
);
```

### System Status Table
```sql
CREATE TABLE system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    last_collection TIMESTAMP,
    total_threats INTEGER,
    high_severity_count INTEGER,
    next_collection TIMESTAMP,
    system_health TEXT DEFAULT 'healthy'
);
```

## 🔄 Data Collection

### Collection Schedule
- **Frequency**: Every 5 minutes
- **Sources**: Hacker forums, ransomware leaks, paste sites, GitHub
- **Deduplication**: Based on content hash
- **Error Handling**: Automatic retry with exponential backoff

### Data Sources

#### Hacker Forums
- exploit.in
- xss.is
- breachforums.st
- 0day.today
- nulled.to
- hackforums.net
- cracked.to
- sinister.ly
- leakbase.pw
- blackhatworld.com

#### Ransomware Leak Sites
- lockbitfiles.com
- blackcatleaks.com
- blackbasta.net
- medusaleaks.com
- playleaks.com
- bianliannews.com
- royalleaks.com
- snatchleaks.com
- cubaleaks.com
- vicesocietyleaks.com

#### Paste Sites
- pastebin.com
- ghostbin.com
- paste.ee
- justpaste.it
- hastebin.com
- rentry.co
- dumpz.org
- paste.org.ru
- paste2.org
- ideone.com

#### GitHub Monitoring
- exploit language:Python
- PoC CVE
- CVE-2025
- 0day exploit
- privilege escalation
- rce exploit
- sql injection exploit
- xss exploit
- csrf exploit
- buffer overflow exploit

## 🛡️ Threat Analysis

### Threat Scoring
- **0.0-0.3**: Low severity
- **0.3-0.6**: Medium severity
- **0.6-0.8**: High severity
- **0.8-1.0**: Critical severity

### Threat Types
- `zero_day`: Zero-day vulnerabilities
- `data_breach`: Data breaches and leaks
- `malware`: Malware and ransomware
- `exploit`: Exploit code and PoCs
- `phishing`: Phishing campaigns
- `social_engineering`: Social engineering attacks

### Source Types
- `hacker_forum`: Hacker forum posts
- `ransomware_leak`: Ransomware leak sites
- `paste_site`: Paste site content
- `github`: GitHub repositories

## 📈 Monitoring & Logging

### Log Files
- `ctms/logs/collector.log`: Data collection logs
- `ctms/logs/production.log`: Production system logs
- `ctms/logs/app.log`: API server logs

### System Monitoring
```bash
# Check system status
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/hacker-grade/system/status

# Check collection logs
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/hacker-grade/health
```

## 🔧 Configuration

### Environment Variables
```bash
# API Configuration
API_HOST=localhost
API_PORT=8000
DEBUG_MODE=false

# Database Configuration
DATABASE_URL=sqlite:///ctms/data/threat_intelligence.db

# Collection Configuration
COLLECTION_INTERVAL=300  # 5 minutes
COLLECTION_TIMEOUT=30    # 30 seconds

# Authentication
API_TOKEN=demo_token_for_development_12345
```

### Customization

#### Modify Collection Sources
Edit `data_collector_service.py`:
```python
async def collect_hacker_forum_data(self):
    # Add your custom scraping logic here
    pass
```

#### Adjust Collection Frequency
Edit `data_collector_service.py`:
```python
def __init__(self):
    self.collection_interval = 300  # Change to desired seconds
```

#### Add New Threat Types
Edit `ctms/analysis/hacker_grade_analyzer.py`:
```python
def classify_hacker_grade_threat_type(self, article):
    # Add your custom classification logic
    pass
```

## 🚨 Alerts & Notifications

### High Severity Alerts
- **Threshold**: Threat score > 0.8
- **Channels**: Email, Webhook
- **Frequency**: Real-time

### Alert Configuration
```python
ALERT_CONFIG = {
    'enabled': True,
    'high_severity_threshold': 0.8,
    'email_settings': {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'your-email@gmail.com',
        'password': 'your-app-password',
        'recipients': ['admin@company.com']
    },
    'webhook_settings': {
        'url': 'https://hooks.slack.com/services/...',
        'headers': {}
    }
}
```

## 🔒 Security Considerations

### Authentication
- Use strong API tokens in production
- Implement rate limiting
- Enable HTTPS in production

### Data Privacy
- Anonymize sensitive data
- Implement data retention policies
- Follow GDPR compliance

### Network Security
- Use VPN for data collection
- Implement IP rotation
- Monitor for detection

## 🐛 Troubleshooting

### Common Issues

#### Data Collector Not Starting
```bash
# Check logs
tail -f ctms/logs/collector.log

# Check database permissions
ls -la ctms/data/
```

#### API Timeout Issues
```bash
# Check API server logs
tail -f ctms/logs/app.log

# Test database connection
python -c "import sqlite3; sqlite3.connect('ctms/data/threat_intelligence.db')"
```

#### Dashboard Not Loading
```bash
# Check Streamlit logs
streamlit run hacker_grade_dashboard.py --server.port 8501

# Check API connectivity
curl http://localhost:8000/health
```

### Performance Optimization

#### Database Optimization
```sql
-- Add indexes for better performance
CREATE INDEX idx_threats_score ON threats(threat_score);
CREATE INDEX idx_threats_type ON threats(threat_type);
CREATE INDEX idx_threats_source ON threats(source_type);
CREATE INDEX idx_threats_collected ON threats(collected_at);
```

#### Memory Optimization
```python
# Increase cache size
CACHE_SIZE = 1000  # Number of cached items

# Optimize queries
LIMIT_QUERY_RESULTS = 100  # Max results per query
```

## 📚 API Examples

### Get Threat Summary
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/hacker-grade/threats/summary
```

### Search Threats
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     "http://localhost:8000/api/v1/hacker-grade/threats/search?query=zero-day"
```

### Get Threats by Type
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/hacker-grade/threats/by-type/zero_day
```

### Get System Status
```bash
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/hacker-grade/system/status
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style
- Follow PEP 8
- Use type hints
- Add docstrings
- Write unit tests

## 📄 License

MIT License - See LICENSE file for details.

## ⚠️ Legal Notice

This system is designed for **educational purposes only** and **defensive security research**. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse of this system.

**Educational Use Only - Defensive Security Research**
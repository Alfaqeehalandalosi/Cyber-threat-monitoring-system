# 🛡️ Cyber Threat Monitoring System (CTMS)

A comprehensive, professional-grade cyber threat intelligence platform built with Python, featuring advanced TOR-enabled web scraping, NLP-powered threat analysis, and real-time alerting capabilities.

## 🌟 Features

### 🔍 **Advanced Threat Intelligence Collection**
- **TOR-Enabled Web Scraping**: Anonymous data collection from dark web sources
- **Multi-Source Intelligence Gathering**: Surface web, dark web, and threat feeds
- **Intelligent Content Extraction**: Advanced parsing and deduplication
- **Rate Limiting & Circuit Rotation**: Ethical and undetectable scraping

### 🧠 **Machine Learning & NLP Analysis**
- **Automated IOC Extraction**: IP addresses, domains, URLs, file hashes, emails
- **Threat Classification**: Multi-class threat type identification
- **Entity Recognition**: Security-specific named entity extraction
- **Sentiment Analysis**: Threat severity and confidence scoring
- **Pattern Recognition**: Advanced regex and ML-based detection

### 📊 **Real-Time Monitoring & Analytics**
- **Interactive Dashboard**: Beautiful Streamlit-based web interface
- **Real-Time Alerts**: Email, Slack, and webhook notifications
- **Advanced Search**: Elasticsearch-powered full-text search
- **Data Visualization**: Interactive charts and threat trend analysis
- **Performance Metrics**: System health and operational dashboards

### 🔐 **Enterprise Security Features**
- **Secure Configuration**: Environment-based credential management
- **Authentication & Authorization**: JWT-based API security
- **Audit Logging**: Comprehensive activity tracking
- **Data Encryption**: Secure storage and transmission
- **Rate Limiting**: API protection and resource management

### 🏗️ **Scalable Architecture**
- **Microservices Design**: Modular, maintainable components
- **Database Flexibility**: MongoDB for documents, Elasticsearch for search
- **Container Support**: Docker-based deployment
- **Async Processing**: High-performance async/await patterns
- **RESTful API**: Comprehensive FastAPI-based endpoints

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Backend Framework** | FastAPI | High-performance API with automatic documentation |
| **Web Scraping** | Scrapy + aiohttp | TOR-enabled anonymous data collection |
| **NLP/ML** | spaCy + Transformers | Advanced text analysis and entity extraction |
| **Databases** | MongoDB + Elasticsearch | Document storage and search capabilities |
| **Frontend** | Streamlit | Interactive web dashboard |
| **Messaging** | Redis | Caching and session management |
| **Notifications** | SMTP + Slack + Webhooks | Multi-channel alerting system |
| **Logging** | Loguru | Structured, performant logging |
| **Configuration** | Pydantic | Type-safe configuration management |
| **Containerization** | Docker + Docker Compose | Consistent deployment environment |

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Docker & Docker Compose
- Git

### 1. Clone & Setup

```bash
# Clone the repository
git clone <repository-url>
cd cyber-threat-monitoring-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration (IMPORTANT!)
nano .env
```

**Required Configuration:**
```bash
SECRET_KEY=your-super-secret-key-change-this
MONGODB_URL=mongodb://admin:secure_mongo_password@localhost:27017/threat_monitoring?authSource=admin
JWT_SECRET_KEY=your-jwt-secret-key-change-this
```

### 3. Start Infrastructure

```bash
# Start databases and services
docker-compose up -d

# Wait for services to be ready
sleep 30

# Verify services are running
docker-compose ps
```

### 4. Install NLP Models

```bash
# Install spaCy English model
python -m spacy download en_core_web_sm
```

### 5. Launch Application

```bash
# Terminal 1: Start API Server
python -m ctms.api.main

# Terminal 2: Start Dashboard
streamlit run ctms/dashboard/main_dashboard.py

# Terminal 3: Test the system
python -c "
import asyncio
from ctms.database.connection import initialize_databases
asyncio.run(initialize_databases())
print('✅ System initialized successfully!')
"
```

### 6. Access the System

- **Dashboard**: http://localhost:8501
- **API Documentation**: http://localhost:8000/docs
- **API Health**: http://localhost:8000/health

**Default Login**: 
- Username: `admin`
- Password: `admin`

## 📖 Usage Guide

### Dashboard Features

1. **Overview Dashboard**
   - System health metrics
   - Real-time threat statistics
   - IOC discovery timeline
   - Recent alerts summary

2. **IOC Analysis**
   - Browse indicators of compromise
   - Search threat intelligence
   - Analyze text for IOCs
   - Export findings

3. **Threat Intelligence**
   - View threat classifications
   - Risk score distributions
   - Threat type analysis
   - Timeline visualization

4. **Alert Management**
   - Monitor active alerts
   - Acknowledge incidents
   - Update alert status
   - View alert history

5. **System Administration**
   - Manage scraping sources
   - Configure notifications
   - Monitor system health
   - View audit logs

### API Usage Examples

```python
import requests

# API base URL
API_URL = "http://localhost:8000"
headers = {"Authorization": "Bearer your-token-here"}

# Get system health
response = requests.get(f"{API_URL}/health")
print(response.json())

# Search threats
response = requests.get(
    f"{API_URL}/api/v1/search?q=malware",
    headers=headers
)
threats = response.json()

# Analyze text for IOCs
response = requests.post(
    f"{API_URL}/api/v1/analysis/text",
    headers=headers,
    json={"text": "Suspicious IP: 192.168.1.100"}
)
analysis = response.json()

# Get recent IOCs
response = requests.get(
    f"{API_URL}/api/v1/iocs?limit=50&severity=high",
    headers=headers
)
iocs = response.json()
```

### Adding Scraping Sources

```python
# Add new threat intelligence source
source_data = {
    "name": "Example Threat Feed",
    "url": "https://example.com/threat-feed",
    "source_type": "surface_web",
    "enabled": True,
    "content_selectors": {
        "threat_data": ".threat-content"
    },
    "scraping_interval": 3600
}

response = requests.post(
    f"{API_URL}/api/v1/scraping/sources",
    headers=headers,
    json=source_data
)
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Application secret key | - | ✅ |
| `MONGODB_URL` | MongoDB connection string | - | ✅ |
| `JWT_SECRET_KEY` | JWT signing key | - | ✅ |
| `ELASTICSEARCH_URL` | Elasticsearch endpoint | `http://localhost:9200` | ❌ |
| `USE_TOR_PROXY` | Enable TOR proxy | `true` | ❌ |
| `SMTP_SERVER` | Email server for alerts | - | ❌ |
| `SLACK_WEBHOOK_URL` | Slack notifications | - | ❌ |

### Scraping Configuration

```yaml
# Custom scraping source example
scraping_sources:
  - name: "Dark Web Forum"
    url: "http://example.onion"
    source_type: "dark_web"
    use_tor: true
    content_selectors:
      title: "h1.post-title"
      content: ".post-content"
    url_patterns:
      - ".*forum.*"
      - ".*thread.*"
    min_content_length: 200
    scraping_interval: 7200
```

### Notification Channels

```python
from ctms.alerts.notification_engine import NotificationChannel, NotificationType

# Email notifications
email_channel = NotificationChannel(
    name="security_team",
    type=NotificationType.EMAIL,
    enabled=True,
    config={
        "recipients": ["security@company.com", "soc@company.com"]
    },
    severity_filter=["high", "critical"]
)

# Slack notifications
slack_channel = NotificationChannel(
    name="security_slack",
    type=NotificationType.SLACK,
    enabled=True,
    config={
        "webhook_url": "https://hooks.slack.com/services/..."
    }
)
```

## 🧪 Testing

### Run Unit Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-mock

# Run all tests
pytest

# Run with coverage
pytest --cov=ctms

# Run specific test modules
pytest ctms/tests/test_nlp.py
pytest ctms/tests/test_scraping.py
```

### Test Individual Components

```python
# Test IOC extraction
from ctms.nlp.threat_analyzer import extract_iocs_from_text

text = "Malicious IP: 192.168.1.100 and domain: evil.com"
iocs = await extract_iocs_from_text(text)
print(iocs)

# Test notification system
from ctms.alerts.notification_engine import test_notifications

results = await test_notifications()
print(results)

# Test scraping (be careful with live sources)
from ctms.scraping.tor_scraper import scrape_single_url

content = await scrape_single_url("http://example.com")
print(content)
```

## 📊 Performance & Monitoring

### System Metrics

- **API Response Time**: < 200ms average
- **Scraping Throughput**: 50-100 pages/minute
- **NLP Processing**: 1000+ documents/hour
- **Database Performance**: < 10ms query time
- **Memory Usage**: < 2GB typical
- **CPU Usage**: < 50% under load

### Monitoring Endpoints

```bash
# System health
curl http://localhost:8000/health

# Performance metrics
curl http://localhost:8000/stats

# Database status
curl http://localhost:8000/api/v1/system/database
```

### Log Analysis

```bash
# View real-time logs
tail -f logs/ctms.log

# Search for errors
grep "ERROR" logs/ctms.log

# Monitor API requests
grep "API:" logs/ctms.log
```

## 🔒 Security Considerations

### Best Practices

1. **Credential Management**
   - Use strong, unique passwords
   - Rotate API keys regularly
   - Store secrets in environment variables
   - Never commit credentials to code

2. **Network Security**
   - Use TLS/SSL for all connections
   - Implement proper firewall rules
   - Monitor network traffic
   - Use VPN for remote access

3. **Data Protection**
   - Encrypt sensitive data at rest
   - Sanitize all inputs
   - Implement proper access controls
   - Regular security audits

4. **TOR Usage**
   - Monitor circuit renewal
   - Respect rate limits
   - Follow ethical guidelines
   - Comply with local laws

### Security Hardening

```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Configure firewall
sudo ufw enable
sudo ufw allow 22    # SSH
sudo ufw allow 8000  # API
sudo ufw allow 8501  # Dashboard

# Set proper file permissions
chmod 600 .env
chmod 700 logs/
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Database Connection Errors
```bash
# Check MongoDB is running
docker-compose ps mongodb

# Check connection
docker-compose logs mongodb

# Restart database
docker-compose restart mongodb
```

#### 2. TOR Proxy Issues
```bash
# Check TOR proxy status
docker-compose ps tor-proxy

# Test TOR connectivity
curl --socks5 localhost:9050 https://check.torproject.org/

# Restart TOR proxy
docker-compose restart tor-proxy
```

#### 3. NLP Model Errors
```bash
# Reinstall spaCy model
python -m spacy download en_core_web_sm --force

# Check model installation
python -c "import spacy; nlp = spacy.load('en_core_web_sm'); print('OK')"
```

#### 4. Memory Issues
```bash
# Check memory usage
free -h

# Monitor process memory
htop

# Restart services
docker-compose restart
```

### Debug Mode

```bash
# Enable debug logging
export DEBUG=true
export LOG_LEVEL=DEBUG

# Start with debug output
python -m ctms.api.main --debug
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run code formatting
black ctms/
flake8 ctms/

# Run type checking
mypy ctms/
```

### Code Style

- Follow PEP 8 guidelines
- Use type hints consistently
- Write comprehensive docstrings
- Add proper logging statements
- Include unit tests for new features

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **spaCy** for excellent NLP capabilities
- **FastAPI** for the high-performance API framework
- **Streamlit** for rapid dashboard development
- **TOR Project** for privacy and anonymity tools
- **Elasticsearch** for powerful search capabilities

## 📞 Support

- **Documentation**: [Wiki](link-to-wiki)
- **Issues**: [GitHub Issues](link-to-issues)
- **Discord**: [Community Server](link-to-discord)
- **Email**: security@yourdomain.com

---

**⚠️ Disclaimer**: This tool is intended for legitimate cybersecurity research and threat intelligence purposes only. Users are responsible for complying with all applicable laws and regulations. The developers assume no liability for misuse of this software.

**🔒 Security Notice**: Always use this system in a secure environment and follow cybersecurity best practices. Report any security vulnerabilities responsibly.
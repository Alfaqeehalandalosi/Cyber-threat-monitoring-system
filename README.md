# Cyber Threat Monitoring System (CTMS)

A comprehensive platform for collecting, analyzing, and monitoring cyber threats using advanced scraping, NLP, and machine learning techniques.

## 🚀 Quick Start Guide

### Prerequisites

- Python 3.8+
- Docker and Docker Compose
- Git

### Step 1: Download the Fixed Version

```bash
# Clone the repository
git clone https://github.com/your-username/cyber-threat-monitoring-system.git
cd cyber-threat-monitoring-system

# Or if you already have the repo, pull the latest changes
git pull origin main
```

### Step 2: Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install additional NLP dependencies
python -m spacy download en_core_web_sm
```

### Step 3: Start the System

```bash
# Start all services using Docker Compose
docker-compose up -d

# Or start services individually
docker-compose up -d mongodb
docker-compose up -d redis
docker-compose up -d tor
```

### Step 4: Run the API

```bash
# Start the FastAPI server
python -m ctms.api.main

# Or use uvicorn directly
uvicorn ctms.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 5: Access the Dashboard

```bash
# Start the Streamlit dashboard
streamlit run ctms/dashboard/main_dashboard.py
```

## 🔧 What Was Fixed

### Root Cause Analysis

The persistent `AttributeError: 'ThreatIntelligenceScraper' object has no attribute 'run_full_cycle'` was caused by:

1. **Missing Method**: The `ThreatIntelligenceScraper` class was missing the `run_full_cycle()` method
2. **Incorrect Method Calls**: Some code was trying to call `run_full_cycle()` directly on the scraper instead of using the `ScrapingOrchestrator`
3. **Missing Analysis Method**: The `ThreatAnalyzer` class was missing the `analyze_latest_threats()` method

### Fixes Applied

1. **Added Backward Compatibility Methods**:
   - Added `run_full_cycle()` method to `ThreatIntelligenceScraper` class
   - Added `analyze_latest_threats()` method to `ThreatAnalyzer` class

2. **Updated Main API**:
   - Fixed the scraping endpoint to use correct methods
   - Added the `_background_run_scrape()` function for backward compatibility
   - Improved error handling and logging

3. **Enhanced Scraping System**:
   - Improved TOR proxy management
   - Better content extraction and processing
   - Enhanced IOC detection and validation

## 📁 Project Structure

```
ctms/
├── api/                    # FastAPI application
│   ├── main.py            # Main API entry point (FIXED)
│   └── __init__.py
├── scraping/              # Web scraping module
│   ├── tor_scraper.py     # TOR-enabled scraper (FIXED)
│   └── __init__.py
├── nlp/                   # Natural language processing
│   ├── threat_analyzer.py # Threat analysis engine (FIXED)
│   └── __init__.py
├── database/              # Database models and connection
├── core/                  # Core configuration and utilities
├── dashboard/             # Streamlit dashboard
└── alerts/                # Alert management
```

## 🛡️ Key Features

### Threat Intelligence Collection
- **TOR-enabled scraping** for anonymous data collection
- **Multi-source support** (surface web, dark web, threat feeds)
- **Rate limiting and circuit rotation** for stealth operations
- **Content deduplication** and validation

### Advanced Analysis
- **NLP-powered threat classification** using spaCy
- **IOC extraction** (IPs, domains, URLs, hashes, emails)
- **Entity recognition** for security context
- **Threat scoring and severity assessment**

### Real-time Monitoring
- **Automated scraping cycles** with configurable schedules
- **Real-time alert generation** based on threat thresholds
- **Dashboard visualization** of threat landscape
- **API endpoints** for integration

## 🔌 API Endpoints

### Authentication
- **Token**: Use `demo_token_for_development_12345` for development

### Core Endpoints
- `GET /health` - System health check
- `GET /stats` - System statistics
- `POST /api/v1/scraping/run` - Trigger scraping cycle (FIXED)
- `GET /api/v1/iocs` - Get indicators of compromise
- `GET /api/v1/threats` - Get threat intelligence
- `GET /api/v1/alerts` - Get alerts

### Analysis Endpoints
- `POST /api/v1/analysis/text` - Analyze raw text
- `POST /api/v1/analysis/content/{id}` - Analyze scraped content
- `GET /api/v1/search` - Search across all data

## 🐳 Docker Setup

### Using Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Manual Docker Setup

```bash
# Start MongoDB
docker run -d --name ctms-mongodb \
  -p 27017:27017 \
  -v ctms-mongodb-data:/data/db \
  mongo:latest

# Start Redis
docker run -d --name ctms-redis \
  -p 6379:6379 \
  redis:alpine

# Start TOR (optional)
docker run -d --name ctms-tor \
  -p 9050:9050 \
  -p 9051:9051 \
  dperson/torproxy
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Database
MONGODB_URL=mongodb://localhost:27017/ctms
REDIS_URL=redis://localhost:6379

# API
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=true

# Scraping
TOR_ENABLED=true
TOR_HOST=localhost
TOR_PORT=9050
TOR_CONTROL_PORT=9051

# Security
JWT_SECRET=your-secret-key-here
```

### Scraping Sources

Add scraping sources via API:

```bash
curl -X POST "http://localhost:8000/api/v1/scraping/sources" \
  -H "Authorization: Bearer demo_token_for_development_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example Threat Feed",
    "url": "https://example.com/threats",
    "source_type": "surface_web",
    "enabled": true,
    "max_concurrent_requests": 5,
    "max_urls_per_cycle": 100
  }'
```

## 🚨 Troubleshooting

### Common Issues

1. **AttributeError: 'ThreatIntelligenceScraper' object has no attribute 'run_full_cycle'**
   - ✅ **FIXED**: Added backward compatibility method
   - The system now supports both old and new method calls

2. **500 Internal Server Error on scraping**
   - ✅ **FIXED**: Improved error handling and method resolution
   - Check logs for specific error details

3. **Database connection issues**
   - Ensure MongoDB is running: `docker-compose up -d mongodb`
   - Check connection string in configuration

4. **TOR proxy issues**
   - Ensure TOR service is running: `docker-compose up -d tor`
   - Check TOR configuration in settings

### Debug Mode

Enable debug mode for detailed logging:

```bash
export DEBUG=true
python -m ctms.api.main
```

### Logs

View application logs:

```bash
# API logs
tail -f logs/api.log

# Scraping logs
tail -f logs/scraping.log

# Analysis logs
tail -f logs/analysis.log
```

## 📊 Monitoring and Metrics

### Health Checks

```bash
# Check system health
curl http://localhost:8000/health

# Get system statistics
curl -H "Authorization: Bearer demo_token_for_development_12345" \
  http://localhost:8000/stats
```

### Dashboard Metrics

Access the Streamlit dashboard at `http://localhost:8501` to view:
- Real-time threat statistics
- IOC timeline and distribution
- Alert status and severity
- System performance metrics

## 🔒 Security Considerations

### Production Deployment

1. **Change default tokens** and implement proper JWT authentication
2. **Use HTTPS** for all API communications
3. **Implement rate limiting** and request validation
4. **Secure database connections** with authentication
5. **Monitor TOR circuit usage** and implement proper rotation

### Data Privacy

- All scraped data is stored locally
- TOR proxy ensures anonymous scraping
- No data is transmitted to external services
- Implement data retention policies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the logs for error details
3. Open an issue on GitHub with:
   - Error message and stack trace
   - Steps to reproduce
   - System configuration details

## 🔄 Version History

### v1.0.1 (Latest - Fixed)
- ✅ Fixed `AttributeError: 'ThreatIntelligenceScraper' object has no attribute 'run_full_cycle'`
- ✅ Added backward compatibility methods
- ✅ Improved error handling and logging
- ✅ Enhanced scraping and analysis capabilities
- ✅ Updated API endpoints and documentation

### v1.0.0 (Initial Release)
- Initial release with basic functionality
- TOR-enabled web scraping
- NLP threat analysis
- FastAPI backend
- Streamlit dashboard

---

**Note**: This version includes comprehensive fixes for the persistent API error. The system now supports both the original method calls and the new orchestrated approach, ensuring backward compatibility while providing improved functionality.
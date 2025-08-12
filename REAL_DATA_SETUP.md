# 🕷️ Real Web Scraping Setup Guide

## Overview

This guide will help you set up **real web scraping** for cybersecurity threat intelligence. The system will scrape actual cybersecurity news sources to provide real-time threat data instead of mock data.

## 🎯 What You'll Get

- **Real cybersecurity news** from 5+ sources
- **Live threat intelligence** with actual threat scores
- **RSS feed parsing** for reliable data collection
- **Web scraping fallback** for additional sources
- **Threat keyword extraction** and classification
- **Real-time dashboard** with live data

## 📋 Prerequisites

1. **Python 3.8+** installed
2. **Virtual environment** ready
3. **API server** running (from previous setup)
4. **Internet connection** for web scraping

## 🚀 Quick Start

### Step 1: Install Dependencies

```bash
# Activate your virtual environment
source ctms_env/bin/activate

# Install web scraping dependencies
pip install aiohttp==3.9.1 feedparser==6.0.10 beautifulsoup4==4.12.2 lxml==4.9.3 requests==2.31.0
```

### Step 2: Start the API Server

```bash
# Make sure API is running
python -m ctms.api.main
```

### Step 3: Start Real Data Dashboard

```bash
# Use the provided script
./start_real_data_dashboard.sh
```

Or manually:
```bash
streamlit run ctms/dashboard/real_data_dashboard.py --server.port 8501
```

## 📰 Data Sources

The system scrapes from these real cybersecurity sources:

| Source | Type | URL | RSS Feed |
|--------|------|-----|----------|
| **Bleeping Computer** | News | https://www.bleepingcomputer.com | ✅ |
| **The Hacker News** | News | https://thehackernews.com | ✅ |
| **Security Week** | News | https://www.securityweek.com | ✅ |
| **Threatpost** | News | https://threatpost.com | ✅ |
| **Krebs on Security** | Blog | https://krebsonsecurity.com | ✅ |

## 🔧 Configuration

### Source Configuration

Edit `ctms/config/real_sources.json` to:
- Enable/disable sources
- Adjust scraping intervals
- Add new sources
- Modify content selectors

### Example Configuration:

```json
{
  "id": "bleepingcomputer",
  "name": "Bleeping Computer",
  "url": "https://www.bleepingcomputer.com",
  "type": "news",
  "enabled": true,
  "scraping_interval": 3600,
  "use_tor": false,
  "api_endpoint": "https://www.bleepingcomputer.com/feed/"
}
```

## 🧪 Testing

### Test the Scraper

```bash
# Test via API
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/real/test
```

### Test Data Collection

```bash
# Get real threat intelligence
curl -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/real/threats/intelligence
```

## 📊 Dashboard Features

### Real Data Dashboard (`real_data_dashboard.py`)

1. **📊 Overview Tab**
   - Real-time metrics
   - Articles collected count
   - Sources active count
   - Average threat score
   - Data freshness indicator

2. **🔍 Threat Analysis Tab**
   - Real threat articles
   - Threat score distribution
   - Threat category breakdown
   - Source attribution

3. **🌐 Sources Tab**
   - Source status monitoring
   - Configuration overview
   - Success rates

4. **🏥 Health Tab**
   - System health status
   - Cache status
   - Manual refresh controls

5. **🧪 Testing Tab**
   - Scraper test results
   - Manual testing tools
   - Sample data display

## 🔍 API Endpoints

### Real Data Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/real/threats/intelligence` | GET | Get real threat intelligence |
| `/api/v1/real/threats/summary` | GET | Get threat summary |
| `/api/v1/real/sources/status` | GET | Get sources status |
| `/api/v1/real/health` | GET | Get system health |
| `/api/v1/real/refresh` | POST | Refresh data |
| `/api/v1/real/test` | GET | Test scraper |

## 🛠️ Troubleshooting

### Common Issues

1. **"No real threat data available"**
   - Check internet connection
   - Verify API server is running
   - Check source configuration

2. **"API Error: 500"**
   - Check API logs
   - Verify dependencies installed
   - Check source URLs are accessible

3. **"Unable to fetch sources status"**
   - Verify `real_sources.json` exists
   - Check file permissions
   - Validate JSON syntax

### Debug Commands

```bash
# Check API health
curl http://localhost:8000/health

# Test scraper directly
python -c "
import asyncio
from ctms.scraping.real_web_scraper import get_real_threat_intelligence
data = asyncio.run(get_real_threat_intelligence())
print(f'Collected {data[\"total_articles\"]} articles')
"

# Check dependencies
pip list | grep -E "(aiohttp|feedparser|beautifulsoup4)"
```

## 🔄 Data Refresh

### Automatic Refresh
- Data is cached for 1 hour
- Automatic background refresh
- Configurable cache duration

### Manual Refresh
```bash
# Via API
curl -X POST -H "Authorization: Bearer demo_token_for_development_12345" \
     http://localhost:8000/api/v1/real/refresh

# Via Dashboard
# Click "🔄 Refresh Data" button in Health tab
```

## 📈 Performance

### Expected Performance
- **Collection Time**: 30-60 seconds for all sources
- **Cache Duration**: 1 hour
- **Memory Usage**: ~50MB for cached data
- **Network Usage**: ~5-10MB per refresh

### Optimization Tips
- Disable unused sources
- Increase cache duration for less critical data
- Use RSS feeds when available (faster than web scraping)

## 🔒 Security Considerations

### Rate Limiting
- 2-second delay between sources
- Respect robots.txt
- User-Agent rotation

### Data Privacy
- No personal data collected
- Only public cybersecurity news
- Configurable data retention

## 🎯 Demo Instructions

### For Your Demo

1. **Start the system**:
   ```bash
   ./start_real_data_dashboard.sh
   ```

2. **Show real data**:
   - Navigate to "🔍 Threat Analysis" tab
   - Point out real article titles and sources
   - Show threat scores and classifications

3. **Demonstrate features**:
   - Click "🔄 Refresh Data" to show live collection
   - Show "🌐 Sources" tab to display configured sources
   - Use "🧪 Testing" tab to run system tests

4. **Explain the technology**:
   - RSS feed parsing for reliable data
   - Web scraping for additional sources
   - Threat keyword extraction
   - Real-time threat scoring

## 📝 Notes

- **Real data** means actual cybersecurity news articles
- **Threat scores** are calculated based on keyword analysis
- **Sources** are major cybersecurity news websites
- **Data** is cached to avoid overwhelming sources
- **Fallback** to mock data if sources are unavailable

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Verify all dependencies are installed
3. Ensure API server is running
4. Check internet connectivity
5. Review source configuration

---

**🎉 Congratulations!** You now have a real web scraping system for cybersecurity threat intelligence!
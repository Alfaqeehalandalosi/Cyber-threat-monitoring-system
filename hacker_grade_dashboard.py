"""
Hacker-Grade Threat Intelligence Dashboard
Advanced threat monitoring interface for hacker forums, ransomware leaks, paste sites, and GitHub
Educational purposes only - Defensive security research
"""

import streamlit as st
import requests
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
from typing import Dict, List, Any
import numpy as np

# Page configuration
st.set_page_config(
    page_title="Hacker-Grade Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #ff4444;
        text-align: center;
        margin-bottom: 2rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    .metric-card {
        background-color: #1e1e1e;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ff4444;
        color: white;
    }
    .threat-card {
        background-color: #2d2d2d;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #444;
        margin-bottom: 1rem;
        color: white;
    }
    .high-severity {
        border-left: 4px solid #ff4444;
        background-color: #3d1e1e;
    }
    .medium-severity {
        border-left: 4px solid #ffaa00;
        background-color: #3d2e1e;
    }
    .low-severity {
        border-left: 4px solid #44aa44;
        background-color: #1e3d1e;
    }
    .zero-day {
        border-left: 4px solid #ff0066;
        background-color: #3d1e3d;
        animation: pulse 2s infinite;
    }
    .ransomware {
        border-left: 4px solid #ff6600;
        background-color: #3d2e1e;
    }
    .github {
        border-left: 4px solid #6cc644;
        background-color: #1e3d1e;
    }
    .forum {
        border-left: 4px solid #0066ff;
        background-color: #1e1e3d;
    }
    .paste {
        border-left: 4px solid #ffcc00;
        background-color: #3d3d1e;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.8; }
        100% { opacity: 1; }
    }
    .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
    }
    .status-online {
        background-color: #44aa44;
    }
    .status-offline {
        background-color: #ff4444;
    }
    .source-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.8em;
        font-weight: bold;
        margin-right: 8px;
    }
    .source-hacker-forum { background-color: #0066ff; color: white; }
    .source-ransomware-leak { background-color: #ff6600; color: white; }
    .source-paste-site { background-color: #ffcc00; color: black; }
    .source-github { background-color: #6cc644; color: white; }
</style>
""", unsafe_allow_html=True)

# Configuration
API_BASE_URL = "http://localhost:8000"
API_TOKEN = "demo_token_for_development_12345"
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}

def make_api_request(endpoint: str, timeout: int = 30, force_refresh: bool = False) -> Dict[str, Any]:
    """Make API request with error handling"""
    try:
        url = f"{API_BASE_URL}{endpoint}"
        if force_refresh and "?" not in url:
            url += "?force_refresh=true"
        elif force_refresh:
            url += "&force_refresh=true"
            
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API request failed: {str(e)}")
        return {}

def make_post_request(endpoint: str, data: Dict[str, Any] = None, timeout: int = 30) -> Dict[str, Any]:
    """Make POST API request"""
    try:
        url = f"{API_BASE_URL}{endpoint}"
        response = requests.post(url, headers=HEADERS, json=data or {}, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"POST request failed: {str(e)}")
        return {}

def render_header(api_status: bool, collection_time: str = None, force_refresh: bool = False):
    """Render dashboard header"""
    st.markdown('<h1 class="main-header">🛡️ Hacker-Grade Threat Intelligence Dashboard</h1>', unsafe_allow_html=True)
    
    # Status indicators
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        status_color = "🟢" if api_status else "🔴"
        st.metric("API Status", f"{status_color} {'Online' if api_status else 'Offline'}")
    
    with col2:
        cache_status = "🔄 Fresh Data" if force_refresh else "💾 Cached Data"
        st.metric("Data Status", cache_status)
    
    with col3:
        if collection_time:
            st.metric("Last Collection", collection_time.split('T')[1][:8])
        else:
            st.metric("Last Collection", "Unknown")
    
    with col4:
        st.metric("System Version", "3.0.0")

def render_threat_metrics(summary_data: Dict[str, Any]):
    """Render threat metrics cards"""
    st.subheader("📊 Hacker-Grade Threat Intelligence Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>📰 Total Articles</h3>
            <h2>{summary_data.get('total_articles', 0)}</h2>
            <p>Real-time collection</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h3>🚨 High Severity</h3>
            <h2>{summary_data.get('high_severity_count', 0)}</h2>
            <p>Score > 0.8</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h3>🎯 Avg Threat Score</h3>
            <h2>{summary_data.get('avg_threat_score', 0):.2f}</h2>
            <p>Overall severity</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h3>🔍 Sources Used</h3>
            <h2>{summary_data.get('sources_used', 0)}</h2>
            <p>Active monitors</p>
        </div>
        """, unsafe_allow_html=True)

def render_source_distribution(summary_data: Dict[str, Any]):
    """Render source distribution charts"""
    st.subheader("📈 Source Distribution Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Source categories pie chart
        source_categories = summary_data.get('source_categories', {})
        if source_categories:
            df_categories = pd.DataFrame(list(source_categories.items()), columns=['Category', 'Count'])
            fig = px.pie(df_categories, values='Count', names='Category', 
                        title='Threat Source Distribution',
                        color_discrete_sequence=['#ff4444', '#ff6600', '#ffcc00', '#6cc644'])
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Threat categories pie chart
        threat_categories = summary_data.get('threat_categories', {})
        if threat_categories:
            df_threats = pd.DataFrame(list(threat_categories.items()), columns=['Category', 'Count'])
            fig = px.pie(df_threats, values='Count', names='Category', 
                        title='Threat Type Distribution',
                        color_discrete_sequence=['#ff0066', '#ff4444', '#ff6600', '#0066ff'])
            st.plotly_chart(fig, use_container_width=True)

def render_top_threats(top_threats: List[Dict[str, Any]]):
    """Render top threats section"""
    st.subheader("🔥 Top Hacker-Grade Threats")
    
    for i, threat in enumerate(top_threats[:10]):
        score = threat.get('threat_score', 0)
        source_type = threat.get('source_type', 'unknown')
        
        # Determine severity class
        if score > 0.8:
            severity_class = "high-severity"
            severity_icon = "🔴"
        elif score > 0.5:
            severity_class = "medium-severity"
            severity_icon = "🟡"
        else:
            severity_class = "low-severity"
            severity_icon = "🟢"
        
        # Add source-specific styling
        if source_type == 'hacker_forum':
            severity_class += " forum"
        elif source_type == 'ransomware_leak':
            severity_class += " ransomware"
        elif source_type == 'github':
            severity_class += " github"
        elif source_type == 'paste_site':
            severity_class += " paste"
        
        # Add zero-day styling
        if threat.get('threat_type') == 'zero_day':
            severity_class += " zero-day"
            severity_icon = "💀"
        
        st.markdown(f"""
        <div class="threat-card {severity_class}">
            <h4>{severity_icon} {threat.get('title', 'Unknown Threat')}</h4>
            <p><strong>Score:</strong> {score:.2f} | <strong>Type:</strong> {threat.get('threat_type', 'Unknown')} | <strong>Source:</strong> {threat.get('source', 'Unknown')}</p>
        </div>
        """, unsafe_allow_html=True)

def render_threat_feed(threat_data: Dict[str, Any]):
    """Render real-time threat feed"""
    st.subheader("📡 Real-Time Hacker-Grade Threat Feed")
    
    articles = threat_data.get('threat_articles', [])
    
    # Filter options
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        min_score = st.slider("Minimum Threat Score", 0.0, 1.0, 0.0, 0.1)
    
    with col2:
        threat_types = list(set(article.get('threat_type', '') for article in articles))
        selected_types = st.multiselect("Threat Types", threat_types, default=threat_types)
    
    with col3:
        source_types = list(set(article.get('source_type', '') for article in articles))
        selected_sources = st.multiselect("Source Types", source_types, default=source_types)
    
    with col4:
        show_zero_day = st.checkbox("Show Zero-Day Only", value=False)
    
    # Filter articles
    filtered_articles = [
        article for article in articles
        if article.get('threat_score', 0) >= min_score
        and article.get('threat_type', '') in selected_types
        and article.get('source_type', '') in selected_sources
        and (not show_zero_day or article.get('threat_type') == 'zero_day')
    ]
    
    # Sort by threat score
    filtered_articles.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
    
    # Display filtered articles
    for article in filtered_articles[:20]:  # Show top 20
        score = article.get('threat_score', 0)
        source_type = article.get('source_type', 'unknown')
        
        # Determine severity class
        if score > 0.8:
            severity_class = "high-severity"
            severity_icon = "🔴"
        elif score > 0.5:
            severity_class = "medium-severity"
            severity_icon = "🟡"
        else:
            severity_class = "low-severity"
            severity_icon = "🟢"
        
        # Add source-specific styling
        if source_type == 'hacker_forum':
            severity_class += " forum"
            source_badge = '<span class="source-badge source-hacker-forum">Forum</span>'
        elif source_type == 'ransomware_leak':
            severity_class += " ransomware"
            source_badge = '<span class="source-badge source-ransomware-leak">Ransomware</span>'
        elif source_type == 'github':
            severity_class += " github"
            source_badge = '<span class="source-badge source-github">GitHub</span>'
        elif source_type == 'paste_site':
            severity_class += " paste"
            source_badge = '<span class="source-badge source-paste-site">Paste</span>'
        else:
            source_badge = ''
        
        # Add zero-day styling
        if article.get('threat_type') == 'zero_day':
            severity_class += " zero-day"
            severity_icon = "💀"
        
        # Extract indicators
        indicators = article.get('indicators', {})
        indicator_text = ""
        if indicators.get('cve_ids'):
            indicator_text += f" CVE: {', '.join(indicators['cve_ids'][:3])}"
        if indicators.get('ip_addresses'):
            indicator_text += f" IPs: {len(indicators['ip_addresses'])}"
        
        st.markdown(f"""
        <div class="threat-card {severity_class}">
            <h4>{severity_icon} {article.get('title', 'Unknown Threat')} {source_badge}</h4>
            <p><strong>Score:</strong> {score:.2f} | <strong>Type:</strong> {article.get('threat_type', 'Unknown')} | <strong>Source:</strong> {article.get('source', 'Unknown')}</p>
            <p><strong>Content:</strong> {article.get('content', '')[:200]}...</p>
            <p><strong>Indicators:</strong> {indicator_text}</p>
            <p><strong>Published:</strong> {article.get('published', 'Unknown')}</p>
        </div>
        """, unsafe_allow_html=True)

def render_zero_day_threats():
    """Render zero-day specific threats"""
    st.subheader("💀 Zero-Day Threats")
    
    # Get zero-day threats
    zero_day_data = make_api_request("/api/v1/hacker-grade/threats/zero-day")
    
    if not zero_day_data:
        st.warning("No zero-day threat data available")
        return
    
    threats = zero_day_data.get('zero_day_threats', [])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Zero-Day", zero_day_data.get('total_zero_day', 0))
    with col2:
        st.metric("High Severity", zero_day_data.get('high_severity_zero_day', 0))
    with col3:
        st.metric("Collection Time", zero_day_data.get('collection_time', 'Unknown').split('T')[1][:8])
    
    # Display zero-day threats
    for threat in threats[:10]:
        score = threat.get('threat_score', 0)
        
        st.markdown(f"""
        <div class="threat-card zero-day">
            <h4>💀 {threat.get('title', 'Unknown Zero-Day')}</h4>
            <p><strong>Score:</strong> {score:.2f} | <strong>Source:</strong> {threat.get('source', 'Unknown')} | <strong>Type:</strong> {threat.get('threat_type', 'Unknown')}</p>
            <p><strong>Content:</strong> {threat.get('content', '')[:300]}...</p>
        </div>
        """, unsafe_allow_html=True)

def render_ransomware_threats():
    """Render ransomware specific threats"""
    st.subheader("🔒 Ransomware Threats")
    
    # Get ransomware threats
    ransomware_data = make_api_request("/api/v1/hacker-grade/threats/ransomware")
    
    if not ransomware_data:
        st.warning("No ransomware threat data available")
        return
    
    threats = ransomware_data.get('ransomware_threats', [])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Ransomware", ransomware_data.get('total_ransomware', 0))
    with col2:
        st.metric("High Severity", ransomware_data.get('high_severity_ransomware', 0))
    with col3:
        st.metric("Collection Time", ransomware_data.get('collection_time', 'Unknown').split('T')[1][:8])
    
    # Display ransomware threats
    for threat in threats[:10]:
        score = threat.get('threat_score', 0)
        
        st.markdown(f"""
        <div class="threat-card ransomware">
            <h4>🔒 {threat.get('title', 'Unknown Ransomware')}</h4>
            <p><strong>Score:</strong> {score:.2f} | <strong>Source:</strong> {threat.get('source', 'Unknown')} | <strong>Type:</strong> {threat.get('threat_type', 'Unknown')}</p>
            <p><strong>Content:</strong> {threat.get('content', '')[:300]}...</p>
        </div>
        """, unsafe_allow_html=True)

def render_github_exploits():
    """Render GitHub exploit threats"""
    st.subheader("🐙 GitHub Exploits")
    
    # Get GitHub threats
    github_data = make_api_request("/api/v1/hacker-grade/threats/github")
    
    if not github_data:
        st.warning("No GitHub exploit data available")
        return
    
    threats = github_data.get('github_threats', [])
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total GitHub", github_data.get('total_github', 0))
    with col2:
        st.metric("High Severity", github_data.get('high_severity_github', 0))
    with col3:
        st.metric("Collection Time", github_data.get('collection_time', 'Unknown').split('T')[1][:8])
    
    # Display GitHub threats
    for threat in threats[:10]:
        score = threat.get('threat_score', 0)
        github_data = threat.get('github_data', {})
        
        st.markdown(f"""
        <div class="threat-card github">
            <h4>🐙 {threat.get('title', 'Unknown GitHub Exploit')}</h4>
            <p><strong>Score:</strong> {score:.2f} | <strong>Language:</strong> {github_data.get('language', 'Unknown')} | <strong>Stars:</strong> {github_data.get('stars', 0)}</p>
            <p><strong>Content:</strong> {threat.get('content', '')[:300]}...</p>
            <p><strong>Link:</strong> <a href="{threat.get('link', '#')}" target="_blank">{threat.get('link', 'Unknown')}</a></p>
        </div>
        """, unsafe_allow_html=True)

def render_threat_report(threat_data: Dict[str, Any]):
    """Render comprehensive threat report"""
    st.subheader("📋 Hacker-Grade Threat Intelligence Report")
    
    report = threat_data.get('threat_report', {})
    
    if not report:
        st.warning("No threat report available")
        return
    
    # Executive summary
    st.markdown("### Executive Summary")
    summary = report.get('executive_summary', {})
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Threats", summary.get('total_threats', 0))
    with col2:
        st.metric("Critical Threats", summary.get('critical_threats', 0))
    with col3:
        st.metric("Recent Threats", summary.get('recent_threats', 0))
    with col4:
        st.metric("Avg Severity", f"{summary.get('average_severity', 0):.2f}")
    
    # Recommendations
    st.markdown("### 🎯 Recommendations")
    recommendations = report.get('recommendations', [])
    for rec in recommendations:
        st.info(rec)
    
    # Threat analysis
    st.markdown("### 📊 Threat Analysis")
    analysis = report.get('threat_analysis', {})
    
    if analysis:
        col1, col2 = st.columns(2)
        
        with col1:
            # Threat type distribution
            threat_dist = analysis.get('threat_type_distribution', {})
            if threat_dist:
                df_threat = pd.DataFrame(list(threat_dist.items()), columns=['Type', 'Count'])
                fig = px.bar(df_threat, x='Type', y='Count', title='Threat Type Distribution',
                           color_discrete_sequence=['#ff4444'])
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Source distribution
            source_dist = analysis.get('source_type_distribution', {})
            if source_dist:
                df_source = pd.DataFrame(list(source_dist.items()), columns=['Source', 'Count'])
                fig = px.bar(df_source, x='Source', y='Count', title='Source Type Distribution',
                           color_discrete_sequence=['#0066ff'])
                st.plotly_chart(fig, use_container_width=True)

def render_indicators_section():
    """Render threat indicators section"""
    st.subheader("🔍 Hacker-Grade Threat Indicators")
    
    # Get indicators
    indicators_data = make_api_request("/api/v1/hacker-grade/threats/indicators")
    
    if not indicators_data:
        st.warning("No indicators data available")
        return
    
    # Display indicators by type
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### CVE Identifiers")
        cve_ids = indicators_data.get('cve_ids', [])
        if cve_ids:
            for cve in cve_ids[:10]:  # Show top 10
                st.code(cve)
        else:
            st.info("No CVE identifiers found")
        
        st.markdown("### Company Names")
        company_names = indicators_data.get('company_names', [])
        if company_names:
            for company in company_names[:10]:  # Show top 10
                st.code(company)
        else:
            st.info("No company names found")
    
    with col2:
        st.markdown("### GitHub Repositories")
        github_repos = indicators_data.get('github_repos', [])
        if github_repos:
            for repo in github_repos[:10]:  # Show top 10
                st.code(repo)
        else:
            st.info("No GitHub repositories found")
        
        st.markdown("### IP Addresses")
        ip_addresses = indicators_data.get('ip_addresses', [])
        if ip_addresses:
            for ip in ip_addresses[:10]:  # Show top 10
                st.code(ip)
        else:
            st.info("No IP addresses found")

def render_alert_configuration():
    """Render alert configuration section"""
    st.subheader("⚙️ Hacker-Grade Alert Configuration")
    
    with st.form("hacker_alert_config"):
        st.markdown("### Email Alerts")
        email_recipients = st.text_area("Email Recipients (one per line)", placeholder="security@company.com\nadmin@company.com")
        
        st.markdown("### Webhook Alerts")
        webhook_url = st.text_input("Webhook URL", placeholder="https://hooks.slack.com/services/...")
        
        st.markdown("### Alert Settings")
        threshold = st.slider("High Severity Threshold", 0.0, 1.0, 0.8, 0.1)
        enabled = st.checkbox("Enable Alerts", value=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.form_submit_button("💾 Save Configuration"):
                recipients_list = [email.strip() for email in email_recipients.split('\n') if email.strip()]
                
                config_data = {
                    'email_recipients': recipients_list,
                    'webhook_url': webhook_url if webhook_url else None,
                    'threshold': threshold,
                    'enabled': enabled
                }
                
                result = make_post_request("/api/v1/hacker-grade/alerts/configure", config_data)
                if result:
                    st.success("Hacker-grade alert configuration saved successfully!")
                else:
                    st.error("Failed to save alert configuration")
        
        with col2:
            if st.form_submit_button("🧪 Test Alerts"):
                result = make_post_request("/api/v1/hacker-grade/alerts/test")
                if result:
                    st.success("Hacker-grade test alerts sent successfully!")
                else:
                    st.error("Failed to send test alerts")

def main():
    """Main dashboard function"""
    # Initialize session state
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = datetime.now()
    if 'force_refresh' not in st.session_state:
        st.session_state.force_refresh = False
    
    # Sidebar controls
    st.sidebar.title("🛡️ Hacker-Grade Controls")
    
    # Refresh controls
    st.sidebar.markdown("### Data Controls")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Refresh Data", type="primary"):
            st.session_state.last_refresh = datetime.now()
            st.session_state.force_refresh = True
            st.rerun()
    
    with col2:
        if st.button("🗑️ Clear Cache"):
            result = make_post_request("/api/v1/hacker-grade/clear-cache")
            if result:
                st.success("Hacker-grade cache cleared successfully!")
                st.session_state.last_refresh = datetime.now()
                st.session_state.force_refresh = True
                st.rerun()
            else:
                st.error("Failed to clear cache")
    
    # Navigation
    st.sidebar.markdown("### Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["Dashboard", "Threat Feed", "Zero-Day Threats", "Ransomware Threats", "GitHub Exploits", "Threat Report", "Indicators", "Alert Configuration"]
    )
    
    # API health check
    health_data = make_api_request("/api/v1/hacker-grade/health")
    api_status = health_data.get('status') == 'healthy'
    
    # Get data
    force_refresh = st.session_state.get('force_refresh', False)
    if force_refresh:
        st.session_state.force_refresh = False
    
    summary_data = make_api_request("/api/v1/hacker-grade/threats/summary", force_refresh=force_refresh)
    threat_data = make_api_request("/api/v1/hacker-grade/threats/intelligence", force_refresh=force_refresh)
    
    collection_time = summary_data.get('collection_time') if summary_data else None
    
    # Render based on selected page
    if page == "Dashboard":
        render_header(api_status, collection_time, force_refresh)
        
        if summary_data:
            render_threat_metrics(summary_data)
            render_source_distribution(summary_data)
            render_top_threats(summary_data.get('top_threats', []))
        else:
            st.error("Failed to load hacker-grade threat data")
    
    elif page == "Threat Feed":
        render_header(api_status, collection_time, force_refresh)
        if threat_data:
            render_threat_feed(threat_data)
        else:
            st.error("Failed to load hacker-grade threat feed data")
    
    elif page == "Zero-Day Threats":
        render_header(api_status, collection_time, force_refresh)
        render_zero_day_threats()
    
    elif page == "Ransomware Threats":
        render_header(api_status, collection_time, force_refresh)
        render_ransomware_threats()
    
    elif page == "GitHub Exploits":
        render_header(api_status, collection_time, force_refresh)
        render_github_exploits()
    
    elif page == "Threat Report":
        render_header(api_status, collection_time, force_refresh)
        if threat_data:
            render_threat_report(threat_data)
        else:
            st.error("Failed to load hacker-grade threat report data")
    
    elif page == "Indicators":
        render_header(api_status, collection_time, force_refresh)
        render_indicators_section()
    
    elif page == "Alert Configuration":
        render_header(api_status, collection_time, force_refresh)
        render_alert_configuration()
    
    # Auto-refresh
    if st.sidebar.checkbox("🔄 Auto-refresh (30s)", value=False):
        time.sleep(30)
        st.rerun()

if __name__ == "__main__":
    main()
"""
Real Data Dashboard
Integrates real threat intelligence from web scraping with advanced visualizations
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
import requests
import json
from datetime import datetime, timedelta
import asyncio
import time
from typing import Dict, Any, List

# Page configuration
st.set_page_config(
    page_title="CTMS - Real Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1f77b4, #ff7f0e);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .threat-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #dc3545;
        margin: 0.5rem 0;
    }
    .source-card {
        background: #e9ecef;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #28a745;
        margin: 0.5rem 0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #f0f2f6;
        border-radius: 4px 4px 0px 0px;
        padding: 10px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1f77b4;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# API configuration
API_BASE_URL = "http://localhost:8000"
API_TOKEN = "demo_token_for_development_12345"

def make_api_request(endpoint: str, method: str = "GET", data: Dict = None) -> Dict[str, Any]:
    """Make API request to backend"""
    try:
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        url = f"{API_BASE_URL}{endpoint}"
        
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=30)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=30)
        else:
            return None
            
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        st.error(f"API Request Error: {str(e)}")
        return None

def render_header():
    """Render dashboard header"""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Cyber Threat Monitoring System</h1>
        <h3>Real-Time Threat Intelligence Dashboard</h3>
        <p>Live data from cybersecurity news sources and threat intelligence feeds</p>
    </div>
    """, unsafe_allow_html=True)

def render_real_data_metrics():
    """Render real data metrics"""
    st.subheader("📊 Real Threat Intelligence Metrics")
    
    # Get real data summary
    summary_data = make_api_request("/api/v1/real/threats/summary")
    
    if summary_data:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📰 Articles Collected</h3>
                <h2>{summary_data.get('total_articles', 0)}</h2>
                <p>Real cybersecurity news</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🌐 Sources Active</h3>
                <h2>{summary_data.get('sources_used', 0)}</h2>
                <p>News sources monitored</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            avg_score = summary_data.get('avg_threat_score', 0.0)
            st.markdown(f"""
            <div class="metric-card">
                <h3>⚠️ Avg Threat Score</h3>
                <h2>{avg_score:.2f}</h2>
                <p>Risk assessment</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            collection_time = summary_data.get('collection_time', '')
            if collection_time:
                try:
                    dt = datetime.fromisoformat(collection_time.replace('Z', '+00:00'))
                    time_ago = datetime.now(dt.tzinfo) - dt
                    minutes_ago = int(time_ago.total_seconds() / 60)
                    time_text = f"{minutes_ago}m ago" if minutes_ago < 60 else f"{minutes_ago//60}h ago"
                except:
                    time_text = "Recent"
            else:
                time_text = "Unknown"
            
            st.markdown(f"""
            <div class="metric-card">
                <h3>🕒 Last Updated</h3>
                <h2>{time_text}</h2>
                <p>Data freshness</p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.warning("⚠️ Unable to fetch real threat intelligence data. Check API connection.")

def render_real_threat_analysis():
    """Render real threat analysis"""
    st.subheader("🔍 Real Threat Analysis")
    
    # Get real threat intelligence data
    real_data = make_api_request("/api/v1/real/threats/intelligence")
    
    if real_data and real_data.get('nlp_results'):
        nlp_results = real_data['nlp_results']
        
        # Display top threats
        st.markdown("### 🚨 Top Threats Detected")
        
        for i, threat in enumerate(nlp_results[:5]):
            threat_score = threat.get('threat_score', 0.0)
            confidence = threat.get('confidence', 0.0)
            
            # Color based on threat score
            if threat_score > 0.8:
                color = "#dc3545"  # Red for high threat
            elif threat_score > 0.6:
                color = "#fd7e14"  # Orange for medium threat
            else:
                color = "#ffc107"  # Yellow for low threat
            
            st.markdown(f"""
            <div class="threat-card" style="border-left-color: {color};">
                <h4>{threat.get('title', 'Unknown Threat')}</h4>
                <p><strong>Source:</strong> {threat.get('source', 'Unknown')}</p>
                <p><strong>Threat Score:</strong> {threat_score:.2f} | <strong>Confidence:</strong> {confidence:.2f}</p>
                <p><strong>Primary Threat:</strong> {threat.get('primary_threat', 'Unknown')}</p>
                <p><strong>Keywords:</strong> {', '.join(threat.get('secondary_threats', [])[:3])}</p>
                <p><strong>IOCs Extracted:</strong> {threat.get('iocs_extracted', 0)}</p>
                <p><strong>Entities:</strong> {', '.join(threat.get('entities_found', [])[:3])}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Threat category distribution
        if len(nlp_results) > 0:
            st.markdown("### 📈 Threat Category Distribution")
            
            threat_categories = {}
            for threat in nlp_results:
                category = threat.get('primary_threat', 'unknown')
                threat_categories[category] = threat_categories.get(category, 0) + 1
            
            if threat_categories:
                fig = px.pie(
                    values=list(threat_categories.values()),
                    names=list(threat_categories.keys()),
                    title="Threat Categories Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        # Threat score distribution
        st.markdown("### 📊 Threat Score Distribution")
        threat_scores = [threat.get('threat_score', 0.0) for threat in nlp_results]
        
        if threat_scores:
            fig = px.histogram(
                x=threat_scores,
                nbins=10,
                title="Distribution of Threat Scores",
                labels={'x': 'Threat Score', 'y': 'Number of Threats'}
            )
            st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.warning("⚠️ No real threat data available. Check data collection status.")

def render_sources_status():
    """Render sources status"""
    st.subheader("🌐 Data Sources Status")
    
    # Get sources status
    sources_status = make_api_request("/api/v1/real/sources/status")
    
    if sources_status:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("### 📰 Configured Sources")
            
            for source in sources_status.get('sources', []):
                status_color = "#28a745" if source.get('enabled', True) else "#6c757d"
                status_text = "🟢 Active" if source.get('enabled', True) else "⚫ Disabled"
                
                st.markdown(f"""
                <div class="source-card">
                    <h4>{source.get('name', 'Unknown Source')}</h4>
                    <p><strong>URL:</strong> {source.get('url', 'N/A')}</p>
                    <p><strong>Type:</strong> {source.get('type', 'Unknown')}</p>
                    <p><strong>Status:</strong> <span style="color: {status_color};">{status_text}</span></p>
                    <p><strong>Tags:</strong> {', '.join(source.get('tags', [])[:3])}</p>
                    <p><strong>Description:</strong> {source.get('description', 'No description')}</p>
                </div>
                """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("### 📊 Sources Summary")
            
            total_sources = sources_status.get('total_sources', 0)
            enabled_sources = sources_status.get('enabled_sources', 0)
            
            st.metric("Total Sources", total_sources)
            st.metric("Active Sources", enabled_sources)
            st.metric("Success Rate", f"{(enabled_sources/total_sources*100):.1f}%" if total_sources > 0 else "0%")
    
    else:
        st.warning("⚠️ Unable to fetch sources status.")

def render_data_health():
    """Render data health status"""
    st.subheader("🏥 Data Collection Health")
    
    # Get health status
    health_data = make_api_request("/api/v1/real/health")
    
    if health_data:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            status = health_data.get('status', 'unknown')
            status_color = "#28a745" if status == "healthy" else "#dc3545"
            st.markdown(f"""
            <div class="metric-card">
                <h3>🔍 System Status</h3>
                <h2 style="color: {status_color};">{status.upper()}</h2>
                <p>Data collection health</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            sources_configured = health_data.get('sources_configured', 0)
            st.metric("Sources Configured", sources_configured)
        
        with col3:
            cache_age = health_data.get('cache_age_seconds', 0)
            cache_valid = health_data.get('cache_valid', False)
            
            if cache_valid:
                cache_status = "🟢 Fresh"
                cache_color = "#28a745"
            else:
                cache_status = "🟡 Stale"
                cache_color = "#ffc107"
            
            st.markdown(f"""
            <div class="metric-card">
                <h3>💾 Cache Status</h3>
                <h2 style="color: {cache_color};">{cache_status}</h2>
                <p>{cache_age}s old</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Refresh button
        if st.button("🔄 Refresh Data", type="primary"):
            refresh_result = make_api_request("/api/v1/real/refresh", method="POST")
            if refresh_result:
                st.success("✅ Data refresh initiated successfully!")
                time.sleep(2)
                st.rerun()
            else:
                st.error("❌ Failed to refresh data")
    
    else:
        st.warning("⚠️ Unable to fetch health status.")

def render_test_results():
    """Render test results"""
    st.subheader("🧪 System Test Results")
    
    # Test real scraper
    test_result = make_api_request("/api/v1/real/test")
    
    if test_result:
        status = test_result.get('status', 'error')
        
        if status == 'success':
            st.success("✅ Real scraper test passed!")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Test Source", test_result.get('test_source', 'Unknown'))
            
            with col2:
                st.metric("Articles Found", test_result.get('articles_found', 0))
            
            with col3:
                st.metric("Sources Configured", test_result.get('sources_configured', 0))
            
            # Show sample article if available
            sample_article = test_result.get('sample_article')
            if sample_article:
                st.markdown("### 📄 Sample Article")
                st.json(sample_article)
        
        else:
            st.error(f"❌ Real scraper test failed: {test_result.get('message', 'Unknown error')}")
            st.metric("Sources Configured", test_result.get('sources_count', 0))
    
    else:
        st.warning("⚠️ Unable to run system test.")

def main():
    """Main dashboard function"""
    render_header()
    
    # Sidebar for navigation
    st.sidebar.title("🛡️ CTMS Navigation")
    
    # Add refresh button in sidebar
    if st.sidebar.button("🔄 Refresh All Data", type="primary"):
        st.rerun()
    
    # Add data source toggle
    use_real_data = st.sidebar.checkbox("📰 Use Real Data", value=True, help="Toggle between real and mock data")
    
    if use_real_data:
        st.sidebar.success("✅ Using Real Threat Intelligence Data")
    else:
        st.sidebar.warning("⚠️ Using Mock Data")
    
    # Main content tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview", 
        "🔍 Threat Analysis", 
        "🌐 Sources", 
        "🏥 Health", 
        "🧪 Testing"
    ])
    
    with tab1:
        render_real_data_metrics()
        
        # Show threat timeline if available
        real_data = make_api_request("/api/v1/real/threats/intelligence")
        if real_data and real_data.get('threat_data'):
            st.markdown("### 📈 Threat Timeline")
            threat_data = real_data['threat_data']
            
            if threat_data.get('dates') and threat_data.get('counts'):
                df = pd.DataFrame({
                    'Date': threat_data['dates'],
                    'Threats': threat_data['counts']
                })
                
                fig = px.line(
                    df, 
                    x='Date', 
                    y='Threats',
                    title="Threat Activity Timeline",
                    markers=True
                )
                st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        render_real_threat_analysis()
    
    with tab3:
        render_sources_status()
    
    with tab4:
        render_data_health()
    
    with tab5:
        render_test_results()
        
        # Add manual test section
        st.markdown("### 🔧 Manual Testing")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🧪 Test Real Scraper"):
                test_result = make_api_request("/api/v1/real/test")
                if test_result:
                    st.json(test_result)
                else:
                    st.error("Test failed")
        
        with col2:
            if st.button("🔄 Force Data Refresh"):
                refresh_result = make_api_request("/api/v1/real/refresh", method="POST")
                if refresh_result:
                    st.success("Refresh initiated!")
                else:
                    st.error("Refresh failed")

if __name__ == "__main__":
    main()
"""
Cyber Threat Intelligence Dashboard - FIXED VERSION
Real-time threat intelligence with dark theme and neon accents
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import requests
import json
import os
from datetime import datetime, timedelta
import time
from typing import Dict, Any, List
import numpy as np

# Page configuration
st.set_page_config(
    page_title="Cyber Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for dark theme with neon accents
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .main {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
        color: #ffffff;
        font-family: 'Inter', sans-serif;
    }
    
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
    }
    
    .dashboard-header {
        background: linear-gradient(90deg, #00ff88, #00ccff, #ff00ff);
        background-size: 200% 200%;
        animation: gradient 3s ease infinite;
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0, 255, 136, 0.3);
    }
    
    @keyframes gradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    .kpi-card {
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 2px solid #00ff88;
        border-radius: 15px;
        padding: 1.5rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0, 255, 136, 0.2);
        transition: all 0.3s ease;
    }
    
    .kpi-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 30px rgba(0, 255, 136, 0.4);
    }
    
    .kpi-value {
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0.5rem 0;
    }
    
    .kpi-label {
        font-size: 0.9rem;
        color: #cccccc;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
        animation: pulse 2s infinite;
    }
    
    .status-green {
        background: #00ff88;
        box-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
    }
    
    .status-red {
        background: #ff0066;
        box-shadow: 0 0 10px rgba(255, 0, 102, 0.5);
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    .threat-score-badge {
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
        text-align: center;
        min-width: 60px;
        display: inline-block;
    }
    
    .score-low {
        background: #00ff88;
        color: #000;
    }
    
    .score-medium {
        background: #ffaa00;
        color: #000;
    }
    
    .score-high {
        background: #ff0066;
        color: #fff;
    }
    
    .chart-container {
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 1px solid #333333;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    
    .notable-changes {
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 1px solid #00ccff;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    
    .change-item {
        padding: 0.5rem 0;
        border-bottom: 1px solid #333333;
    }
    
    .change-item:last-child {
        border-bottom: none;
    }
    
    .increase {
        color: #00ff88;
    }
    
    .decrease {
        color: #ff0066;
    }
    
    .stDataFrame {
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 1px solid #333333;
        border-radius: 10px;
    }
    
    .stButton > button {
        background: linear-gradient(90deg, #00ff88, #00ccff);
        color: #000;
        border: none;
        border-radius: 25px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 255, 136, 0.4);
    }
    
    .refresh-info {
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 1px solid #00ccff;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Configuration
API_BASE_URL = "http://localhost:8000"
API_TOKEN = os.getenv("CTMS_API_TOKEN", "demo_token_for_development_12345")

def make_api_request(endpoint: str, timeout: int = 30) -> Dict[str, Any]:
    """Make API request with error handling and loading state"""
    try:
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        url = f"{API_BASE_URL}{endpoint}"
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.Timeout:
        st.error("API request timed out")
        return None
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to API server. Is it running?")
        return None
    except Exception as e:
        st.error(f"API Request Error: {str(e)}")
        return None

def get_threat_score_color(score: float) -> str:
    """Get color class for threat score"""
    if score < 0.5:
        return "score-low"
    elif score < 0.8:
        return "score-medium"
    else:
        return "score-high"

def format_time_ago(timestamp: str) -> str:
    """Format timestamp as time ago"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now(dt.tzinfo)
        diff = now - dt
        
        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours}h ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes}m ago"
        else:
            return "Just now"
    except:
        return "Unknown"

def generate_mock_historical_data() -> Dict[str, List]:
    """Generate mock historical data for charts"""
    dates = []
    counts = []
    
    for i in range(30):
        date = datetime.now() - timedelta(days=29-i)
        dates.append(date.strftime("%Y-%m-%d"))
        # Generate realistic data with some variation
        base_count = 15
        variation = np.random.normal(0, 5)
        count = max(0, int(base_count + variation))
        counts.append(count)
    
    return {
        "dates": dates,
        "counts": counts
    }

def render_header(api_status: bool, collection_time: str = None):
    """Render dashboard header with status indicator"""
    status_class = "status-green" if api_status else "status-red"
    status_text = "Connected" if api_status else "Disconnected"
    
    st.markdown(f"""
    <div class="dashboard-header">
        <h1 style="margin: 0; color: #000; font-weight: 700; font-size: 2.5rem;">
            🛡️ Cyber Threat Intelligence Dashboard
        </h1>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 1rem;">
            <div>
                <span class="status-indicator {status_class}"></span>
                <span style="color: #000; font-weight: 600;">API Status: {status_text}</span>
            </div>
            <div style="color: #000; font-weight: 500;">
                Last Updated: {format_time_ago(collection_time) if collection_time else 'Unknown'}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_kpi_cards(data: Dict[str, Any]):
    """Render KPI cards in a row"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_articles = data.get('total_articles', 0)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">📰 Total Articles</div>
            <div class="kpi-value" style="color: #00ff88;">{total_articles}</div>
            <div style="font-size: 0.8rem; color: #cccccc;">Real-time collection</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        sources_used = data.get('sources_used', 0)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">🌐 Sources Used</div>
            <div class="kpi-value" style="color: #00ccff;">{sources_used}</div>
            <div style="font-size: 0.8rem; color: #cccccc;">Active sources</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        avg_score = data.get('avg_threat_score', 0.0)
        score_color = "#00ff88" if avg_score < 0.5 else "#ffaa00" if avg_score < 0.8 else "#ff0066"
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">⚠️ Avg Threat Score</div>
            <div class="kpi-value" style="color: {score_color};">{avg_score:.2f}</div>
            <div style="font-size: 0.8rem; color: #cccccc;">Risk assessment</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        # Count high severity threats
        high_severity_count = 0
        if 'nlp_results' in data:
            high_severity_count = sum(1 for threat in data['nlp_results'] if threat.get('threat_score', 0) > 0.8)
        
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">🚨 High Severity</div>
            <div class="kpi-value" style="color: #ff0066;">{high_severity_count}</div>
            <div style="font-size: 0.8rem; color: #cccccc;">Score > 0.8</div>
        </div>
        """, unsafe_allow_html=True)

def render_threats_table(data: Dict[str, Any]):
    """Render threats table with sorting and search - FIXED VERSION"""
    if not data.get('nlp_results'):
        st.warning("No threat data available")
        return
    
    # Create DataFrame for the table
    threats_data = []
    for threat in data['nlp_results']:
        threats_data.append({
            'Title': threat.get('title', 'Unknown'),
            'Threat Score': threat.get('threat_score', 0.0),
            'Primary Threat': threat.get('primary_threat', 'Unknown'),
            'Source': threat.get('source', 'Unknown'),
            'Confidence': threat.get('confidence', 0.0),
            'IOCs': threat.get('iocs_extracted', 0)
        })
    
    df = pd.DataFrame(threats_data)
    
    # Add search functionality
    search_term = st.text_input("🔍 Search threats:", placeholder="Enter threat title or source...")
    if search_term:
        df = df[df['Title'].str.contains(search_term, case=False) | 
                df['Source'].str.contains(search_term, case=False)]
    
    # Display table with custom styling
    st.markdown("### 🚨 Top Threats")
    
    # Display the table with proper formatting
    if not df.empty:
        # Create a display DataFrame with formatted threat scores
        display_df = df.copy()
        
        # Format threat scores with colors
        def format_threat_score(score):
            if score < 0.5:
                return f"🟢 {score:.2f}"
            elif score < 0.8:
                return f"🟡 {score:.2f}"
            else:
                return f"🔴 {score:.2f}"
        
        display_df['Threat Score'] = display_df['Threat Score'].apply(format_threat_score)
        
        # Show the table
        st.dataframe(
            display_df[['Title', 'Threat Score', 'Primary Threat', 'Source']],
            use_container_width=True,
            hide_index=True
        )
        
        # Show additional info
        st.markdown("**Legend:** 🟢 Low Risk | 🟡 Medium Risk | 🔴 High Risk")
    else:
        st.info("No threats found matching your search criteria.")

def render_threat_categories_chart(data: Dict[str, Any]):
    """Render threat categories pie chart"""
    if not data.get('nlp_results'):
        st.warning("No threat data available")
        return
    
    # Count threat categories
    categories = {}
    for threat in data['nlp_results']:
        category = threat.get('primary_threat', 'Unknown')
        categories[category] = categories.get(category, 0) + 1
    
    if not categories:
        st.warning("No threat categories found")
        return
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=list(categories.keys()),
        values=list(categories.values()),
        hole=0.4,
        marker_colors=['#00ff88', '#00ccff', '#ff00ff', '#ffaa00', '#ff0066', '#9933ff'],
        textinfo='label+percent+value',
        textposition='inside',
        insidetextorientation='radial'
    )])
    
    fig.update_layout(
        title="Threat Categories Distribution",
        title_font_color="#ffffff",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color="#ffffff"),
        showlegend=True,
        legend=dict(
            font=dict(color="#ffffff"),
            bgcolor='rgba(0,0,0,0)'
        )
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_historical_chart():
    """Render historical articles chart"""
    historical_data = generate_mock_historical_data()
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=historical_data['dates'],
        y=historical_data['counts'],
        mode='lines+markers',
        name='Articles Collected',
        line=dict(color='#00ff88', width=3),
        marker=dict(color='#00ff88', size=6),
        fill='tonexty',
        fillcolor='rgba(0, 255, 136, 0.1)'
    ))
    
    fig.update_layout(
        title="Historical Articles Collection (Last 30 Days)",
        title_font_color="#ffffff",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color="#ffffff"),
        xaxis=dict(
            gridcolor='#333333',
            showgrid=True
        ),
        yaxis=dict(
            gridcolor='#333333',
            showgrid=True
        ),
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_notable_changes(data: Dict[str, Any]):
    """Render notable changes section"""
    st.markdown("### 📊 Notable Changes")
    
    # Store previous data in session state for comparison
    if 'previous_data' not in st.session_state:
        st.session_state.previous_data = data
        st.info("First data collection - no previous data for comparison")
        return
    
    previous_data = st.session_state.previous_data
    
    # Compare current vs previous data
    changes = []
    
    # Compare total articles
    current_articles = data.get('total_articles', 0)
    previous_articles = previous_data.get('total_articles', 0)
    if current_articles != previous_articles:
        diff = current_articles - previous_articles
        change_type = "increase" if diff > 0 else "decrease"
        changes.append(f"📰 Articles: {diff:+d} ({change_type})")
    
    # Compare threat scores
    current_avg = data.get('avg_threat_score', 0.0)
    previous_avg = previous_data.get('avg_threat_score', 0.0)
    if abs(current_avg - previous_avg) > 0.05:
        diff = current_avg - previous_avg
        change_type = "increase" if diff > 0 else "decrease"
        changes.append(f"⚠️ Avg Threat Score: {diff:+.2f} ({change_type})")
    
    # Compare threat categories
    current_categories = {}
    previous_categories = {}
    
    for threat in data.get('nlp_results', []):
        category = threat.get('primary_threat', 'Unknown')
        current_categories[category] = current_categories.get(category, 0) + 1
    
    for threat in previous_data.get('nlp_results', []):
        category = threat.get('primary_threat', 'Unknown')
        previous_categories[category] = previous_categories.get(category, 0) + 1
    
    for category in set(current_categories.keys()) | set(previous_categories.keys()):
        current_count = current_categories.get(category, 0)
        previous_count = previous_categories.get(category, 0)
        if current_count != previous_count:
            diff = current_count - previous_count
            change_type = "increase" if diff > 0 else "decrease"
            changes.append(f"🎯 {category}: {diff:+d} ({change_type})")
    
    if changes:
        st.markdown("""
        <div class="notable-changes">
        """, unsafe_allow_html=True)
        
        for change in changes[:5]:  # Show top 5 changes
            if "increase" in change:
                st.markdown(f'<div class="change-item increase">�� {change}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="change-item decrease">📉 {change}</div>', unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No significant changes detected since last update")
    
    # Update previous data
    st.session_state.previous_data = data

def main():
    """Main dashboard function - FIXED VERSION"""
    # Clear cache on manual refresh
    if st.button("🔄 Refresh Data", type="primary"):
        st.cache_data.clear()
        st.session_state.clear()
        st.rerun()
    
    # Show refresh info
    st.markdown("""
    <div class="refresh-info">
        <span style="color: #00ccff;">⏰ Click refresh button to get latest data</span>
    </div>
    """, unsafe_allow_html=True)
    
    # Fetch data with loading spinner
    with st.spinner("🔄 Fetching threat intelligence data..."):
        summary_data = make_api_request("/api/v1/real/threats/summary")
        real_data = make_api_request("/api/v1/real/threats/intelligence")
    
    # Determine API status
    api_status = summary_data is not None and real_data is not None
    collection_time = summary_data.get('collection_time') if summary_data else None
    
    # Render header
    render_header(api_status, collection_time)
    
    if not api_status:
        st.error("❌ Unable to connect to threat intelligence API. Please check if the server is running.")
        return
    
    # Combine data
    combined_data = {**summary_data, **real_data}
    
    # Row 1: KPI Cards
    render_kpi_cards(combined_data)
    
    # Row 2: Threats Table and Categories Chart
    col1, col2 = st.columns([1, 1])
    
    with col1:
        render_threats_table(combined_data)
    
    with col2:
        render_threat_categories_chart(combined_data)
    
    # Row 3: Historical Chart and Notable Changes
    col1, col2 = st.columns([1, 1])
    
    with col1:
        render_historical_chart()
    
    with col2:
        render_notable_changes(combined_data)

if __name__ == "__main__":
    main()

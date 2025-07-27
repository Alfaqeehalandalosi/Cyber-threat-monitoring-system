# =============================================================================
# MAIN STREAMLIT DASHBOARD
# =============================================================================
"""
Main Streamlit dashboard for the Cyber Threat Monitoring System.
Provides interactive web interface for threat analysis and monitoring.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json

from ctms.core.config import settings

# Configure Streamlit page
st.set_page_config(
    page_title="Cyber Threat Monitoring System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# DASHBOARD CONFIGURATION
# =============================================================================
API_BASE_URL = f"http://localhost:{settings.api_port}"
DEMO_TOKEN = "demo_token_for_development_12345"  # For development only

# Dashboard state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()


# =============================================================================
# API CLIENT FUNCTIONS
# =============================================================================
def make_api_request(endpoint: str, method: str = "GET", data: Dict = None) -> Optional[Dict]:
    """
    Make API request to the backend.
    
    Args:
        endpoint: API endpoint
        method: HTTP method
        data: Request data for POST/PUT
        
    Returns:
        Optional[Dict]: API response data
    """
    try:
        headers = {
            "Authorization": f"Bearer {DEMO_TOKEN}",
            "Content-Type": "application/json"
        }
        
        url = f"{API_BASE_URL}{endpoint}"
        
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=30)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=30)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data, timeout=30)
        else:
            return None
        
        if response.status_code in [200, 201]:
            return response.json()
        else:
            st.error(f"API Error: {response.status_code} - {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        st.error(f"Connection Error: {e}")
        return None
    except Exception as e:
        st.error(f"Unexpected Error: {e}")
        return None


def get_system_health() -> Dict[str, Any]:
    """Get system health status."""
    return make_api_request("/health")


def get_system_stats() -> Dict[str, Any]:
    """Get system statistics."""
    return make_api_request("/stats")


def get_iocs(limit: int = 100, ioc_type: str = None, severity: str = None) -> List[Dict]:
    """Get IOCs with filters."""
    params = f"?limit={limit}"
    if ioc_type:
        params += f"&ioc_type={ioc_type}"
    if severity:
        params += f"&severity={severity}"
    
    result = make_api_request(f"/api/v1/iocs{params}")
    return result if result else []


def get_threats(limit: int = 100, threat_type: str = None, severity: str = None) -> List[Dict]:
    """Get threats with filters."""
    params = f"?limit={limit}"
    if threat_type:
        params += f"&threat_type={threat_type}"
    if severity:
        params += f"&severity={severity}"
    
    result = make_api_request(f"/api/v1/threats{params}")
    return result if result else []


def get_alerts(limit: int = 100, status: str = None, severity: str = None) -> List[Dict]:
    """Get alerts with filters."""
    params = f"?limit={limit}"
    if status:
        params += f"&status={status}"
    if severity:
        params += f"&severity={severity}"
    
    result = make_api_request(f"/api/v1/alerts{params}")
    return result if result else []


def analyze_text(text: str) -> Dict[str, Any]:
    """Analyze text for threats and IOCs."""
    return make_api_request("/api/v1/analysis/text", "POST", {"text": text})


def search_intelligence(query: str, limit: int = 50) -> Dict[str, Any]:
    """Search threat intelligence."""
    result = make_api_request(f"/api/v1/search?q={query}&limit={limit}")
    return result if result else {}


# =============================================================================
# AUTHENTICATION
# =============================================================================
def show_login():
    """Show login interface."""
    st.title("🛡️ Cyber Threat Monitoring System")
    st.subheader("Authentication Required")
    
    with st.form("login_form"):
        username = st.text_input("Username", value="admin")
        password = st.text_input("Password", type="password", value="admin")
        
        if st.form_submit_button("Login"):
            # Simple authentication for demo
            if username == "admin" and password == "admin":
                st.session_state.authenticated = True
                st.success("✅ Login successful!")
                st.experimental_rerun()
            else:
                st.error("❌ Invalid credentials")


# =============================================================================
# MAIN DASHBOARD COMPONENTS
# =============================================================================
def show_dashboard_header():
    """Show dashboard header with system status."""
    col1, col2, col3 = st.columns([3, 1, 1])
    
    with col1:
        st.title("🛡️ Cyber Threat Monitoring System")
        st.caption("Advanced Threat Intelligence Platform")
    
    with col2:
        if st.button("🔄 Refresh", key="header_refresh"):
            st.session_state.last_refresh = datetime.now()
            st.experimental_rerun()
    
    with col3:
        # System health indicator
        health = get_system_health()
        if health and health.get("status") == "healthy":
            st.success("🟢 System Healthy")
        else:
            st.error("🔴 System Issues")


def show_metrics_overview():
    """Show key metrics overview."""
    st.subheader("📊 System Overview")
    
    # Get system statistics
    stats = get_system_stats()
    
    if stats:
        collections = stats.get("collections", {})
        recent_activity = stats.get("recent_activity", {})
        
        # Main metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                label="IOCs",
                value=collections.get("iocs", 0),
                delta=recent_activity.get("new_iocs_24h", 0),
                delta_color="inverse"
            )
        
        with col2:
            st.metric(
                label="Threats",
                value=collections.get("threats", 0),
                delta=recent_activity.get("new_threats_24h", 0),
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                label="Alerts",
                value=collections.get("alerts", 0),
                delta=recent_activity.get("new_alerts_24h", 0),
                delta_color="inverse"
            )
        
        with col4:
            st.metric(
                label="Content",
                value=collections.get("scraped_content", 0),
                delta=recent_activity.get("processed_content_24h", 0)
            )
        
        with col5:
            st.metric(
                label="Sources",
                value=collections.get("scraping_sources", 0)
            )


def show_threat_severity_chart():
    """Show threat severity distribution chart."""
    st.subheader("🔥 Threat Severity Distribution")
    
    # Get threats for analysis
    threats = get_threats(limit=1000)
    
    if threats:
        df = pd.DataFrame(threats)
        
        # Count by severity
        severity_counts = df['severity'].value_counts()
        
        # Create pie chart
        fig = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            title="Threat Severity Distribution",
            color_discrete_map={
                'critical': '#FF4B4B',
                'high': '#FF8C00',
                'medium': '#FFD700',
                'low': '#32CD32'
            }
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No threat data available")


def show_ioc_timeline():
    """Show IOC discovery timeline."""
    st.subheader("📈 IOC Discovery Timeline")
    
    # Get IOCs for timeline
    iocs = get_iocs(limit=1000)
    
    if iocs:
        df = pd.DataFrame(iocs)
        df['created_at'] = pd.to_datetime(df['created_at'])
        df['date'] = df['created_at'].dt.date
        
        # Group by date and count
        daily_counts = df.groupby('date').size().reset_index(name='count')
        
        # Create line chart
        fig = px.line(
            daily_counts,
            x='date',
            y='count',
            title='IOCs Discovered Over Time',
            labels={'count': 'Number of IOCs', 'date': 'Date'}
        )
        
        fig.update_traces(line_color='#FF6B6B', line_width=3)
        fig.update_layout(showlegend=False)
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No IOC data available")


def show_recent_alerts():
    """Show recent alerts table."""
    st.subheader("🚨 Recent Alerts")
    
    alerts = get_alerts(limit=20)
    
    if alerts:
        df = pd.DataFrame(alerts)
        
        # Format for display
        display_df = df[['title', 'severity', 'status', 'created_at']].copy()
        display_df['created_at'] = pd.to_datetime(display_df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
        
        # Style the dataframe
        def style_severity(val):
            colors = {
                'critical': 'background-color: #FFE6E6; color: #D32F2F',
                'high': 'background-color: #FFF3E0; color: #F57C00',
                'medium': 'background-color: #FFFDE7; color: #FBC02D',
                'low': 'background-color: #E8F5E8; color: #388E3C'
            }
            return colors.get(val, '')
        
        styled_df = display_df.style.applymap(style_severity, subset=['severity'])
        
        st.dataframe(styled_df, use_container_width=True)
        
        # Alert actions
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔍 View All Alerts"):
                st.session_state.active_tab = "alerts"
                st.experimental_rerun()
        
        with col2:
            if st.button("➕ Create Alert"):
                st.session_state.show_create_alert = True
    else:
        st.info("No recent alerts")


def show_ioc_analysis():
    """Show IOC analysis and search."""
    st.subheader("🔍 IOC Analysis")
    
    tab1, tab2, tab3 = st.tabs(["Browse IOCs", "Search", "Quick Analysis"])
    
    with tab1:
        # IOC filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            ioc_type_filter = st.selectbox(
                "IOC Type",
                ["All", "ip_address", "domain", "url", "file_hash", "email"],
                key="ioc_type_filter"
            )
        
        with col2:
            severity_filter = st.selectbox(
                "Severity",
                ["All", "critical", "high", "medium", "low"],
                key="ioc_severity_filter"
            )
        
        with col3:
            limit = st.number_input("Limit", min_value=10, max_value=1000, value=100)
        
        # Get filtered IOCs
        type_param = None if ioc_type_filter == "All" else ioc_type_filter
        severity_param = None if severity_filter == "All" else severity_filter
        
        iocs = get_iocs(limit=limit, ioc_type=type_param, severity=severity_param)
        
        if iocs:
            df = pd.DataFrame(iocs)
            display_columns = ['value', 'type', 'severity', 'confidence', 'source', 'created_at']
            
            if all(col in df.columns for col in display_columns):
                display_df = df[display_columns].copy()
                display_df['created_at'] = pd.to_datetime(display_df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
                
                st.dataframe(display_df, use_container_width=True)
                
                # IOC type distribution
                type_counts = df['type'].value_counts()
                fig = px.bar(
                    x=type_counts.index,
                    y=type_counts.values,
                    title="IOC Type Distribution",
                    labels={'x': 'IOC Type', 'y': 'Count'}
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.dataframe(df, use_container_width=True)
        else:
            st.info("No IOCs found matching the criteria")
    
    with tab2:
        # Search functionality
        search_query = st.text_input("Search Intelligence", placeholder="Enter IOC, domain, IP, or keyword...")
        
        if search_query:
            with st.spinner("Searching..."):
                results = search_intelligence(search_query)
            
            if results and results.get('total_results', 0) > 0:
                st.success(f"Found {results['total_results']} results")
                
                # Display results by category
                for category, items in results.get('results', {}).items():
                    if items:
                        st.subheader(f"{category.replace('ctms_', '').title()} ({len(items)})")
                        
                        # Convert to DataFrame for better display
                        df = pd.DataFrame(items)
                        st.dataframe(df, use_container_width=True)
            else:
                st.info("No results found")
    
    with tab3:
        # Quick text analysis
        st.write("Paste text to analyze for IOCs and threats:")
        
        analysis_text = st.text_area(
            "Text to analyze",
            height=200,
            placeholder="Paste suspicious text, logs, or threat intelligence here..."
        )
        
        if st.button("🔍 Analyze Text") and analysis_text:
            with st.spinner("Analyzing..."):
                analysis_results = analyze_text(analysis_text)
            
            if analysis_results:
                # Display IOCs
                iocs = analysis_results.get('iocs', {})
                if iocs:
                    st.subheader("🎯 Found IOCs")
                    for ioc_type, ioc_list in iocs.items():
                        if ioc_list:
                            st.write(f"**{ioc_type.replace('_', ' ').title()}:**")
                            for ioc in ioc_list:
                                st.write(f"- {ioc['value']} (confidence: {ioc['confidence']:.2f})")
                
                # Display classification
                classification = analysis_results.get('classification', {})
                if classification:
                    st.subheader("🏷️ Threat Classification")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Primary Threat", classification.get('primary_threat', 'Unknown'))
                    with col2:
                        st.metric("Severity", classification.get('severity', 'Unknown'))
                    with col3:
                        st.metric("Confidence", f"{classification.get('confidence', 0):.2f}")
                    
                    # Threat scores
                    threat_scores = classification.get('threat_scores', {})
                    if threat_scores:
                        st.write("**Threat Scores:**")
                        for threat, score in threat_scores.items():
                            st.progress(score, text=f"{threat}: {score:.2f}")
            else:
                st.error("Analysis failed")


def show_threat_intelligence():
    """Show threat intelligence view."""
    st.subheader("🎯 Threat Intelligence")
    
    # Get threats
    threats = get_threats(limit=100)
    
    if threats:
        df = pd.DataFrame(threats)
        
        # Threat type distribution
        col1, col2 = st.columns(2)
        
        with col1:
            type_counts = df['threat_type'].value_counts()
            fig = px.pie(
                values=type_counts.values,
                names=type_counts.index,
                title="Threat Type Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk score distribution
            fig = px.histogram(
                df,
                x='risk_score',
                nbins=20,
                title="Risk Score Distribution",
                labels={'risk_score': 'Risk Score', 'count': 'Number of Threats'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Recent threats table
        st.subheader("Recent Threats")
        display_columns = ['title', 'threat_type', 'severity', 'risk_score', 'source', 'created_at']
        
        if all(col in df.columns for col in display_columns):
            display_df = df[display_columns].copy()
            display_df['created_at'] = pd.to_datetime(display_df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
            
            st.dataframe(display_df, use_container_width=True)
        else:
            st.dataframe(df, use_container_width=True)
    else:
        st.info("No threat intelligence data available")


def show_system_administration():
    """Show system administration panel."""
    st.subheader("⚙️ System Administration")
    
    tab1, tab2, tab3 = st.tabs(["Health", "Sources", "Operations"])
    
    with tab1:
        # System health
        health = get_system_health()
        
        if health:
            st.json(health)
        else:
            st.error("Unable to retrieve system health")
    
    with tab2:
        # Scraping sources management
        st.write("### Scraping Sources")
        
        sources = make_api_request("/api/v1/scraping/sources")
        
        if sources:
            df = pd.DataFrame(sources)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No scraping sources configured")
        
        # Add new source
        with st.expander("Add New Source"):
            with st.form("add_source"):
                name = st.text_input("Source Name")
                url = st.text_input("URL")
                source_type = st.selectbox("Type", ["dark_web", "surface_web", "threat_feed"])
                enabled = st.checkbox("Enabled", value=True)
                
                if st.form_submit_button("Add Source"):
                    source_data = {
                        "name": name,
                        "url": url,
                        "source_type": source_type,
                        "enabled": enabled
                    }
                    
                    result = make_api_request("/api/v1/scraping/sources", "POST", source_data)
                    if result:
                        st.success("Source added successfully!")
                        st.experimental_rerun()
    
    with tab3:
        # System operations
        st.write("### System Operations")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🕷️ Run Scraping Cycle"):
                with st.spinner("Running scraping cycle..."):
                    result = make_api_request("/api/v1/scraping/run", "POST")
                
                if result:
                    st.success("Scraping cycle completed!")
                    st.json(result)
                else:
                    st.error("Scraping cycle failed")
        
        with col2:
            if st.button("🔄 Refresh System Stats"):
                st.session_state.last_refresh = datetime.now()
                st.experimental_rerun()


# =============================================================================
# MAIN DASHBOARD LAYOUT
# =============================================================================
def main_dashboard():
    """Main dashboard layout."""
    
    # Header
    show_dashboard_header()
    
    # Auto-refresh timer
    if datetime.now() - st.session_state.last_refresh > timedelta(minutes=5):
        st.info("Data is over 5 minutes old. Consider refreshing.")
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["Overview", "IOC Analysis", "Threat Intelligence", "Alerts", "Administration"],
        key="main_navigation"
    )
    
    # Auto-refresh setting
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)
    if auto_refresh:
        time.sleep(30)
        st.experimental_rerun()
    
    # Logout
    if st.sidebar.button("🚪 Logout"):
        st.session_state.authenticated = False
        st.experimental_rerun()
    
    # Main content based on selected page
    if page == "Overview":
        show_metrics_overview()
        
        col1, col2 = st.columns(2)
        with col1:
            show_threat_severity_chart()
        with col2:
            show_ioc_timeline()
        
        show_recent_alerts()
    
    elif page == "IOC Analysis":
        show_ioc_analysis()
    
    elif page == "Threat Intelligence":
        show_threat_intelligence()
    
    elif page == "Alerts":
        st.subheader("🚨 Alert Management")
        alerts = get_alerts(limit=200)
        
        if alerts:
            df = pd.DataFrame(alerts)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No alerts available")
    
    elif page == "Administration":
        show_system_administration()


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================
def main():
    """Main application entry point."""
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        padding: 1rem 0;
        border-bottom: 2px solid #f0f2f6;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 0.5rem 0;
    }
    
    .status-healthy {
        color: #28a745;
    }
    
    .status-unhealthy {
        color: #dc3545;
    }
    
    .sidebar .sidebar-content {
        background: #f8f9fa;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Check authentication
    if not st.session_state.authenticated:
        show_login()
    else:
        main_dashboard()


if __name__ == "__main__":
    main()
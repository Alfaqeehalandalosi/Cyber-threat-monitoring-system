#!/usr/bin/env python3
"""
Advanced Cyber Threat Monitoring Dashboard
=========================================

This dashboard provides comprehensive threat intelligence visualization,
real-time NLP analysis results, machine learning insights, and interactive
alerts as specified in the project proposal.

Features:
- Real-time threat intelligence display
- Advanced NLP and ML visualizations
- Interactive threat trend analysis
- Comprehensive IOC analysis
- Automated alert system
- Threat classification with confidence scores
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import json
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import altair as alt
from collections import defaultdict, Counter
import re

# Configure Streamlit
st.set_page_config(
    page_title="Advanced Cyber Threat Monitoring System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# CONFIGURATION
# =============================================================================
API_BASE_URL = "http://localhost:8000"
DEMO_TOKEN = "demo_token_for_development_12345"

# Color schemes for different threat types
THREAT_COLORS = {
    'malware': '#FF6B6B',
    'phishing': '#4ECDC4', 
    'apt': '#45B7D1',
    'exploit': '#96CEB4',
    'ransomware': '#FFEAA7',
    'ddos': '#DDA0DD',
    'data_breach': '#98D8C8',
    'credential_theft': '#F7DC6F'
}

SEVERITY_COLORS = {
    'critical': '#FF0000',
    'high': '#FF6B35',
    'medium': '#F7931E',
    'low': '#4CAF50',
    'info': '#2196F3'
}

# =============================================================================
# SESSION STATE MANAGEMENT
# =============================================================================
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = True  # Auto-authenticate for demo
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'threat_data' not in st.session_state:
    st.session_state.threat_data = {}
if 'nlp_results' not in st.session_state:
    st.session_state.nlp_results = {}

# =============================================================================
# API CLIENT FUNCTIONS
# =============================================================================
def make_api_request(endpoint: str, method: str = "GET", data: Dict = None) -> Optional[Dict]:
    """Make API request to backend."""
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
        else:
            return None
        
        if response.status_code in [200, 201]:
            return response.json()
        else:
            return None
            
    except:
        return None

# =============================================================================
# MOCK DATA GENERATION (for demonstration)
# =============================================================================
def generate_mock_threat_data() -> Dict[str, Any]:
    """Generate realistic mock threat data for demonstration."""
    
    # Generate timeline data for the last 30 days
    dates = pd.date_range(start=datetime.now() - timedelta(days=30), end=datetime.now(), freq='D')
    
    # Threat types with realistic distributions
    threat_types = ['malware', 'phishing', 'apt', 'exploit', 'ransomware', 'ddos', 'data_breach', 'credential_theft']
    
    # Fix the shape mismatch by generating counts properly
    threat_counts = []
    for _ in range(len(dates)):
        daily_count = np.random.poisson(10)  # Average 10 threats per day
        threat_counts.append(daily_count)
    
    # Generate detailed threat data
    threats = []
    for i, date in enumerate(dates):
        for j in range(threat_counts[i]):
            threat_type = np.random.choice(threat_types, p=[0.25, 0.20, 0.05, 0.15, 0.10, 0.10, 0.08, 0.07])
            severity = np.random.choice(['critical', 'high', 'medium', 'low'], p=[0.05, 0.20, 0.50, 0.25])
            
            threats.append({
                'id': f"threat_{i}_{j}",
                'type': threat_type,
                'severity': severity,
                'title': f"{threat_type.title()} Attack Detected",
                'description': f"Advanced {threat_type} attack targeting critical infrastructure",
                'timestamp': date + timedelta(hours=np.random.randint(0, 24)),
                'confidence': np.random.uniform(0.7, 0.98),
                'source': np.random.choice(['Bleeping Computer', 'The Hacker News', 'Security Week', 'Dark Web', 'Internal Detection']),
                'iocs_count': np.random.randint(1, 15),
                'affected_systems': np.random.randint(1, 50)
            })
    
    return {
        'threats': threats,
        'timeline_data': {
            'dates': dates.tolist(),
            'counts': threat_counts.tolist()
        },
        'summary': {
            'total_threats': len(threats),
            'critical_threats': len([t for t in threats if t['severity'] == 'critical']),
            'high_threats': len([t for t in threats if t['severity'] == 'high']),
            'by_type': Counter([t['type'] for t in threats]),
            'by_severity': Counter([t['severity'] for t in threats])
        }
    }

def generate_mock_nlp_results() -> Dict[str, Any]:
    """Generate realistic NLP analysis results."""
    
    # Mock content analysis results
    content_samples = [
        {
            'id': 'content_001',
            'title': 'New Ransomware Campaign Targeting Healthcare',
            'content': 'A sophisticated ransomware campaign has been detected targeting healthcare organizations worldwide. The malware uses advanced encryption techniques and demands payment in cryptocurrency.',
            'threat_score': 0.92,
            'confidence': 0.89,
            'primary_threat': 'ransomware',
            'secondary_threats': ['malware', 'data_breach'],
            'iocs_extracted': 8,
            'entities_found': ['healthcare', 'ransomware', 'cryptocurrency', 'encryption'],
            'sentiment': 'negative',
            'language': 'en'
        },
        {
            'id': 'content_002', 
            'title': 'APT Group Using Zero-Day Exploits',
            'content': 'Advanced Persistent Threat group APT29 has been observed using previously unknown zero-day exploits in targeted attacks against government agencies.',
            'threat_score': 0.95,
            'confidence': 0.94,
            'primary_threat': 'apt',
            'secondary_threats': ['exploit', 'targeted_attack'],
            'iocs_extracted': 12,
            'entities_found': ['APT29', 'zero-day', 'government', 'exploits'],
            'sentiment': 'negative',
            'language': 'en'
        },
        {
            'id': 'content_003',
            'title': 'Phishing Campaign Impersonating Microsoft',
            'content': 'A large-scale phishing campaign is impersonating Microsoft support to steal user credentials and gain access to corporate networks.',
            'threat_score': 0.78,
            'confidence': 0.82,
            'primary_threat': 'phishing',
            'secondary_threats': ['credential_theft', 'social_engineering'],
            'iocs_extracted': 5,
            'entities_found': ['Microsoft', 'phishing', 'credentials', 'corporate'],
            'sentiment': 'negative',
            'language': 'en'
        }
    ]
    
    # Generate NLP processing statistics
    nlp_stats = {
        'total_documents_analyzed': 1247,
        'threats_detected': 89,
        'iocs_extracted': 342,
        'entities_identified': 567,
        'processing_time_avg': 2.3,
        'accuracy_rate': 0.94,
        'false_positive_rate': 0.06
    }
    
    # Generate threat classification results
    classification_results = {
        'malware': {'detected': 45, 'confidence_avg': 0.87, 'false_positives': 3},
        'phishing': {'detected': 23, 'confidence_avg': 0.82, 'false_positives': 2},
        'apt': {'detected': 12, 'confidence_avg': 0.94, 'false_positives': 1},
        'ransomware': {'detected': 8, 'confidence_avg': 0.91, 'false_positives': 0},
        'exploit': {'detected': 15, 'confidence_avg': 0.89, 'false_positives': 2}
    }
    
    return {
        'content_analysis': content_samples,
        'statistics': nlp_stats,
        'classification_results': classification_results,
        'processing_timeline': generate_processing_timeline()
    }

def generate_processing_timeline() -> List[Dict]:
    """Generate NLP processing timeline data."""
    timeline = []
    base_time = datetime.now() - timedelta(hours=24)
    
    for i in range(24):
        time_point = base_time + timedelta(hours=i)
        timeline.append({
            'timestamp': time_point,
            'documents_processed': np.random.randint(10, 50),
            'threats_detected': np.random.randint(1, 8),
            'iocs_extracted': np.random.randint(5, 25),
            'processing_time_avg': np.random.uniform(1.5, 3.5)
        })
    
    return timeline

def generate_mock_ioc_data() -> Dict[str, Any]:
    """Generate realistic IOC data."""
    
    ioc_types = ['ip_address', 'domain', 'url', 'hash', 'email']
    ioc_data = []
    
    for i in range(100):
        ioc_type = np.random.choice(ioc_types)
        severity = np.random.choice(['critical', 'high', 'medium', 'low'], p=[0.10, 0.25, 0.40, 0.25])
        
        if ioc_type == 'ip_address':
            value = f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        elif ioc_type == 'domain':
            value = f"malicious{np.random.randint(1, 1000)}.com"
        elif ioc_type == 'url':
            value = f"https://malicious{np.random.randint(1, 1000)}.com/payload"
        elif ioc_type == 'hash':
            value = f"{'a' * 32}"  # MD5 hash
        else:  # email
            value = f"malicious{np.random.randint(1, 1000)}@evil.com"
        
        ioc_data.append({
            'id': f"ioc_{i}",
            'type': ioc_type,
            'value': value,
            'severity': severity,
            'first_seen': datetime.now() - timedelta(days=np.random.randint(1, 30)),
            'last_seen': datetime.now() - timedelta(hours=np.random.randint(1, 24)),
            'threat_type': np.random.choice(['malware', 'phishing', 'apt', 'exploit']),
            'confidence': np.random.uniform(0.7, 0.98),
            'source': np.random.choice(['NLP Analysis', 'Manual Input', 'Threat Feed', 'Internal Detection'])
        })
    
    return {
        'iocs': ioc_data,
        'summary': {
            'total_iocs': len(ioc_data),
            'by_type': Counter([ioc['type'] for ioc in ioc_data]),
            'by_severity': Counter([ioc['severity'] for ioc in ioc_data]),
            'by_threat_type': Counter([ioc['threat_type'] for ioc in ioc_data])
        }
    }

# =============================================================================
# DASHBOARD COMPONENTS
# =============================================================================
def render_header():
    """Render the main dashboard header."""
    st.markdown("""
    <div style="text-align: center; padding: 2rem 0; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); border-radius: 10px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0; font-size: 3rem;">🛡️ Advanced Cyber Threat Monitoring System</h1>
        <p style="color: white; margin: 0.5rem 0 0 0; font-size: 1.2rem;">Real-time Threat Intelligence & NLP Analysis Dashboard</p>
        <p style="color: #f0f0f0; margin: 0.5rem 0 0 0; font-size: 1rem;">Powered by Advanced NLP & Machine Learning</p>
    </div>
    """, unsafe_allow_html=True)

def render_metrics_overview():
    """Render comprehensive metrics overview."""
    st.subheader("📊 Real-Time System Metrics")
    
    # Get or generate data
    if not st.session_state.threat_data:
        st.session_state.threat_data = generate_mock_threat_data()
    
    if not st.session_state.nlp_results:
        st.session_state.nlp_results = generate_mock_nlp_results()
    
    threat_data = st.session_state.threat_data
    nlp_data = st.session_state.nlp_results
    
    # Create metrics columns
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="🚨 Active Threats",
            value=threat_data['summary']['total_threats'],
            delta=f"+{np.random.randint(5, 15)} today",
            delta_color="inverse"
        )
    
    with col2:
        st.metric(
            label="🔍 IOCs Detected",
            value=nlp_data['statistics']['iocs_extracted'],
            delta=f"+{np.random.randint(10, 30)} today",
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            label="📄 Documents Analyzed",
            value=nlp_data['statistics']['total_documents_analyzed'],
            delta=f"+{np.random.randint(50, 150)} today"
        )
    
    with col4:
        st.metric(
            label="🎯 NLP Accuracy",
            value=f"{nlp_data['statistics']['accuracy_rate']:.1%}",
            delta=f"+{np.random.uniform(0.01, 0.03):.1%}",
            delta_color="normal"
        )
    
    with col5:
        st.metric(
            label="⚡ Processing Time",
            value=f"{nlp_data['statistics']['processing_time_avg']:.1f}s",
            delta=f"-{np.random.uniform(0.1, 0.5):.1f}s",
            delta_color="normal"
        )

def render_threat_timeline():
    """Render interactive threat timeline."""
    st.subheader("📈 Real-Time Threat Timeline")
    
    threat_data = st.session_state.threat_data
    
    # Create timeline chart
    df_timeline = pd.DataFrame({
        'Date': threat_data['timeline_data']['dates'],
        'Threats': threat_data['timeline_data']['counts']
    })
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=df_timeline['Date'],
        y=df_timeline['Threats'],
        mode='lines+markers',
        name='Threats Detected',
        line=dict(color='#FF6B6B', width=3),
        marker=dict(size=8, color='#FF6B6B'),
        fill='tonexty',
        fillcolor='rgba(255, 107, 107, 0.1)'
    ))
    
    fig.update_layout(
        title="Threat Detection Timeline (Last 30 Days)",
        xaxis_title="Date",
        yaxis_title="Number of Threats",
        hovermode='x unified',
        showlegend=False,
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_threat_classification():
    """Render threat classification with ML insights."""
    st.subheader("🧠 Machine Learning Threat Classification")
    
    nlp_data = st.session_state.nlp_results
    classification = nlp_data['classification_results']
    
    # Create subplot for classification results
    fig = make_subplots(
        rows=1, cols=2,
        subplot_titles=('Threat Detection by Type', 'Classification Confidence'),
        specs=[[{"type": "bar"}, {"type": "bar"}]]
    )
    
    # Threat detection counts
    threat_types = list(classification.keys())
    detection_counts = [classification[t]['detected'] for t in threat_types]
    
    fig.add_trace(
        go.Bar(
            x=threat_types,
            y=detection_counts,
            name='Detected',
            marker_color=[THREAT_COLORS.get(t, '#666') for t in threat_types],
            text=detection_counts,
            textposition='auto'
        ),
        row=1, col=1
    )
    
    # Confidence scores
    confidence_scores = [classification[t]['confidence_avg'] for t in threat_types]
    
    fig.add_trace(
        go.Bar(
            x=threat_types,
            y=confidence_scores,
            name='Confidence',
            marker_color=[THREAT_COLORS.get(t, '#666') for t in threat_types],
            text=[f"{c:.2f}" for c in confidence_scores],
            textposition='auto'
        ),
        row=1, col=2
    )
    
    fig.update_layout(
        height=400,
        showlegend=False,
        title_text="ML-Powered Threat Classification Results"
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Add classification insights
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🔍 Classification Insights:**")
        st.markdown("""
        - **APT Detection**: Highest confidence (94%) due to sophisticated patterns
        - **Ransomware**: 91% confidence with low false positive rate
        - **Phishing**: Moderate confidence (82%) due to evolving tactics
        - **Overall Accuracy**: 94% with 6% false positive rate
        """)
    
    with col2:
        st.markdown("**📊 Performance Metrics:**")
        st.markdown(f"""
        - **Total Documents**: {nlp_data['statistics']['total_documents_analyzed']:,}
        - **Threats Detected**: {nlp_data['statistics']['threats_detected']}
        - **IOCs Extracted**: {nlp_data['statistics']['iocs_extracted']}
        - **Processing Speed**: {nlp_data['statistics']['processing_time_avg']:.1f}s avg
        """)

def render_nlp_analysis_results():
    """Render detailed NLP analysis results."""
    st.subheader("🧠 Natural Language Processing Analysis")
    
    nlp_data = st.session_state.nlp_results
    
    # Show content analysis examples
    st.markdown("**📝 Content Analysis Examples:**")
    
    for i, content in enumerate(nlp_data['content_analysis']):
        with st.expander(f"📄 {content['title']} (Score: {content['threat_score']:.2f})"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Content:** {content['content']}")
                st.markdown(f"**Primary Threat:** {content['primary_threat'].title()}")
                st.markdown(f"**Secondary Threats:** {', '.join([t.title() for t in content['secondary_threats']])}")
            
            with col2:
                # Threat score gauge
                fig = go.Figure(go.Indicator(
                    mode="gauge+number+delta",
                    value=content['threat_score'] * 100,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Threat Score"},
                    delta={'reference': 50},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 50], 'color': "lightgray"},
                            {'range': [50, 80], 'color': "yellow"},
                            {'range': [80, 100], 'color': "red"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 90
                        }
                    }
                ))
                fig.update_layout(height=200)
                st.plotly_chart(fig, use_container_width=True)
            
            # Entities and IOCs
            col3, col4 = st.columns(2)
            with col3:
                st.markdown("**🔍 Extracted Entities:**")
                for entity in content['entities_found']:
                    st.markdown(f"- {entity}")
            
            with col4:
                st.markdown("**🎯 IOCs Extracted:**")
                st.metric("Count", content['iocs_extracted'])
                st.metric("Confidence", f"{content['confidence']:.2f}")

def render_ioc_analysis():
    """Render comprehensive IOC analysis."""
    st.subheader("🎯 Indicators of Compromise (IOC) Analysis")
    
    # Generate IOC data if not exists
    if 'ioc_data' not in st.session_state:
        st.session_state.ioc_data = generate_mock_ioc_data()
    
    ioc_data = st.session_state.ioc_data
    
    # IOC distribution charts
    col1, col2 = st.columns(2)
    
    with col1:
        # IOC types distribution
        ioc_types = list(ioc_data['summary']['by_type'].keys())
        ioc_counts = list(ioc_data['summary']['by_type'].values())
        
        fig = px.pie(
            values=ioc_counts,
            names=ioc_types,
            title="IOC Distribution by Type",
            color_discrete_map={
                'ip_address': '#FF6B6B',
                'domain': '#4ECDC4',
                'url': '#45B7D1',
                'hash': '#96CEB4',
                'email': '#FFEAA7'
            }
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # IOC severity distribution
        severity_types = list(ioc_data['summary']['by_severity'].keys())
        severity_counts = list(ioc_data['summary']['by_severity'].values())
        
        fig = px.bar(
            x=severity_types,
            y=severity_counts,
            title="IOC Distribution by Severity",
            color=severity_types,
            color_discrete_map=SEVERITY_COLORS
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent IOCs table
    st.markdown("**🕒 Recent IOCs Detected:**")
    
    recent_iocs = sorted(ioc_data['iocs'], key=lambda x: x['last_seen'], reverse=True)[:10]
    ioc_df = pd.DataFrame(recent_iocs)
    
    # Format the dataframe for display
    display_df = ioc_df[['type', 'value', 'severity', 'threat_type', 'confidence', 'source']].copy()
    display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x:.2f}")
    
    st.dataframe(
        display_df,
        use_container_width=True,
        column_config={
            "type": "Type",
            "value": "Value", 
            "severity": "Severity",
            "threat_type": "Threat Type",
            "confidence": "Confidence",
            "source": "Source"
        }
    )

def render_real_time_alerts():
    """Render real-time alert system."""
    st.subheader("🚨 Real-Time Alert System")
    
    # Generate mock alerts
    if not st.session_state.alerts:
        alert_types = [
            "Critical malware detected",
            "High-confidence phishing campaign",
            "APT activity observed", 
            "Zero-day exploit detected",
            "Data breach indicators",
            "Ransomware encryption detected"
        ]
        
        for i in range(10):
            alert_type = np.random.choice(alert_types)
            severity = np.random.choice(['critical', 'high', 'medium'], p=[0.2, 0.4, 0.4])
            
            st.session_state.alerts.append({
                'id': f"alert_{i}",
                'type': alert_type,
                'severity': severity,
                'timestamp': datetime.now() - timedelta(minutes=np.random.randint(1, 60)),
                'description': f"{alert_type} requiring immediate attention",
                'status': np.random.choice(['new', 'investigating', 'resolved'], p=[0.4, 0.4, 0.2])
            })
    
    # Alert summary
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🚨 New Alerts", len([a for a in st.session_state.alerts if a['status'] == 'new']))
    
    with col2:
        st.metric("🔍 Investigating", len([a for a in st.session_state.alerts if a['status'] == 'investigating']))
    
    with col3:
        st.metric("✅ Resolved", len([a for a in st.session_state.alerts if a['status'] == 'resolved']))
    
    with col4:
        st.metric("⚡ Response Time", "2.3 min")
    
    # Alerts table with interactive features
    st.markdown("**📋 Active Alerts:**")
    
    alerts_df = pd.DataFrame(st.session_state.alerts)
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.selectbox("Filter by Severity", ["All"] + list(SEVERITY_COLORS.keys()))
    
    with col2:
        status_filter = st.selectbox("Filter by Status", ["All", "new", "investigating", "resolved"])
    
    with col3:
        if st.button("🔄 Refresh Alerts"):
            st.rerun()
    
    # Apply filters
    if severity_filter != "All":
        alerts_df = alerts_df[alerts_df['severity'] == severity_filter]
    
    if status_filter != "All":
        alerts_df = alerts_df[alerts_df['status'] == status_filter]
    
    # Display filtered alerts
    if not alerts_df.empty:
        # Style the dataframe
        def style_alert_row(row):
            if row['severity'] == 'critical':
                return ['background-color: #ffebee'] * len(row)
            elif row['severity'] == 'high':
                return ['background-color: #fff3e0'] * len(row)
            else:
                return ['background-color: #f3e5f5'] * len(row)
        
        st.dataframe(
            alerts_df[['type', 'severity', 'timestamp', 'status']],
            use_container_width=True,
            column_config={
                "type": "Alert Type",
                "severity": "Severity",
                "timestamp": "Time",
                "status": "Status"
            }
        )
    else:
        st.info("No alerts match the selected filters.")

def render_threat_intelligence():
    """Render threat intelligence insights."""
    st.subheader("🔍 Threat Intelligence Insights")
    
    threat_data = st.session_state.threat_data
    
    # Threat intelligence summary
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**📊 Threat Intelligence Summary:**")
        
        # Create threat intelligence metrics
        intel_metrics = {
            "Total Threats Analyzed": threat_data['summary']['total_threats'],
            "Critical Threats": threat_data['summary']['critical_threats'],
            "High Priority": threat_data['summary']['high_threats'],
            "Threat Sources": len(set([t['source'] for t in threat_data['threats']])),
            "Average Confidence": f"{np.mean([t['confidence'] for t in threat_data['threats']]):.2f}",
            "IOCs per Threat": f"{np.mean([t['iocs_count'] for t in threat_data['threats']]):.1f}"
        }
        
        for metric, value in intel_metrics.items():
            st.metric(metric, value)
    
    with col2:
        st.markdown("**🎯 Key Intelligence Findings:**")
        
        findings = [
            "🔴 **Ransomware attacks increased 45% this month**",
            "🟡 **APT groups targeting healthcare sector**", 
            "🟢 **Phishing campaigns using COVID-19 themes**",
            "🔵 **New zero-day exploits in wild**",
            "🟣 **Data breaches affecting 2M+ records**"
        ]
        
        for finding in findings:
            st.markdown(finding)
    
    # Threat correlation analysis
    st.markdown("**🔗 Threat Correlation Analysis:**")
    
    # Create correlation matrix
    threat_types = list(threat_data['summary']['by_type'].keys())
    correlation_data = np.random.rand(len(threat_types), len(threat_types))
    np.fill_diagonal(correlation_data, 1.0)
    
    fig = px.imshow(
        correlation_data,
        x=threat_types,
        y=threat_types,
        title="Threat Type Correlation Matrix",
        color_continuous_scale='RdBu'
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_system_health():
    """Render system health and performance."""
    st.subheader("⚙️ System Health & Performance")
    
    # System metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🖥️ CPU Usage", "45%", "-5%")
    
    with col2:
        st.metric("💾 Memory Usage", "62%", "+2%")
    
    with col3:
        st.metric("💿 Disk Usage", "28%", "0%")
    
    with col4:
        st.metric("🌐 Network I/O", "1.2 MB/s", "+0.3 MB/s")
    
    # Performance timeline
    st.markdown("**📈 NLP Processing Performance:**")
    
    nlp_data = st.session_state.nlp_results
    timeline_data = nlp_data['processing_timeline']
    
    df_timeline = pd.DataFrame(timeline_data)
    df_timeline['timestamp'] = pd.to_datetime(df_timeline['timestamp'])
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Documents Processed per Hour', 'Average Processing Time'),
        vertical_spacing=0.1
    )
    
    fig.add_trace(
        go.Scatter(
            x=df_timeline['timestamp'],
            y=df_timeline['documents_processed'],
            mode='lines+markers',
            name='Documents',
            line=dict(color='#4ECDC4')
        ),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(
            x=df_timeline['timestamp'],
            y=df_timeline['processing_time_avg'],
            mode='lines+markers',
            name='Time (s)',
            line=dict(color='#FF6B6B')
        ),
        row=2, col=1
    )
    
    fig.update_layout(height=500, showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

# =============================================================================
# MAIN DASHBOARD LAYOUT
# =============================================================================
def main():
    """Main dashboard application."""
    
    # Custom CSS for enhanced styling
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin: 0.5rem 0;
    }
    
    .alert-critical {
        background: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    
    .alert-high {
        background: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    
    .sidebar .sidebar-content {
        background: #f8f9fa;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #f0f2f6;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #667eea;
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Render header
    render_header()
    
    # Sidebar controls
    st.sidebar.title("🎛️ Control Panel")
    
    # Auto-refresh
    auto_refresh = st.sidebar.checkbox("🔄 Auto Refresh (30s)", value=False)
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    # Manual refresh
    if st.sidebar.button("🔄 Manual Refresh"):
        st.rerun()
    
    # System status
    st.sidebar.markdown("---")
    st.sidebar.markdown("**📊 System Status:**")
    st.sidebar.success("✅ All Systems Operational")
    st.sidebar.info("🔄 Last Updated: " + datetime.now().strftime("%H:%M:%S"))
    
    # Main content tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 Overview", 
        "🧠 NLP Analysis", 
        "🎯 IOC Analysis", 
        "🚨 Alerts", 
        "🔍 Intelligence",
        "⚙️ System Health"
    ])
    
    with tab1:
        render_metrics_overview()
        render_threat_timeline()
        render_threat_classification()
    
    with tab2:
        render_nlp_analysis_results()
    
    with tab3:
        render_ioc_analysis()
    
    with tab4:
        render_real_time_alerts()
    
    with tab5:
        render_threat_intelligence()
    
    with tab6:
        render_system_health()
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666; padding: 1rem;'>"
        "🛡️ Advanced Cyber Threat Monitoring System | "
        "Powered by NLP & Machine Learning | "
        f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
"""
Advanced Threat Analyzer
NLP and ML-based threat intelligence analysis for academic cybersecurity research
"""

import re
import json
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import logging
from collections import Counter
import hashlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import pickle
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedThreatAnalyzer:
    """Advanced threat intelligence analyzer with NLP and ML capabilities"""
    
    def __init__(self):
        self.config = self._load_config()
        self.ml_pipeline = None
        self.vectorizer = None
        self.classifier = None
        self.is_trained = False
        self._initialize_ml_components()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load advanced threat analysis configuration"""
        try:
            with open('ctms/config/advanced_sources.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading advanced sources config: {str(e)}")
            return {}
    
    def _initialize_ml_components(self):
        """Initialize machine learning components"""
        try:
            # Initialize TF-IDF vectorizer
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.95
            )
            
            # Initialize classifier
            self.classifier = MultinomialNB()
            
            # Create pipeline
            self.ml_pipeline = Pipeline([
                ('tfidf', self.vectorizer),
                ('classifier', self.classifier)
            ])
            
            # Try to load pre-trained model
            self._load_trained_model()
            
        except Exception as e:
            logger.error(f"Error initializing ML components: {str(e)}")
    
    def _load_trained_model(self):
        """Load pre-trained model if available"""
        model_path = 'ctms/models/threat_classifier.pkl'
        try:
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.ml_pipeline = pickle.load(f)
                self.is_trained = True
                logger.info("Loaded pre-trained threat classifier model")
        except Exception as e:
            logger.warning(f"Could not load pre-trained model: {str(e)}")
    
    def _save_trained_model(self):
        """Save trained model"""
        try:
            os.makedirs('ctms/models', exist_ok=True)
            model_path = 'ctms/models/threat_classifier.pkl'
            with open(model_path, 'wb') as f:
                pickle.dump(self.ml_pipeline, f)
            logger.info("Saved trained threat classifier model")
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
    
    def extract_features(self, text: str) -> Dict[str, Any]:
        """Extract features from text for threat analysis"""
        features = {
            'text_length': len(text),
            'word_count': len(text.split()),
            'has_urls': bool(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)),
            'has_cve': bool(re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)),
            'has_ip_addresses': bool(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)),
            'has_emails': bool(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)),
            'has_hashes': bool(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)),
            'has_code_snippets': bool(re.findall(r'(?:function|class|def|import|require|include)', text)),
            'has_commands': bool(re.findall(r'(?:cmd|powershell|bash|sh|\.exe|\.bat)', text, re.IGNORECASE))
        }
        
        # Keyword-based features
        keywords = self.config.get('threat_keywords', {})
        for category, keyword_list in keywords.items():
            features[f'keyword_{category}'] = sum(1 for keyword in keyword_list if keyword.lower() in text.lower())
        
        return features
    
    def calculate_advanced_threat_score(self, article: Dict[str, Any]) -> float:
        """Calculate advanced threat score using multiple factors"""
        score = 0.0
        text = f"{article.get('title', '')} {article.get('content', '')}"
        
        # Extract features
        features = self.extract_features(text)
        
        # Base score from source trust level
        source_type = article.get('source_type', 'unknown')
        trust_levels = self.config.get('threat_scoring', {}).get('source_trust_levels', {})
        score += trust_levels.get(source_type, 0.5)
        
        # Keyword-based scoring
        keyword_weights = self.config.get('threat_scoring', {}).get('keyword_weights', {})
        for category, weight in keyword_weights.items():
            if features.get(f'keyword_{category}', 0) > 0:
                score += weight * min(features[f'keyword_{category}'], 3) / 3
        
        # Feature-based scoring
        if features['has_cve']:
            score += 0.2
        if features['has_code_snippets']:
            score += 0.15
        if features['has_commands']:
            score += 0.1
        if features['has_hashes']:
            score += 0.1
        if features['has_urls']:
            score += 0.05
        
        # Recency factor
        published = article.get('published', '')
        if published:
            try:
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                days_old = (datetime.now(pub_date.tzinfo) - pub_date).days
                if days_old < 1:
                    score += 0.2
                elif days_old < 7:
                    score += 0.1
                elif days_old < 30:
                    score += 0.05
            except:
                pass
        
        # ML-based classification if available
        if self.is_trained:
            try:
                ml_score = self._get_ml_prediction(text)
                score = (score + ml_score) / 2  # Average of rule-based and ML scores
            except Exception as e:
                logger.warning(f"ML prediction failed: {str(e)}")
        
        return min(1.0, max(0.0, score))
    
    def _get_ml_prediction(self, text: str) -> float:
        """Get machine learning prediction for threat score"""
        try:
            # Predict threat class (0: low, 1: medium, 2: high)
            prediction = self.ml_pipeline.predict([text])[0]
            # Convert to score (0.0 to 1.0)
            return prediction / 2.0
        except Exception as e:
            logger.error(f"ML prediction error: {str(e)}")
            return 0.5
    
    def classify_threat_type(self, article: Dict[str, Any]) -> str:
        """Classify threat type using advanced analysis"""
        text = f"{article.get('title', '')} {article.get('content', '')}"
        text_lower = text.lower()
        
        # Priority-based classification
        if any(word in text_lower for word in ['zero-day', '0day', 'zero day']):
            return 'zero_day'
        elif any(word in text_lower for word in ['remote code execution', 'RCE', 'code execution']):
            return 'remote_code_execution'
        elif any(word in text_lower for word in ['data breach', 'leak', 'stolen', 'compromised']):
            return 'data_breach'
        elif any(word in text_lower for word in ['malware', 'ransomware', 'trojan', 'virus']):
            return 'malware'
        elif any(word in text_lower for word in ['exploit', 'PoC', 'proof of concept']):
            return 'exploit'
        elif any(word in text_lower for word in ['vulnerability', 'CVE', 'security flaw']):
            return 'vulnerability'
        elif any(word in text_lower for word in ['phishing', 'social engineering']):
            return 'social_engineering'
        else:
            return 'general_threat'
    
    def extract_indicators(self, article: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat indicators from article"""
        text = f"{article.get('title', '')} {article.get('content', '')}"
        
        indicators = {
            'cve_ids': re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE),
            'ip_addresses': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text),
            'domains': re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', text),
            'email_addresses': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text),
            'hashes': re.findall(r'\b[a-fA-F0-9]{32,64}\b', text),
            'urls': re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text),
            'file_paths': re.findall(r'(?:/[^/\s]+)+', text),
            'commands': re.findall(r'(?:cmd|powershell|bash|sh|\.exe|\.bat)[\s\S]*?(?:\n|$)', text, re.IGNORECASE)
        }
        
        return indicators
    
    def analyze_threat_trends(self, articles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat trends across articles"""
        if not articles:
            return {}
        
        # Threat type distribution
        threat_types = [article.get('threat_type', 'unknown') for article in articles]
        threat_type_counts = Counter(threat_types)
        
        # Source type distribution
        source_types = [article.get('source_type', 'unknown') for article in articles]
        source_type_counts = Counter(source_types)
        
        # Threat score distribution
        threat_scores = [article.get('threat_score', 0) for article in articles]
        avg_threat_score = np.mean(threat_scores) if threat_scores else 0
        
        # High severity threats
        high_severity = [a for a in articles if a.get('threat_score', 0) > 0.8]
        
        # Time-based analysis
        recent_articles = []
        for article in articles:
            try:
                published = article.get('published', '')
                if published:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    if (datetime.now(pub_date.tzinfo) - pub_date).days < 7:
                        recent_articles.append(article)
            except:
                pass
        
        # Indicator analysis
        all_indicators = {}
        for article in articles:
            indicators = self.extract_indicators(article)
            for indicator_type, values in indicators.items():
                if indicator_type not in all_indicators:
                    all_indicators[indicator_type] = []
                all_indicators[indicator_type].extend(values)
        
        # Remove duplicates from indicators
        for indicator_type in all_indicators:
            all_indicators[indicator_type] = list(set(all_indicators[indicator_type]))
        
        return {
            'total_articles': len(articles),
            'threat_type_distribution': dict(threat_type_counts),
            'source_type_distribution': dict(source_type_counts),
            'average_threat_score': avg_threat_score,
            'high_severity_count': len(high_severity),
            'recent_articles_count': len(recent_articles),
            'indicators_found': {k: len(v) for k, v in all_indicators.items()},
            'top_indicators': {k: v[:10] for k, v in all_indicators.items() if v},  # Top 10 of each type
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def generate_threat_report(self, articles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence report"""
        if not articles:
            return {'error': 'No articles to analyze'}
        
        # Analyze trends
        trends = self.analyze_threat_trends(articles)
        
        # Top threats by score
        top_threats = sorted(articles, key=lambda x: x.get('threat_score', 0), reverse=True)[:10]
        
        # Critical threats (score > 0.9)
        critical_threats = [a for a in articles if a.get('threat_score', 0) > 0.9]
        
        # Recent threats (last 24 hours)
        recent_threats = []
        for article in articles:
            try:
                published = article.get('published', '')
                if published:
                    pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    if (datetime.now(pub_date.tzinfo) - pub_date).days < 1:
                        recent_threats.append(article)
            except:
                pass
        
        # Threat recommendations
        recommendations = self._generate_recommendations(articles, trends)
        
        return {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'articles_analyzed': len(articles),
                'analysis_duration': 'real-time'
            },
            'executive_summary': {
                'total_threats': len(articles),
                'critical_threats': len(critical_threats),
                'recent_threats': len(recent_threats),
                'average_severity': trends.get('average_threat_score', 0),
                'top_threat_type': max(trends.get('threat_type_distribution', {}).items(), key=lambda x: x[1])[0] if trends.get('threat_type_distribution') else 'unknown'
            },
            'threat_analysis': trends,
            'top_threats': top_threats,
            'critical_threats': critical_threats,
            'recent_threats': recent_threats,
            'recommendations': recommendations
        }
    
    def _generate_recommendations(self, articles: List[Dict[str, Any]], trends: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on threat analysis"""
        recommendations = []
        
        # High severity threats
        high_severity_count = trends.get('high_severity_count', 0)
        if high_severity_count > 5:
            recommendations.append(f"High number of high-severity threats detected ({high_severity_count}). Consider immediate security review.")
        
        # Zero-day threats
        zero_day_count = trends.get('threat_type_distribution', {}).get('zero_day', 0)
        if zero_day_count > 0:
            recommendations.append(f"Zero-day vulnerabilities detected ({zero_day_count}). Prioritize patch management and monitoring.")
        
        # Data breach threats
        data_breach_count = trends.get('threat_type_distribution', {}).get('data_breach', 0)
        if data_breach_count > 3:
            recommendations.append(f"Multiple data breach threats detected ({data_breach_count}). Review data protection measures.")
        
        # Malware threats
        malware_count = trends.get('threat_type_distribution', {}).get('malware', 0)
        if malware_count > 5:
            recommendations.append(f"High malware activity detected ({malware_count}). Update antivirus and review endpoint security.")
        
        # Recent threats
        recent_count = trends.get('recent_articles_count', 0)
        if recent_count > 10:
            recommendations.append(f"High volume of recent threats ({recent_count}). Consider increasing monitoring frequency.")
        
        # CVE indicators
        cve_count = trends.get('indicators_found', {}).get('cve_ids', 0)
        if cve_count > 20:
            recommendations.append(f"Many CVE references detected ({cve_count}). Review vulnerability management process.")
        
        if not recommendations:
            recommendations.append("No immediate action required. Continue monitoring threat landscape.")
        
        return recommendations
    
    def train_model(self, training_data: List[Tuple[str, int]]):
        """Train the machine learning model with labeled data"""
        try:
            texts, labels = zip(*training_data)
            self.ml_pipeline.fit(texts, labels)
            self.is_trained = True
            self._save_trained_model()
            logger.info("Successfully trained threat classifier model")
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")

# Utility functions
def analyze_articles(articles: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze a list of articles and return comprehensive threat intelligence"""
    analyzer = AdvancedThreatAnalyzer()
    
    # Enhance articles with advanced analysis
    enhanced_articles = []
    for article in articles:
        enhanced_article = article.copy()
        enhanced_article['threat_score'] = analyzer.calculate_advanced_threat_score(article)
        enhanced_article['threat_type'] = analyzer.classify_threat_type(article)
        enhanced_article['indicators'] = analyzer.extract_indicators(article)
        enhanced_articles.append(enhanced_article)
    
    # Generate comprehensive report
    report = analyzer.generate_threat_report(enhanced_articles)
    
    return {
        'enhanced_articles': enhanced_articles,
        'threat_report': report,
        'analysis_timestamp': datetime.now().isoformat()
    }

if __name__ == "__main__":
    # Test the advanced analyzer
    test_articles = [
        {
            'title': 'Critical CVE-2024-1234 Remote Code Execution Vulnerability',
            'content': 'A critical vulnerability has been discovered that allows remote code execution.',
            'source': 'Security Blog',
            'source_type': 'research',
            'published': datetime.now().isoformat()
        },
        {
            'title': 'New Zero-Day Exploit for Windows Systems',
            'content': 'Researchers have found a zero-day exploit affecting Windows systems.',
            'source': 'GitHub',
            'source_type': 'github',
            'published': datetime.now().isoformat()
        }
    ]
    
    result = analyze_articles(test_articles)
    print("Advanced Threat Analysis Results:")
    print(f"Enhanced articles: {len(result['enhanced_articles'])}")
    print(f"Average threat score: {np.mean([a['threat_score'] for a in result['enhanced_articles']]):.2f}")
    print(f"Threat types: {list(set(a['threat_type'] for a in result['enhanced_articles']))}")
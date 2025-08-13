"""
Threat Analyzer Module
Basic threat analysis functionality
"""

import re
from datetime import datetime
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    """Basic threat analyzer"""
    
    def __init__(self):
        self.threat_keywords = [
            'vulnerability', 'exploit', 'malware', 'ransomware', 'phishing',
            'breach', 'attack', 'hack', 'cyber', 'security', 'threat'
        ]
    
    def analyze_articles(self, articles: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze articles for threats"""
        try:
            total_articles = len(articles)
            threat_articles = []
            
            for article in articles:
                text = f"{article.get('title', '')} {article.get('content', '')}"
                threat_score = self._calculate_threat_score(text)
                
                if threat_score > 0.5:
                    threat_articles.append({
                        **article,
                        'threat_score': threat_score
                    })
            
            return {
                'total_articles': total_articles,
                'threat_articles': threat_articles,
                'threat_count': len(threat_articles),
                'analysis_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}")
            return {}
    
    def _calculate_threat_score(self, text: str) -> float:
        """Calculate threat score for text"""
        try:
            text_lower = text.lower()
            keyword_matches = sum(1 for keyword in self.threat_keywords if keyword in text_lower)
            return min(1.0, keyword_matches / len(self.threat_keywords))
        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return 0.0
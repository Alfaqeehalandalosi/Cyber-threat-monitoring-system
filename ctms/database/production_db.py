"""
Production Database Service
Fast data retrieval for the hacker-grade threat intelligence system
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import asyncio
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class ProductionDatabase:
    """Production database service for fast data access"""
    
    def __init__(self, db_path: str = "ctms/data/threat_intelligence.db"):
        self.db_path = db_path
        self._cache = {}
        self._cache_ttl = 60  # 1 minute cache
    
    def _get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    async def get_recent_threats(self, limit: int = 100, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent threats from database"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get threats from last N hours
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            cursor.execute('''
                SELECT id, title, content, threat_score, threat_type, source, source_type,
                       published_at, collected_at, indicators, hash_id
                FROM threats 
                WHERE status = 'active' AND collected_at >= ?
                ORDER BY collected_at DESC
                LIMIT ?
            ''', (cutoff_time.isoformat(), limit))
            
            rows = cursor.fetchall()
            threats = []
            
            for row in rows:
                threat = {
                    'id': row[0],
                    'title': row[1],
                    'content': row[2],
                    'threat_score': row[3],
                    'threat_type': row[4],
                    'source': row[5],
                    'source_type': row[6],
                    'published_at': row[7],
                    'collected_at': row[8],
                    'indicators': json.loads(row[9]) if row[9] else {},
                    'hash_id': row[10]
                }
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            logger.error(f"Error getting recent threats: {e}")
            return []
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get threat summary statistics"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get total threats
            cursor.execute('SELECT COUNT(*) FROM threats WHERE status = "active"')
            total_threats = cursor.fetchone()[0]
            
            # Get high severity threats
            cursor.execute('SELECT COUNT(*) FROM threats WHERE threat_score > 0.8 AND status = "active"')
            high_severity_count = cursor.fetchone()[0]
            
            # Get threat type distribution
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM threats 
                WHERE status = 'active'
                GROUP BY threat_type
                ORDER BY count DESC
            ''')
            threat_types = dict(cursor.fetchall())
            
            # Get source type distribution
            cursor.execute('''
                SELECT source_type, COUNT(*) as count
                FROM threats 
                WHERE status = 'active'
                GROUP BY source_type
                ORDER BY count DESC
            ''')
            source_types = dict(cursor.fetchall())
            
            # Get average threat score
            cursor.execute('SELECT AVG(threat_score) FROM threats WHERE status = "active"')
            avg_score = cursor.fetchone()[0] or 0.0
            
            # Get top threats
            cursor.execute('''
                SELECT title, threat_score, threat_type, source, source_type
                FROM threats 
                WHERE status = 'active'
                ORDER BY threat_score DESC
                LIMIT 10
            ''')
            top_threats = []
            for row in cursor.fetchall():
                top_threats.append({
                    'title': row[0],
                    'threat_score': row[1],
                    'threat_type': row[2],
                    'source': row[3],
                    'source_type': row[4]
                })
            
            conn.close()
            
            return {
                'total_articles': total_threats,  # Match dashboard expectation
                'high_severity_count': high_severity_count,
                'avg_threat_score': round(avg_score, 2),
                'threat_categories': threat_types,  # Match dashboard expectation
                'source_categories': source_types,  # Match dashboard expectation
                'top_threats': top_threats,
                'sources_used': len(source_types),  # Add sources count
                'collection_time': datetime.now().isoformat(),  # Add collection time
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting threat summary: {e}")
            return {}
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get system status from database"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT last_collection, total_threats, high_severity_count, 
                       next_collection, system_health
                FROM system_status 
                WHERE id = 1
            ''')
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'last_collection': row[0],
                    'total_threats': row[1],
                    'high_severity_count': row[2],
                    'next_collection': row[3],
                    'system_health': row[4],
                    'collection_frequency': '5 minutes'
                }
            else:
                return {
                    'last_collection': None,
                    'total_threats': 0,
                    'high_severity_count': 0,
                    'next_collection': None,
                    'system_health': 'unknown',
                    'collection_frequency': '5 minutes'
                }
                
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {}
    
    async def get_collection_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent collection logs"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT collection_time, source_type, articles_collected, articles_new,
                       duration_seconds, status, error_message
                FROM collection_log 
                ORDER BY collection_time DESC
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            logs = []
            
            for row in rows:
                log = {
                    'collection_time': row[0],
                    'source_type': row[1],
                    'articles_collected': row[2],
                    'articles_new': row[3],
                    'duration_seconds': row[4],
                    'status': row[5],
                    'error_message': row[6]
                }
                logs.append(log)
            
            conn.close()
            return logs
            
        except Exception as e:
            logger.error(f"Error getting collection logs: {e}")
            return []
    
    async def search_threats(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search threats by title or content"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            search_term = f"%{query}%"
            
            cursor.execute('''
                SELECT id, title, content, threat_score, threat_type, source, source_type,
                       published_at, collected_at, indicators
                FROM threats 
                WHERE status = 'active' AND (title LIKE ? OR content LIKE ?)
                ORDER BY threat_score DESC, collected_at DESC
                LIMIT ?
            ''', (search_term, search_term, limit))
            
            rows = cursor.fetchall()
            threats = []
            
            for row in rows:
                threat = {
                    'id': row[0],
                    'title': row[1],
                    'content': row[2],
                    'threat_score': row[3],
                    'threat_type': row[4],
                    'source': row[5],
                    'source_type': row[6],
                    'published_at': row[7],
                    'collected_at': row[8],
                    'indicators': json.loads(row[9]) if row[9] else {}
                }
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            logger.error(f"Error searching threats: {e}")
            return []
    
    async def get_threats_by_type(self, threat_type: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get threats by type"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, title, content, threat_score, threat_type, source, source_type,
                       published_at, collected_at, indicators
                FROM threats 
                WHERE status = 'active' AND threat_type = ?
                ORDER BY threat_score DESC, collected_at DESC
                LIMIT ?
            ''', (threat_type, limit))
            
            rows = cursor.fetchall()
            threats = []
            
            for row in rows:
                threat = {
                    'id': row[0],
                    'title': row[1],
                    'content': row[2],
                    'threat_score': row[3],
                    'threat_type': row[4],
                    'source': row[5],
                    'source_type': row[6],
                    'published_at': row[7],
                    'collected_at': row[8],
                    'indicators': json.loads(row[9]) if row[9] else {}
                }
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            logger.error(f"Error getting threats by type: {e}")
            return []
    
    async def get_threats_by_source(self, source_type: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get threats by source type"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, title, content, threat_score, threat_type, source, source_type,
                       published_at, collected_at, indicators
                FROM threats 
                WHERE status = 'active' AND source_type = ?
                ORDER BY threat_score DESC, collected_at DESC
                LIMIT ?
            ''', (source_type, limit))
            
            rows = cursor.fetchall()
            threats = []
            
            for row in rows:
                threat = {
                    'id': row[0],
                    'title': row[1],
                    'content': row[2],
                    'threat_score': row[3],
                    'threat_type': row[4],
                    'source': row[5],
                    'source_type': row[6],
                    'published_at': row[7],
                    'collected_at': row[8],
                    'indicators': json.loads(row[9]) if row[9] else {}
                }
                threats.append(threat)
            
            conn.close()
            return threats
            
        except Exception as e:
            logger.error(f"Error getting threats by source: {e}")
            return []

# Global database instance
db = ProductionDatabase()
"""
Database Module
Basic database functionality
"""

import sqlite3
import asyncio
from typing import Dict, Any, List
import logging
import os

logger = logging.getLogger(__name__)

class Database:
    """Basic database class"""
    
    def __init__(self, db_path: str = "ctms/data/threat_intelligence.db"):
        self.db_path = db_path
        self.connection = None
    
    async def initialize(self):
        """Initialize database"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            # Create connection
            self.connection = sqlite3.connect(self.db_path)
            
            # Create tables
            await self._create_tables()
            
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    async def _create_tables(self):
        """Create database tables"""
        try:
            cursor = self.connection.cursor()
            
            # Create threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    content TEXT,
                    source TEXT,
                    source_type TEXT,
                    threat_score REAL,
                    published_date TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.connection.commit()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
    
    async def save_threat(self, threat_data: Dict[str, Any]):
        """Save threat data to database"""
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO threats (title, content, source, source_type, threat_score, published_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                threat_data.get('title', ''),
                threat_data.get('content', ''),
                threat_data.get('source', ''),
                threat_data.get('source_type', ''),
                threat_data.get('threat_score', 0.0),
                threat_data.get('published', '')
            ))
            
            self.connection.commit()
            logger.info("Threat data saved successfully")
        except Exception as e:
            logger.error(f"Error saving threat data: {e}")
    
    async def get_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get threats from database"""
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM threats ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            threats = []
            
            for row in rows:
                threats.append({
                    'id': row[0],
                    'title': row[1],
                    'content': row[2],
                    'source': row[3],
                    'source_type': row[4],
                    'threat_score': row[5],
                    'published_date': row[6],
                    'created_at': row[7]
                })
            
            return threats
        except Exception as e:
            logger.error(f"Error getting threats: {e}")
            return []
# =============================================================================
# DATABASE CONNECTION MODULE
# =============================================================================
"""
Database connection management for MongoDB and Elasticsearch.
Provides connection pooling, health checks, and error handling.
"""

import asyncio
from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import MongoClient
from elasticsearch import AsyncElasticsearch, Elasticsearch
from contextlib import asynccontextmanager

from ctms.core.config import settings
from ctms.core.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# MONGODB CONNECTION MANAGEMENT
# =============================================================================
class MongoDBManager:
    """
    MongoDB connection manager with async support.
    Handles connection pooling and database operations.
    """
    
    def __init__(self):
        """Initialize MongoDB manager."""
        self._client: Optional[AsyncIOMotorClient] = None
        self._database: Optional[AsyncIOMotorDatabase] = None
        self._sync_client: Optional[MongoClient] = None
        self._connected = False
    
    async def connect(self) -> None:
        """
        Establish connection to MongoDB.
        
        Raises:
            Exception: If connection fails
        """
        try:
            logger.info("🔌 Connecting to MongoDB...")
            
            # Create async client
            self._client = AsyncIOMotorClient(
                settings.mongodb_url,
                maxPoolSize=50,
                minPoolSize=5,
                maxIdleTimeMS=30000,
                waitQueueTimeoutMS=5000,
                connectTimeoutMS=20000,
                serverSelectionTimeoutMS=20000
            )
            
            # Get database
            self._database = self._client[settings.mongodb_database]
            
            # Test connection
            await self._client.admin.command('ping')
            
            # Create sync client for non-async operations
            self._sync_client = MongoClient(settings.mongodb_url)
            
            self._connected = True
            logger.info("✅ MongoDB connection established")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close MongoDB connections."""
        if self._client:
            self._client.close()
            logger.info("🔌 MongoDB connection closed")
        
        if self._sync_client:
            self._sync_client.close()
        
        self._connected = False
    
    @property
    def database(self) -> AsyncIOMotorDatabase:
        """
        Get the async database instance.
        
        Returns:
            AsyncIOMotorDatabase: Database instance
            
        Raises:
            RuntimeError: If not connected
        """
        if not self._connected or not self._database:
            raise RuntimeError("MongoDB not connected. Call connect() first.")
        return self._database
    
    @property
    def client(self) -> AsyncIOMotorClient:
        """
        Get the async client instance.
        
        Returns:
            AsyncIOMotorClient: Client instance
            
        Raises:
            RuntimeError: If not connected
        """
        if not self._connected or not self._client:
            raise RuntimeError("MongoDB not connected. Call connect() first.")
        return self._client
    
    @property
    def sync_client(self) -> MongoClient:
        """
        Get the sync client instance.
        
        Returns:
            MongoClient: Sync client instance
            
        Raises:
            RuntimeError: If not connected
        """
        if not self._connected or not self._sync_client:
            raise RuntimeError("MongoDB not connected. Call connect() first.")
        return self._sync_client
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform MongoDB health check.
        
        Returns:
            Dict[str, Any]: Health status information
        """
        try:
            # Ping server
            await self._client.admin.command('ping')
            
            # Get server info
            server_info = await self._client.admin.command('buildInfo')
            
            # Get database stats
            db_stats = await self._database.command('dbStats')
            
            return {
                "status": "healthy",
                "connected": self._connected,
                "server_version": server_info.get("version"),
                "database": settings.mongodb_database,
                "collections": len(await self._database.list_collection_names()),
                "data_size": db_stats.get("dataSize", 0),
                "storage_size": db_stats.get("storageSize", 0),
                "index_size": db_stats.get("indexSize", 0),
            }
        
        except Exception as e:
            logger.error(f"MongoDB health check failed: {e}")
            return {
                "status": "unhealthy",
                "connected": False,
                "error": str(e)
            }
    
    async def create_indexes(self) -> None:
        """Create database indexes for performance."""
        try:
            logger.info("📄 Creating MongoDB indexes...")
            
            # IOC indexes
            await self._database.iocs.create_index([("value", 1), ("type", 1)])
            await self._database.iocs.create_index([("source", 1)])
            await self._database.iocs.create_index([("severity", 1)])
            await self._database.iocs.create_index([("created_at", -1)])
            
            # Threat intelligence indexes
            await self._database.threats.create_index([("threat_type", 1)])
            await self._database.threats.create_index([("severity", 1)])
            await self._database.threats.create_index([("source", 1)])
            await self._database.threats.create_index([("created_at", -1)])
            
            # Scraped content indexes
            await self._database.scraped_content.create_index([("content_hash", 1)])
            await self._database.scraped_content.create_index([("source_id", 1)])
            await self._database.scraped_content.create_index([("processed", 1)])
            await self._database.scraped_content.create_index([("scraping_timestamp", -1)])
            
            # Alert indexes
            await self._database.alerts.create_index([("status", 1)])
            await self._database.alerts.create_index([("severity", 1)])
            await self._database.alerts.create_index([("created_at", -1)])
            await self._database.alerts.create_index([("assigned_to", 1)])
            
            # User indexes
            await self._database.users.create_index([("username", 1)], unique=True)
            await self._database.users.create_index([("email", 1)], unique=True)
            
            logger.info("✅ MongoDB indexes created successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to create MongoDB indexes: {e}")
            raise


# =============================================================================
# ELASTICSEARCH CONNECTION MANAGEMENT
# =============================================================================
class ElasticsearchManager:
    """
    Elasticsearch connection manager with async support.
    Handles indexing, searching, and cluster management.
    """
    
    def __init__(self):
        """Initialize Elasticsearch manager."""
        self._client: Optional[AsyncElasticsearch] = None
        self._sync_client: Optional[Elasticsearch] = None
        self._connected = False
    
    async def connect(self) -> None:
        """
        Establish connection to Elasticsearch.
        
        Raises:
            Exception: If connection fails
        """
        try:
            logger.info("🔌 Connecting to Elasticsearch...")
            
            # Create async client
            self._client = AsyncElasticsearch([settings.elasticsearch_url])
            
            # Create sync client
            self._sync_client = Elasticsearch([settings.elasticsearch_url])
            
            # Test connection
            info = await self._client.info()
            
            self._connected = True
            logger.info(f"✅ Elasticsearch connection established - Version: {info['version']['number']}")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to Elasticsearch: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close Elasticsearch connections."""
        if self._client:
            await self._client.close()
            logger.info("🔌 Elasticsearch connection closed")
        
        if self._sync_client:
            self._sync_client.close()
        
        self._connected = False
    
    @property
    def client(self) -> AsyncElasticsearch:
        """
        Get the async client instance.
        
        Returns:
            AsyncElasticsearch: Client instance
            
        Raises:
            RuntimeError: If not connected
        """
        if not self._connected or not self._client:
            raise RuntimeError("Elasticsearch not connected. Call connect() first.")
        return self._client
    
    @property
    def sync_client(self) -> Elasticsearch:
        """
        Get the sync client instance.
        
        Returns:
            Elasticsearch: Sync client instance
            
        Raises:
            RuntimeError: If not connected
        """
        if not self._connected or not self._sync_client:
            raise RuntimeError("Elasticsearch not connected. Call connect() first.")
        return self._sync_client
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform Elasticsearch health check.
        
        Returns:
            Dict[str, Any]: Health status information
        """
        try:
            # Get cluster health
            health = await self._client.cluster.health()
            
            # Get cluster info
            info = await self._client.info()
            
            # Get index statistics
            stats = await self._client.indices.stats()
            
            return {
                "status": health["status"],
                "connected": self._connected,
                "cluster_name": health["cluster_name"],
                "elasticsearch_version": info["version"]["number"],
                "number_of_nodes": health["number_of_nodes"],
                "active_primary_shards": health["active_primary_shards"],
                "active_shards": health["active_shards"],
                "indices_count": len(stats["indices"]),
                "total_docs": stats["_all"]["total"]["docs"]["count"],
                "total_size": stats["_all"]["total"]["store"]["size_in_bytes"],
            }
        
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            return {
                "status": "red",
                "connected": False,
                "error": str(e)
            }
    
    async def create_indexes(self) -> None:
        """Create Elasticsearch indexes and mappings."""
        try:
            logger.info("📄 Creating Elasticsearch indexes...")
            
            # IOC index
            ioc_mapping = {
                "mappings": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "value": {"type": "keyword"},
                        "description": {"type": "text"},
                        "threat_types": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "severity": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "source_type": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "created_at": {"type": "date"},
                        "first_seen": {"type": "date"},
                        "last_seen": {"type": "date"}
                    }
                }
            }
            
            await self._create_index_if_not_exists("ctms_iocs", ioc_mapping)
            
            # Threat intelligence index
            threat_mapping = {
                "mappings": {
                    "properties": {
                        "title": {"type": "text"},
                        "description": {"type": "text"},
                        "threat_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "source_type": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "risk_score": {"type": "float"},
                        "created_at": {"type": "date"},
                        "first_observed": {"type": "date"},
                        "last_observed": {"type": "date"}
                    }
                }
            }
            
            await self._create_index_if_not_exists("ctms_threats", threat_mapping)
            
            # Scraped content index
            content_mapping = {
                "mappings": {
                    "properties": {
                        "title": {"type": "text"},
                        "content": {"type": "text"},
                        "source_url": {"type": "keyword"},
                        "scraped_url": {"type": "keyword"},
                        "content_hash": {"type": "keyword"},
                        "language": {"type": "keyword"},
                        "threat_score": {"type": "float"},
                        "relevance_score": {"type": "float"},
                        "scraping_timestamp": {"type": "date"},
                        "processed": {"type": "boolean"}
                    }
                }
            }
            
            await self._create_index_if_not_exists("ctms_content", content_mapping)
            
            # Alert index
            alert_mapping = {
                "mappings": {
                    "properties": {
                        "title": {"type": "text"},
                        "description": {"type": "text"},
                        "alert_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "status": {"type": "keyword"},
                        "assigned_to": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "risk_score": {"type": "float"},
                        "tags": {"type": "keyword"},
                        "created_at": {"type": "date"},
                        "acknowledged_at": {"type": "date"},
                        "resolved_at": {"type": "date"}
                    }
                }
            }
            
            await self._create_index_if_not_exists("ctms_alerts", alert_mapping)
            
            logger.info("✅ Elasticsearch indexes created successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to create Elasticsearch indexes: {e}")
            raise
    
    async def _create_index_if_not_exists(self, index_name: str, mapping: Dict[str, Any]) -> None:
        """
        Create index if it doesn't exist.
        
        Args:
            index_name: Name of the index
            mapping: Index mapping configuration
        """
        try:
            if not await self._client.indices.exists(index=index_name):
                await self._client.indices.create(index=index_name, body=mapping)
                logger.info(f"📄 Created index: {index_name}")
            else:
                logger.info(f"📄 Index already exists: {index_name}")
        
        except Exception as e:
            logger.error(f"Failed to create index {index_name}: {e}")
            raise


# =============================================================================
# DATABASE MANAGER - UNIFIED INTERFACE
# =============================================================================
class DatabaseManager:
    """
    Unified database manager for MongoDB and Elasticsearch.
    Provides a single interface for all database operations.
    """
    
    def __init__(self):
        """Initialize database manager."""
        self.mongodb = MongoDBManager()
        self.elasticsearch = ElasticsearchManager()
        self._initialized = False
    
    async def connect(self) -> None:
        """Connect to all databases."""
        try:
            logger.info("🚀 Initializing database connections...")
            
            # Connect to MongoDB (required)
            await self.mongodb.connect()
            
            # Try to connect to Elasticsearch (optional)
            es_connected = False
            try:
                await self.elasticsearch.connect()
                es_connected = True
            except Exception as es_err:
                logger.warning(f"⚠️ Elasticsearch not available: {es_err}")
            
            # Create indexes
            try:
                await self.mongodb.create_indexes()
            except Exception as idx_err:
                logger.warning(f"⚠️ Failed to create MongoDB indexes: {idx_err}")
            
            if es_connected:
                try:
                    await self.elasticsearch.create_indexes()
                except Exception as es_idx_err:
                    logger.warning(f"⚠️ Failed to create Elasticsearch indexes: {es_idx_err}")
            
            self._initialized = True
            logger.info("✅ Database initialization complete")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize MongoDB: {e}")
            await self.disconnect()
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from all databases."""
        await self.mongodb.disconnect()
        await self.elasticsearch.disconnect()
        self._initialized = False
        logger.info("🔌 All database connections closed")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on all databases.
        
        Returns:
            Dict[str, Any]: Combined health status
        """
        mongodb_health = await self.mongodb.health_check()
        elasticsearch_health = await self.elasticsearch.health_check()
        
        overall_status = "healthy"
        if mongodb_health["status"] != "healthy":
            overall_status = "unhealthy"
        # If Mongo is healthy but ES is red, still report unhealthy to signal degraded state
        elif elasticsearch_health["status"] not in ["green", "yellow"]:
            overall_status = "degraded"
        
        return {
            "overall_status": overall_status,
            "mongodb": mongodb_health,
            "elasticsearch": elasticsearch_health,
            "initialized": self._initialized
        }
    
    @asynccontextmanager
    async def transaction(self):
        """
        Simple transaction context for MongoDB operations.
        Note: This is a basic implementation; full ACID transactions
        require MongoDB replica sets or sharded clusters.
        """
        session = None
        try:
            session = await self.mongodb.client.start_session()
            async with session.start_transaction():
                yield session
        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            raise
        finally:
            if session:
                await session.end_session()


# =============================================================================
# GLOBAL DATABASE INSTANCE
# =============================================================================
# Single global instance to be imported throughout the application
db_manager = DatabaseManager()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================
async def get_database():
    """
    Get the MongoDB database instance.
    
    Returns:
        AsyncIOMotorDatabase: Database instance
    """
    try:
        return db_manager.mongodb.database
    except RuntimeError:
        # Lazy-connect if not initialized
        try:
            await db_manager.connect()
            return db_manager.mongodb.database
        except Exception as e:
            logger.error(f"Database not available: {e}")
            raise


async def get_elasticsearch():
    """
    Get the Elasticsearch client instance.
    
    Returns:
        AsyncElasticsearch: Elasticsearch client
    """
    return db_manager.elasticsearch.client


async def initialize_databases():
    """Initialize all database connections."""
    await db_manager.connect()


async def close_databases():
    """Close all database connections."""
    await db_manager.disconnect()


async def database_health():
    """Get database health status."""
    return await db_manager.health_check()
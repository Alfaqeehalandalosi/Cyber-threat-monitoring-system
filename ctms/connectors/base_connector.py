# =============================================================================
# CYBER THREAT MONITORING SYSTEM - BASE CONNECTOR
# =============================================================================
# OpenCTI-inspired base connector class for threat intelligence integration

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass

from ctms.core.config import settings
from ctms.core.logger import logger
from ctms.connectors import ConnectorType, ConnectorScope
from ctms.intelligence.stix_processor import STIXProcessor, ProcessingResult


@dataclass
class ConnectorWork:
    """Represents a work item for connector processing"""
    id: str
    name: str
    connector_id: str
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, ERROR
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    processed_objects: int = 0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


@dataclass
class ConnectorConfiguration:
    """Connector configuration settings"""
    id: str
    name: str
    type: ConnectorType
    scope: Union[ConnectorScope, List[ConnectorScope]]
    confidence_level: int = 50
    auto_import: bool = True
    update_existing_data: bool = True
    interval: Optional[int] = None  # in seconds
    
    # OpenCTI specific fields
    run_and_terminate: bool = False
    log_level: str = "info"
    
    # Custom configuration
    custom_config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.custom_config is None:
            self.custom_config = {}


class BaseConnector(ABC):
    """
    Base connector class inspired by OpenCTI's connector architecture
    
    All connectors inherit from this class and implement the required methods
    based on their connector type (EXTERNAL_IMPORT, INTERNAL_ENRICHMENT, etc.)
    """
    
    def __init__(self, config: ConnectorConfiguration):
        self.config = config
        self.stix_processor = None
        self.current_work: Optional[ConnectorWork] = None
        self.state: Dict[str, Any] = {}
        self._running = False
        
        # Setup logging
        self.logger = logger
        self.logger.info(f"🔌 Initializing connector: {self.config.name}")
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate connector configuration"""
        if not self.config.id:
            raise ValueError("Connector ID is required")
        
        if not self.config.name:
            raise ValueError("Connector name is required")
        
        if self.config.confidence_level < 0 or self.config.confidence_level > 100:
            raise ValueError("Confidence level must be between 0 and 100")
        
        self.logger.debug(f"✅ Connector configuration validated: {self.config.name}")
    
    def set_database_manager(self, db_manager) -> None:
        """Set database manager for STIX processing"""
        self.stix_processor = STIXProcessor(db_manager)
        self.logger.debug("📦 Database manager configured for connector")
    
    async def initialize(self) -> None:
        """Initialize connector (override in subclasses if needed)"""
        self.logger.info(f"🚀 Initializing connector: {self.config.name}")
        
        # Load connector state
        await self._load_state()
        
        # Perform connector-specific initialization
        await self._initialize()
        
        self.logger.info(f"✅ Connector initialized: {self.config.name}")
    
    @abstractmethod
    async def _initialize(self) -> None:
        """Connector-specific initialization (implement in subclasses)"""
        pass
    
    async def start(self) -> None:
        """Start the connector"""
        if self._running:
            self.logger.warning(f"⚠️ Connector {self.config.name} is already running")
            return
        
        self._running = True
        self.logger.info(f"▶️ Starting connector: {self.config.name}")
        
        try:
            await self.initialize()
            
            if self.config.type in [ConnectorType.EXTERNAL_IMPORT, ConnectorType.STREAM]:
                # Self-triggered connectors run continuously
                await self._run_continuous()
            else:
                # OpenCTI-triggered connectors wait for messages
                await self._listen_for_messages()
                
        except Exception as e:
            self.logger.error(f"❌ Error starting connector {self.config.name}: {str(e)}")
            self._running = False
            raise
    
    async def stop(self) -> None:
        """Stop the connector"""
        self.logger.info(f"⏹️ Stopping connector: {self.config.name}")
        self._running = False
        
        # Save current state
        await self._save_state()
        
        # Perform connector-specific cleanup
        await self._cleanup()
        
        self.logger.info(f"✅ Connector stopped: {self.config.name}")
    
    @abstractmethod
    async def _cleanup(self) -> None:
        """Connector-specific cleanup (implement in subclasses)"""
        pass
    
    async def _run_continuous(self) -> None:
        """Run continuous processing for self-triggered connectors"""
        while self._running:
            try:
                # Check if it's time to run
                if await self._should_run():
                    # Create work item
                    work = ConnectorWork(
                        id=f"work--{str(uuid.uuid4())}",
                        name=f"{self.config.name} run @ {datetime.utcnow().isoformat()}",
                        connector_id=self.config.id
                    )
                    
                    # Process work
                    await self._process_work(work)
                
                # Wait for next iteration
                await asyncio.sleep(self._get_sleep_interval())
                
            except Exception as e:
                self.logger.error(f"❌ Error in continuous run: {str(e)}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _listen_for_messages(self) -> None:
        """Listen for messages from OpenCTI platform"""
        self.logger.info(f"👂 Listening for messages: {self.config.name}")
        
        # This would typically connect to a message queue (RabbitMQ in OpenCTI)
        # For now, we'll simulate message processing
        while self._running:
            try:
                # Simulate waiting for messages
                await asyncio.sleep(5)
                
                # In a real implementation, this would process incoming messages
                # For demonstration, we'll process a sample message occasionally
                if datetime.utcnow().second % 30 == 0:  # Every 30 seconds
                    sample_message = {
                        "entity_id": f"indicator--{str(uuid.uuid4())}",
                        "entity_type": "Indicator",
                        "operation": "CREATE"
                    }
                    await self._process_message(sample_message)
                    
            except Exception as e:
                self.logger.error(f"❌ Error listening for messages: {str(e)}")
                await asyncio.sleep(5)
    
    async def _process_message(self, message: Dict[str, Any]) -> None:
        """Process incoming message (OpenCTI-triggered connectors)"""
        self.logger.debug(f"📨 Processing message: {message}")
        
        try:
            # Create work item for message
            work = ConnectorWork(
                id=f"work--{str(uuid.uuid4())}",
                name=f"Message processing for {message.get('entity_id', 'unknown')}",
                connector_id=self.config.id
            )
            
            # Process the message
            result = await self._process_message_work(work, message)
            
            if result.success:
                self.logger.debug(f"✅ Message processed successfully")
            else:
                self.logger.warning(f"⚠️ Message processing completed with warnings: {result.warnings}")
                
        except Exception as e:
            self.logger.error(f"❌ Error processing message: {str(e)}")
    
    async def _process_work(self, work: ConnectorWork) -> ProcessingResult:
        """Process a work item"""
        self.current_work = work
        work.status = "IN_PROGRESS"
        work.start_time = datetime.utcnow()
        
        self.logger.info(f"🔄 Starting work: {work.name}")
        
        try:
            # Perform the actual work (implemented by subclasses)
            result = await self._execute_work(work)
            
            # Update work status
            work.status = "COMPLETED" if result.success else "ERROR"
            work.end_time = datetime.utcnow()
            work.processed_objects = result.objects_created + result.objects_updated
            work.errors = result.errors
            
            # Update state
            self.state['last_run'] = work.end_time.isoformat()
            self.state['total_processed'] = self.state.get('total_processed', 0) + work.processed_objects
            
            self.logger.info(f"✅ Work completed: {work.name} - "
                           f"Processed: {work.processed_objects}, Errors: {len(work.errors)}")
            
            return result
            
        except Exception as e:
            work.status = "ERROR"
            work.end_time = datetime.utcnow()
            work.errors.append(str(e))
            
            self.logger.error(f"❌ Work failed: {work.name} - {str(e)}")
            raise
        
        finally:
            self.current_work = None
            await self._save_state()
    
    @abstractmethod
    async def _execute_work(self, work: ConnectorWork) -> ProcessingResult:
        """Execute the main work logic (implement in subclasses)"""
        pass
    
    @abstractmethod
    async def _process_message_work(self, work: ConnectorWork, message: Dict[str, Any]) -> ProcessingResult:
        """Process message-based work (implement in subclasses)"""
        pass
    
    async def _should_run(self) -> bool:
        """Check if connector should run based on interval"""
        if not self.config.interval:
            return True  # Run immediately if no interval specified
        
        last_run_str = self.state.get('last_run')
        if not last_run_str:
            return True  # First run
        
        try:
            last_run = datetime.fromisoformat(last_run_str)
            next_run = last_run + timedelta(seconds=self.config.interval)
            return datetime.utcnow() >= next_run
        except Exception:
            return True  # Run if we can't parse last run time
    
    def _get_sleep_interval(self) -> int:
        """Get sleep interval between checks"""
        if self.config.interval:
            return min(60, self.config.interval // 10)  # Check every 1/10th of interval, max 60s
        return 60  # Default 60 seconds
    
    async def _load_state(self) -> None:
        """Load connector state from storage"""
        # In a real implementation, this would load from database
        # For now, use in-memory state
        if not hasattr(self, '_persistent_state'):
            self._persistent_state = {}
        self.state = self._persistent_state.copy()
        
        self.logger.debug(f"📥 Loaded connector state: {len(self.state)} items")
    
    async def _save_state(self) -> None:
        """Save connector state to storage"""
        # In a real implementation, this would save to database
        self._persistent_state = self.state.copy()
        
        self.logger.debug(f"💾 Saved connector state: {len(self.state)} items")
    
    def get_state(self) -> Dict[str, Any]:
        """Get current connector state"""
        return self.state.copy()
    
    def set_state(self, new_state: Dict[str, Any]) -> None:
        """Set connector state"""
        self.state.update(new_state)
    
    def get_status(self) -> Dict[str, Any]:
        """Get connector status information"""
        return {
            'id': self.config.id,
            'name': self.config.name,
            'type': self.config.type,
            'scope': self.config.scope,
            'running': self._running,
            'current_work': self.current_work.__dict__ if self.current_work else None,
            'state': self.get_state(),
            'last_run': self.state.get('last_run'),
            'total_processed': self.state.get('total_processed', 0)
        }
    
    async def send_stix_bundle(
        self,
        bundle_data: Union[str, Dict[str, Any]],
        work_id: Optional[str] = None,
        update_existing: bool = None
    ) -> ProcessingResult:
        """Send STIX bundle for processing (similar to OpenCTI's helper)"""
        if not self.stix_processor:
            raise ValueError("STIX processor not configured")
        
        if update_existing is None:
            update_existing = self.config.update_existing_data
        
        self.logger.debug(f"📤 Sending STIX bundle for processing")
        
        result = await self.stix_processor.process_bundle(
            bundle_data=bundle_data,
            update_existing=update_existing,
            auto_enrich=True
        )
        
        self.logger.debug(f"📥 STIX bundle processed: {result.objects_created} created, "
                         f"{result.objects_updated} updated")
        
        return result
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        return {
            'connector_id': self.config.id,
            'name': self.config.name,
            'status': 'running' if self._running else 'stopped',
            'type': self.config.type,
            'last_run': self.state.get('last_run'),
            'errors': [],
            'timestamp': datetime.utcnow().isoformat()
        }


# =============================================================================
# Connector Factory
# =============================================================================

class ConnectorFactory:
    """Factory for creating connectors"""
    
    @staticmethod
    def create_connector(
        connector_type: str,
        config: ConnectorConfiguration
    ) -> BaseConnector:
        """Create connector instance based on type"""
        from ctms.connectors import get_connector
        
        connector_class = get_connector(connector_type)
        if not connector_class:
            raise ValueError(f"Unknown connector type: {connector_type}")
        
        return connector_class(config)
    
    @staticmethod
    def create_config(
        connector_id: str,
        name: str,
        connector_type: ConnectorType,
        scope: Union[ConnectorScope, List[ConnectorScope]],
        **kwargs
    ) -> ConnectorConfiguration:
        """Create connector configuration"""
        return ConnectorConfiguration(
            id=connector_id,
            name=name,
            type=connector_type,
            scope=scope,
            **kwargs
        )
# =============================================================================
# CYBER THREAT MONITORING SYSTEM - MITRE ATT&CK CONNECTOR
# =============================================================================
# OpenCTI-inspired MITRE ATT&CK data connector

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import aiohttp

from ctms.connectors.base_connector import BaseConnector, ConnectorWork
from ctms.connectors import ConnectorType, ConnectorScope, register_connector
from ctms.intelligence.stix_processor import ProcessingResult
from ctms.database.stix_models import (
    STIXBundle, STIXAttackPattern, STIXMalware, STIXThreatActor,
    STIXIntrusionSet, STIXRelationship
)


@register_connector
class MitreAttackConnector(BaseConnector):
    """
    MITRE ATT&CK Framework connector
    
    Imports STIX data from MITRE ATT&CK framework including:
    - Attack patterns (techniques)
    - Malware families
    - Threat actor groups
    - Relationships between entities
    """
    
    MITRE_STIX_URLS = {
        'enterprise': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
        'mobile': 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json',
        'ics': 'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json'
    }
    
    def __init__(self, config):
        super().__init__(config)
        
        # MITRE-specific configuration
        self.domains = config.custom_config.get('domains', ['enterprise'])
        self.import_malware = config.custom_config.get('import_malware', True)
        self.import_threat_actors = config.custom_config.get('import_threat_actors', True)
        self.import_attack_patterns = config.custom_config.get('import_attack_patterns', True)
        
        # HTTP session for API calls
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _initialize(self) -> None:
        """Initialize MITRE ATT&CK connector"""
        self.logger.info("🎯 Initializing MITRE ATT&CK connector")
        
        # Create HTTP session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300),
            headers={
                'User-Agent': 'CTMS-MITRE-Connector/1.0',
                'Accept': 'application/json'
            }
        )
        
        # Validate domains
        invalid_domains = [d for d in self.domains if d not in self.MITRE_STIX_URLS]
        if invalid_domains:
            raise ValueError(f"Invalid MITRE domains: {invalid_domains}")
        
        self.logger.info(f"✅ MITRE connector configured for domains: {self.domains}")
    
    async def _cleanup(self) -> None:
        """Clean up resources"""
        if self.session:
            await self.session.close()
            self.session = None
        self.logger.info("🧹 MITRE connector cleanup completed")
    
    async def _execute_work(self, work: ConnectorWork) -> ProcessingResult:
        """Execute MITRE ATT&CK data import"""
        self.logger.info("🚀 Starting MITRE ATT&CK data import")
        
        total_result = ProcessingResult(
            success=True,
            objects_created=0,
            objects_updated=0,
            relationships_created=0,
            errors=[],
            warnings=[]
        )
        
        try:
            # Process each domain
            for domain in self.domains:
                self.logger.info(f"📥 Processing MITRE {domain.upper()} domain")
                
                # Download STIX data
                stix_data = await self._download_mitre_data(domain)
                
                if stix_data:
                    # Process the STIX bundle
                    result = await self._process_mitre_bundle(stix_data, domain)
                    
                    # Aggregate results
                    total_result.objects_created += result.objects_created
                    total_result.objects_updated += result.objects_updated
                    total_result.relationships_created += result.relationships_created
                    total_result.errors.extend(result.errors)
                    total_result.warnings.extend(result.warnings)
                    
                    self.logger.info(f"✅ Processed {domain}: {result.objects_created} created, "
                                   f"{result.objects_updated} updated")
                else:
                    error_msg = f"Failed to download MITRE {domain} data"
                    total_result.errors.append(error_msg)
                    self.logger.error(error_msg)
            
            # Update statistics
            self.state['last_import'] = datetime.utcnow().isoformat()
            self.state['domains_processed'] = len(self.domains)
            
            if total_result.errors:
                total_result.success = False
            
        except Exception as e:
            total_result.success = False
            total_result.errors.append(f"MITRE import failed: {str(e)}")
            self.logger.error(f"❌ MITRE import failed: {str(e)}")
        
        return total_result
    
    async def _process_message_work(self, work: ConnectorWork, message: Dict[str, Any]) -> ProcessingResult:
        """Process message-based work (not applicable for EXTERNAL_IMPORT)"""
        return ProcessingResult(
            success=True,
            objects_created=0,
            objects_updated=0,
            relationships_created=0,
            errors=["Message processing not supported for MITRE connector"],
            warnings=[]
        )
    
    async def _download_mitre_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Download MITRE STIX data for specified domain"""
        url = self.MITRE_STIX_URLS.get(domain)
        if not url:
            self.logger.error(f"❌ Unknown MITRE domain: {domain}")
            return None
        
        try:
            self.logger.debug(f"📡 Downloading MITRE {domain} data from {url}")
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    self.logger.debug(f"✅ Downloaded MITRE {domain} data: "
                                    f"{len(data.get('objects', []))} objects")
                    return data
                else:
                    self.logger.error(f"❌ HTTP {response.status} downloading {domain} data")
                    return None
                    
        except Exception as e:
            self.logger.error(f"❌ Error downloading MITRE {domain} data: {str(e)}")
            return None
    
    async def _process_mitre_bundle(self, stix_data: Dict[str, Any], domain: str) -> ProcessingResult:
        """Process MITRE STIX bundle"""
        self.logger.debug(f"🔄 Processing MITRE {domain} STIX bundle")
        
        try:
            # Filter objects based on configuration
            filtered_objects = self._filter_mitre_objects(stix_data.get('objects', []))
            
            # Create filtered bundle
            filtered_bundle = {
                'type': 'bundle',
                'id': stix_data.get('id', f"bundle--mitre-{domain}"),
                'objects': filtered_objects
            }
            
            # Enrich with MITRE-specific metadata
            enriched_bundle = self._enrich_mitre_objects(filtered_bundle, domain)
            
            # Process through STIX processor
            result = await self.send_stix_bundle(enriched_bundle)
            
            self.logger.debug(f"✅ MITRE {domain} bundle processed: {len(filtered_objects)} objects")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Error processing MITRE {domain} bundle: {str(e)}")
            return ProcessingResult(
                success=False,
                objects_created=0,
                objects_updated=0,
                relationships_created=0,
                errors=[str(e)],
                warnings=[]
            )
    
    def _filter_mitre_objects(self, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter MITRE objects based on configuration"""
        filtered = []
        
        for obj in objects:
            obj_type = obj.get('type', '')
            
            # Always include basic objects
            if obj_type in ['identity', 'marking-definition']:
                filtered.append(obj)
                continue
            
            # Filter based on configuration
            if obj_type == 'attack-pattern' and self.import_attack_patterns:
                filtered.append(obj)
            elif obj_type == 'malware' and self.import_malware:
                filtered.append(obj)
            elif obj_type in ['threat-actor', 'intrusion-set'] and self.import_threat_actors:
                filtered.append(obj)
            elif obj_type in ['relationship', 'sighting']:
                # Include relationships for included objects
                filtered.append(obj)
        
        self.logger.debug(f"🎯 Filtered {len(filtered)} objects from {len(objects)} total")
        return filtered
    
    def _enrich_mitre_objects(self, bundle: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Enrich MITRE objects with additional metadata"""
        for obj in bundle.get('objects', []):
            obj_type = obj.get('type', '')
            
            # Add MITRE-specific extensions
            if obj_type == 'attack-pattern':
                self._enrich_attack_pattern(obj, domain)
            elif obj_type == 'malware':
                self._enrich_malware(obj, domain)
            elif obj_type in ['threat-actor', 'intrusion-set']:
                self._enrich_threat_actor(obj, domain)
            
            # Add common MITRE metadata
            obj['x_mitre_domain'] = domain
            obj['x_mitre_version'] = obj.get('x_mitre_version', '1.0')
            
            # Add OpenCTI extensions
            obj['x_opencti_score'] = self._calculate_mitre_score(obj)
            obj['x_opencti_labels'] = obj.get('x_opencti_labels', [])
            if 'mitre' not in obj['x_opencti_labels']:
                obj['x_opencti_labels'].append('mitre')
            if domain not in obj['x_opencti_labels']:
                obj['x_opencti_labels'].append(domain)
        
        return bundle
    
    def _enrich_attack_pattern(self, attack_pattern: Dict[str, Any], domain: str) -> None:
        """Enrich MITRE attack pattern with additional data"""
        # Extract MITRE ID
        external_refs = attack_pattern.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                attack_pattern['x_mitre_id'] = ref.get('external_id')
                break
        
        # Add platform information
        platforms = attack_pattern.get('x_mitre_platforms', [])
        if platforms:
            attack_pattern['x_opencti_labels'].extend([f"platform-{p.lower()}" for p in platforms])
        
        # Add data sources
        data_sources = attack_pattern.get('x_mitre_data_sources', [])
        if data_sources:
            attack_pattern['x_opencti_labels'].extend([f"datasource-{ds.lower().replace(' ', '-')}" for ds in data_sources])
    
    def _enrich_malware(self, malware: Dict[str, Any], domain: str) -> None:
        """Enrich MITRE malware with additional data"""
        # Add malware type labels
        malware_types = malware.get('malware_types', [])
        if malware_types:
            malware['x_opencti_labels'].extend([f"malware-{mt}" for mt in malware_types])
        
        # Add platform information
        platforms = malware.get('x_mitre_platforms', [])
        if platforms:
            malware['x_opencti_labels'].extend([f"platform-{p.lower()}" for p in platforms])
    
    def _enrich_threat_actor(self, threat_actor: Dict[str, Any], domain: str) -> None:
        """Enrich MITRE threat actor with additional data"""
        # Add actor type labels
        if threat_actor.get('type') == 'threat-actor':
            actor_types = threat_actor.get('threat_actor_types', [])
            if actor_types:
                threat_actor['x_opencti_labels'].extend([f"actor-{at}" for at in actor_types])
        
        # Add sophistication level
        sophistication = threat_actor.get('sophistication')
        if sophistication:
            threat_actor['x_opencti_labels'].append(f"sophistication-{sophistication}")
    
    def _calculate_mitre_score(self, obj: Dict[str, Any]) -> int:
        """Calculate risk score for MITRE object"""
        base_score = 50  # Default score
        
        obj_type = obj.get('type', '')
        
        # Adjust score based on object type
        if obj_type == 'attack-pattern':
            # Higher score for techniques with kill chain phases
            kill_chain_phases = obj.get('kill_chain_phases', [])
            if kill_chain_phases:
                base_score += len(kill_chain_phases) * 5
            
            # Higher score for techniques with many data sources
            data_sources = obj.get('x_mitre_data_sources', [])
            if data_sources:
                base_score += min(len(data_sources) * 3, 20)
        
        elif obj_type == 'malware':
            # Higher score for malware with multiple types
            malware_types = obj.get('malware_types', [])
            base_score += len(malware_types) * 10
        
        elif obj_type in ['threat-actor', 'intrusion-set']:
            # Higher score for sophisticated threat actors
            sophistication = obj.get('sophistication', '')
            sophistication_scores = {
                'minimal': 10,
                'intermediate': 20,
                'advanced': 30,
                'expert': 40,
                'innovator': 50,
                'strategic': 60
            }
            base_score += sophistication_scores.get(sophistication, 0)
        
        return min(base_score, 100)  # Cap at 100
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform MITRE connector health check"""
        base_health = await super().health_check()
        
        # Add MITRE-specific health information
        mitre_health = {
            'domains_configured': self.domains,
            'import_settings': {
                'attack_patterns': self.import_attack_patterns,
                'malware': self.import_malware,
                'threat_actors': self.import_threat_actors
            },
            'last_import': self.state.get('last_import'),
            'domains_processed': self.state.get('domains_processed', 0)
        }
        
        # Test connectivity to MITRE endpoints
        connectivity_status = {}
        if self.session:
            for domain, url in self.MITRE_STIX_URLS.items():
                if domain in self.domains:
                    try:
                        async with self.session.head(url) as response:
                            connectivity_status[domain] = response.status == 200
                    except Exception:
                        connectivity_status[domain] = False
        
        mitre_health['connectivity'] = connectivity_status
        
        base_health.update(mitre_health)
        return base_health


# =============================================================================
# Connector Configuration Helper
# =============================================================================

def create_mitre_connector_config(
    connector_id: str = "mitre-attack-connector",
    domains: List[str] = None,
    interval_hours: int = 24,
    **kwargs
) -> Dict[str, Any]:
    """Create MITRE ATT&CK connector configuration"""
    
    if domains is None:
        domains = ['enterprise']
    
    custom_config = {
        'domains': domains,
        'import_attack_patterns': kwargs.get('import_attack_patterns', True),
        'import_malware': kwargs.get('import_malware', True),
        'import_threat_actors': kwargs.get('import_threat_actors', True)
    }
    
    from ctms.connectors.base_connector import ConnectorConfiguration
    
    return ConnectorConfiguration(
        id=connector_id,
        name=f"MITRE ATT&CK Connector ({', '.join(domains)})",
        type=ConnectorType.EXTERNAL_IMPORT,
        scope=[ConnectorScope.ATTACK_PATTERN, ConnectorScope.MALWARE, ConnectorScope.THREAT_ACTOR],
        confidence_level=75,  # High confidence for MITRE data
        interval=interval_hours * 3600,  # Convert hours to seconds
        custom_config=custom_config,
        **kwargs
    )


# =============================================================================
# Sample Usage
# =============================================================================

async def create_sample_mitre_connector():
    """Create and configure sample MITRE connector"""
    
    # Create configuration
    config = create_mitre_connector_config(
        domains=['enterprise', 'mobile'],
        interval_hours=24,
        import_attack_patterns=True,
        import_malware=True,
        import_threat_actors=True
    )
    
    # Create connector instance
    connector = MitreAttackConnector(config)
    
    # Set up database (would be provided by the main application)
    # connector.set_database_manager(database_manager)
    
    return connector
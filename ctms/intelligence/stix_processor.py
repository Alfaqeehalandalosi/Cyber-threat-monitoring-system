# =============================================================================
# CYBER THREAT MONITORING SYSTEM - STIX PROCESSOR
# =============================================================================
# OpenCTI-inspired STIX 2.1 processing engine for threat intelligence

import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
import uuid

from ctms.core.config import settings
from ctms.core.logger import logger
from ctms.database.stix_models import (
    STIXBundle, STIXIndicator, STIXThreatActor, STIXMalware,
    STIXAttackPattern, STIXRelationship, STIXSighting,
    STIXIPv4Address, STIXDomainName, STIXURL, STIXEmailAddress,
    STIX_MODEL_REGISTRY, create_stix_object, get_stix_model
)


@dataclass
class ProcessingResult:
    """Result of STIX processing operation"""
    success: bool
    objects_created: int
    objects_updated: int
    relationships_created: int
    errors: List[str]
    warnings: List[str]
    bundle_id: Optional[str] = None


class STIXPatternParser:
    """Parse STIX patterns and extract observables"""
    
    # STIX pattern regex patterns
    PATTERN_REGEXES = {
        'ipv4-addr': r"\[ipv4-addr:value\s*=\s*'([^']+)'\]",
        'ipv6-addr': r"\[ipv6-addr:value\s*=\s*'([^']+)'\]",
        'domain-name': r"\[domain-name:value\s*=\s*'([^']+)'\]",
        'url': r"\[url:value\s*=\s*'([^']+)'\]",
        'email-addr': r"\[email-addr:value\s*=\s*'([^']+)'\]",
        'file': r"\[file:hashes\.(?:MD5|SHA-1|SHA-256|SHA-512)\s*=\s*'([^']+)'\]",
        'mutex': r"\[mutex:name\s*=\s*'([^']+)'\]",
        'registry-key': r"\[windows-registry-key:key\s*=\s*'([^']+)'\]",
    }
    
    @classmethod
    def parse_pattern(cls, pattern: str) -> List[Dict[str, str]]:
        """Extract observables from STIX pattern"""
        observables = []
        
        for obs_type, regex in cls.PATTERN_REGEXES.items():
            matches = re.findall(regex, pattern, re.IGNORECASE)
            for match in matches:
                observables.append({
                    'type': obs_type,
                    'value': match,
                    'pattern': pattern
                })
        
        return observables
    
    @classmethod
    def create_stix_pattern(cls, observable_type: str, value: str) -> str:
        """Create STIX pattern from observable"""
        if observable_type in ['ipv4-addr', 'ipv6-addr']:
            return f"[{observable_type}:value = '{value}']"
        elif observable_type == 'domain-name':
            return f"[domain-name:value = '{value}']"
        elif observable_type == 'url':
            return f"[url:value = '{value}']"
        elif observable_type == 'email-addr':
            return f"[email-addr:value = '{value}']"
        elif observable_type == 'file':
            # Assume SHA-256 hash if it looks like a hash
            if len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value):
                return f"[file:hashes.'SHA-256' = '{value}']"
            elif len(value) == 32 and all(c in '0123456789abcdefABCDEF' for c in value):
                return f"[file:hashes.MD5 = '{value}']"
            elif len(value) == 40 and all(c in '0123456789abcdefABCDEF' for c in value):
                return f"[file:hashes.'SHA-1' = '{value}']"
        
        # Default pattern
        return f"[{observable_type}:value = '{value}']"


class STIXRelationshipManager:
    """Manage STIX relationships and links"""
    
    # Common relationship types
    RELATIONSHIP_TYPES = {
        'indicates': 'Indicator indicates entity',
        'attributed-to': 'Activity attributed to actor',
        'targets': 'Actor targets entity',
        'uses': 'Actor uses tool/technique',
        'mitigates': 'Course of action mitigates technique',
        'compromises': 'Malware compromises system',
        'communicates-with': 'Malware communicates with infrastructure',
        'downloads': 'Malware downloads payload',
        'drops': 'Malware drops file',
        'variant-of': 'Malware variant relationship',
        'based-on': 'Pattern based on another pattern',
        'related-to': 'Generic relationship',
    }
    
    @classmethod
    def create_relationship(
        cls,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        description: Optional[str] = None,
        confidence: Optional[int] = None,
        start_time: Optional[datetime] = None,
        stop_time: Optional[datetime] = None
    ) -> STIXRelationship:
        """Create STIX relationship object"""
        
        relationship_id = f"relationship--{str(uuid.uuid4())}"
        
        relationship_data = {
            'id': relationship_id,
            'source_ref': source_ref,
            'target_ref': target_ref,
            'relationship_type': relationship_type,
            'created': datetime.utcnow(),
            'modified': datetime.utcnow()
        }
        
        if description:
            relationship_data['description'] = description
        if confidence:
            relationship_data['confidence'] = confidence
        if start_time:
            relationship_data['start_time'] = start_time
        if stop_time:
            relationship_data['stop_time'] = stop_time
        
        return STIXRelationship(**relationship_data)
    
    @classmethod
    def create_sighting(
        cls,
        sighting_of_ref: str,
        where_sighted_refs: Optional[List[str]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        count: Optional[int] = None
    ) -> STIXSighting:
        """Create STIX sighting object"""
        
        sighting_id = f"sighting--{str(uuid.uuid4())}"
        
        sighting_data = {
            'id': sighting_id,
            'sighting_of_ref': sighting_of_ref,
            'created': datetime.utcnow(),
            'modified': datetime.utcnow()
        }
        
        if where_sighted_refs:
            sighting_data['where_sighted_refs'] = where_sighted_refs
        if first_seen:
            sighting_data['first_seen'] = first_seen
        if last_seen:
            sighting_data['last_seen'] = last_seen
        if count:
            sighting_data['count'] = count
        
        return STIXSighting(**sighting_data)


class STIXEnrichmentEngine:
    """Enrich STIX objects with additional intelligence"""
    
    def __init__(self):
        self.enrichment_rules = self._load_enrichment_rules()
    
    def _load_enrichment_rules(self) -> Dict[str, Any]:
        """Load enrichment rules configuration"""
        return {
            'auto_create_observables': True,
            'auto_link_indicators': True,
            'confidence_thresholds': {
                'low': 25,
                'medium': 50,
                'high': 75
            },
            'ttl_settings': {
                'indicator': timedelta(days=365),
                'malware': timedelta(days=730),
                'threat-actor': timedelta(days=1095)
            }
        }
    
    async def enrich_indicator(self, indicator: STIXIndicator) -> Dict[str, Any]:
        """Enrich indicator with observables and metadata"""
        enrichment_data = {
            'observables': [],
            'labels': [],
            'confidence_score': indicator.confidence or 50,
            'kill_chain_phases': indicator.kill_chain_phases
        }
        
        # Extract observables from pattern
        if indicator.pattern:
            observables = STIXPatternParser.parse_pattern(indicator.pattern)
            enrichment_data['observables'] = observables
            
            # Auto-generate labels based on observables
            for observable in observables:
                obs_type = observable['type']
                if obs_type not in enrichment_data['labels']:
                    enrichment_data['labels'].append(obs_type)
        
        # Set main observable type
        if enrichment_data['observables']:
            primary_observable = enrichment_data['observables'][0]
            enrichment_data['main_observable_type'] = primary_observable['type']
        
        return enrichment_data
    
    async def enrich_malware(self, malware: STIXMalware) -> Dict[str, Any]:
        """Enrich malware object with additional context"""
        enrichment_data = {
            'family_classification': None,
            'capability_tags': [],
            'platform_tags': [],
            'confidence_score': 50
        }
        
        # Extract capabilities from description
        if malware.description:
            description_lower = malware.description.lower()
            
            # Common malware capabilities
            capabilities = {
                'backdoor': ['backdoor', 'remote access', 'rat'],
                'trojan': ['trojan', 'banking trojan'],
                'ransomware': ['ransomware', 'crypto-locker', 'encrypt'],
                'botnet': ['botnet', 'bot', 'command and control'],
                'keylogger': ['keylogger', 'keystroke', 'password theft'],
                'spyware': ['spyware', 'surveillance', 'data theft']
            }
            
            for capability, keywords in capabilities.items():
                if any(keyword in description_lower for keyword in keywords):
                    enrichment_data['capability_tags'].append(capability)
        
        # Set family classification
        if malware.is_family:
            enrichment_data['family_classification'] = 'family'
        else:
            enrichment_data['family_classification'] = 'variant'
        
        return enrichment_data


class STIXProcessor:
    """Main STIX processing engine inspired by OpenCTI"""
    
    def __init__(self, database_manager=None):
        self.db = database_manager
        self.pattern_parser = STIXPatternParser()
        self.relationship_manager = STIXRelationshipManager()
        self.enrichment_engine = STIXEnrichmentEngine()
        
        # Processing statistics
        self.stats = {
            'bundles_processed': 0,
            'objects_created': 0,
            'objects_updated': 0,
            'relationships_created': 0,
            'errors': 0,
            'warnings': 0
        }
    
    async def process_bundle(
        self,
        bundle_data: Union[Dict[str, Any], str, STIXBundle],
        update_existing: bool = True,
        auto_enrich: bool = True
    ) -> ProcessingResult:
        """Process STIX bundle similar to OpenCTI's processing"""
        
        logger.info("🔄 Starting STIX bundle processing")
        
        result = ProcessingResult(
            success=True,
            objects_created=0,
            objects_updated=0,
            relationships_created=0,
            errors=[],
            warnings=[]
        )
        
        try:
            # Parse bundle data
            if isinstance(bundle_data, str):
                bundle_dict = json.loads(bundle_data)
            elif isinstance(bundle_data, dict):
                bundle_dict = bundle_data
            elif isinstance(bundle_data, STIXBundle):
                bundle_dict = bundle_data.dict()
            else:
                raise ValueError("Invalid bundle format")
            
            # Validate bundle structure
            if not self._validate_bundle(bundle_dict):
                result.success = False
                result.errors.append("Invalid STIX bundle structure")
                return result
            
            result.bundle_id = bundle_dict.get('id')
            
            # Extract objects from bundle
            objects = bundle_dict.get('objects', [])
            logger.info(f"📦 Processing {len(objects)} STIX objects")
            
            # Sort objects by processing priority (relationships last)
            objects = self._sort_objects_by_priority(objects)
            
            # Process each object
            for obj_data in objects:
                try:
                    obj_result = await self._process_object(
                        obj_data, 
                        update_existing=update_existing,
                        auto_enrich=auto_enrich
                    )
                    
                    result.objects_created += obj_result.get('created', 0)
                    result.objects_updated += obj_result.get('updated', 0)
                    result.relationships_created += obj_result.get('relationships', 0)
                    
                    if obj_result.get('warnings'):
                        result.warnings.extend(obj_result['warnings'])
                        
                except Exception as e:
                    error_msg = f"Error processing object {obj_data.get('id', 'unknown')}: {str(e)}"
                    result.errors.append(error_msg)
                    logger.error(error_msg)
            
            # Update statistics
            self.stats['bundles_processed'] += 1
            self.stats['objects_created'] += result.objects_created
            self.stats['objects_updated'] += result.objects_updated
            self.stats['relationships_created'] += result.relationships_created
            self.stats['errors'] += len(result.errors)
            self.stats['warnings'] += len(result.warnings)
            
            logger.info(f"✅ Bundle processing complete: {result.objects_created} created, "
                       f"{result.objects_updated} updated, {result.relationships_created} relationships")
            
        except Exception as e:
            result.success = False
            result.errors.append(f"Bundle processing failed: {str(e)}")
            logger.error(f"❌ Bundle processing failed: {str(e)}")
        
        return result
    
    def _validate_bundle(self, bundle_dict: Dict[str, Any]) -> bool:
        """Validate STIX bundle structure"""
        required_fields = ['type', 'id', 'objects']
        
        for field in required_fields:
            if field not in bundle_dict:
                logger.warning(f"Missing required field in bundle: {field}")
                return False
        
        if bundle_dict['type'] != 'bundle':
            logger.warning(f"Invalid bundle type: {bundle_dict['type']}")
            return False
        
        return True
    
    def _sort_objects_by_priority(self, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort objects by processing priority"""
        priority_order = {
            'marking-definition': 0,
            'identity': 1,
            'location': 2,
            'attack-pattern': 3,
            'malware': 4,
            'tool': 5,
            'threat-actor': 6,
            'intrusion-set': 7,
            'campaign': 8,
            'indicator': 9,
            'observed-data': 10,
            'report': 11,
            'relationship': 20,  # Process relationships last
            'sighting': 21
        }
        
        def get_priority(obj):
            return priority_order.get(obj.get('type', ''), 15)
        
        return sorted(objects, key=get_priority)
    
    async def _process_object(
        self,
        obj_data: Dict[str, Any],
        update_existing: bool = True,
        auto_enrich: bool = True
    ) -> Dict[str, Any]:
        """Process individual STIX object"""
        
        result = {
            'created': 0,
            'updated': 0,
            'relationships': 0,
            'warnings': []
        }
        
        obj_type = obj_data.get('type')
        obj_id = obj_data.get('id')
        
        logger.debug(f"🔍 Processing {obj_type}: {obj_id}")
        
        # Get model class for object type
        model_class = get_stix_model(obj_type)
        if not model_class:
            result['warnings'].append(f"Unknown object type: {obj_type}")
            return result
        
        try:
            # Create object instance
            stix_object = model_class(**obj_data)
            
            # Auto-enrich if enabled
            if auto_enrich:
                await self._auto_enrich_object(stix_object)
            
            # Check if object exists
            existing_object = await self._find_existing_object(obj_id, obj_type)
            
            if existing_object and update_existing:
                # Update existing object
                await self._update_object(existing_object, stix_object)
                result['updated'] = 1
                logger.debug(f"📝 Updated {obj_type}: {obj_id}")
            
            elif not existing_object:
                # Create new object
                await self._create_object(stix_object)
                result['created'] = 1
                logger.debug(f"✨ Created {obj_type}: {obj_id}")
                
                # Auto-create relationships for indicators
                if obj_type == 'indicator' and auto_enrich:
                    relationships = await self._auto_create_relationships(stix_object)
                    result['relationships'] = len(relationships)
            
        except Exception as e:
            result['warnings'].append(f"Failed to process {obj_type} {obj_id}: {str(e)}")
            logger.warning(f"⚠️ Failed to process {obj_type} {obj_id}: {str(e)}")
        
        return result
    
    async def _auto_enrich_object(self, stix_object) -> None:
        """Auto-enrich STIX object with additional data"""
        
        if isinstance(stix_object, STIXIndicator):
            enrichment = await self.enrichment_engine.enrich_indicator(stix_object)
            
            # Update indicator with enriched data
            if enrichment.get('main_observable_type'):
                stix_object.x_opencti_main_observable_type = enrichment['main_observable_type']
            
            if enrichment.get('labels'):
                stix_object.x_opencti_labels.extend(enrichment['labels'])
        
        elif isinstance(stix_object, STIXMalware):
            enrichment = await self.enrichment_engine.enrich_malware(stix_object)
            
            # Update malware with enriched data
            if enrichment.get('capability_tags'):
                stix_object.x_opencti_labels.extend(enrichment['capability_tags'])
    
    async def _find_existing_object(self, obj_id: str, obj_type: str) -> Optional[Dict[str, Any]]:
        """Find existing object in database"""
        if not self.db:
            return None
        
        try:
            # Search in MongoDB
            collection = self.db.mongodb.get_collection('stix_objects')
            existing = await collection.find_one({'id': obj_id, 'type': obj_type})
            return existing
        except Exception as e:
            logger.warning(f"Error finding existing object: {str(e)}")
            return None
    
    async def _create_object(self, stix_object) -> None:
        """Create new STIX object in database"""
        if not self.db:
            logger.debug("No database manager configured, skipping object creation")
            return
        
        try:
            # Store in MongoDB
            collection = self.db.mongodb.get_collection('stix_objects')
            await collection.insert_one(stix_object.dict())
            
            # Index in Elasticsearch for search
            if hasattr(self.db, 'elasticsearch') and self.db.elasticsearch:
                doc_id = stix_object.id.replace('--', '_')
                await self.db.elasticsearch.index(
                    index=f"stix_{stix_object.type.replace('-', '_')}",
                    id=doc_id,
                    document=stix_object.dict()
                )
        
        except Exception as e:
            logger.error(f"Error creating object: {str(e)}")
            raise
    
    async def _update_object(self, existing_object: Dict[str, Any], new_object) -> None:
        """Update existing STIX object"""
        if not self.db:
            return
        
        try:
            # Update modified timestamp
            new_object.modified = datetime.utcnow()
            
            # Update in MongoDB
            collection = self.db.mongodb.get_collection('stix_objects')
            await collection.replace_one(
                {'id': new_object.id},
                new_object.dict()
            )
            
            # Update in Elasticsearch
            if hasattr(self.db, 'elasticsearch') and self.db.elasticsearch:
                doc_id = new_object.id.replace('--', '_')
                await self.db.elasticsearch.index(
                    index=f"stix_{new_object.type.replace('-', '_')}",
                    id=doc_id,
                    document=new_object.dict()
                )
        
        except Exception as e:
            logger.error(f"Error updating object: {str(e)}")
            raise
    
    async def _auto_create_relationships(self, indicator: STIXIndicator) -> List[STIXRelationship]:
        """Auto-create relationships for indicators"""
        relationships = []
        
        if not indicator.pattern:
            return relationships
        
        # Extract observables and create relationships
        observables = self.pattern_parser.parse_pattern(indicator.pattern)
        
        for observable_data in observables:
            try:
                # Create observable object
                observable = await self._create_observable_from_pattern(observable_data)
                
                # Create "indicates" relationship
                relationship = self.relationship_manager.create_relationship(
                    source_ref=indicator.id,
                    target_ref=observable.id,
                    relationship_type='indicates',
                    description=f"Indicator indicates {observable_data['type']}",
                    confidence=indicator.confidence
                )
                
                relationships.append(relationship)
                
                # Store relationship
                await self._create_object(relationship)
                
            except Exception as e:
                logger.warning(f"Failed to create relationship for observable: {str(e)}")
        
        return relationships
    
    async def _create_observable_from_pattern(self, observable_data: Dict[str, str]):
        """Create cyber observable from pattern data"""
        obs_type = observable_data['type']
        obs_value = observable_data['value']
        
        # Create appropriate observable object
        if obs_type == 'ipv4-addr':
            return STIXIPv4Address(value=obs_value)
        elif obs_type == 'domain-name':
            return STIXDomainName(value=obs_value)
        elif obs_type == 'url':
            return STIXURL(value=obs_value)
        elif obs_type == 'email-addr':
            return STIXEmailAddress(value=obs_value)
        else:
            # Generic observable
            model_class = get_stix_model(obs_type)
            if model_class:
                return model_class(value=obs_value)
        
        raise ValueError(f"Cannot create observable for type: {obs_type}")
    
    async def export_to_stix_bundle(
        self,
        object_ids: Optional[List[str]] = None,
        object_types: Optional[List[str]] = None,
        include_relationships: bool = True
    ) -> STIXBundle:
        """Export objects to STIX bundle"""
        
        logger.info("📤 Exporting STIX bundle")
        
        if not self.db:
            raise ValueError("Database manager not configured")
        
        # Build query
        query = {}
        if object_ids:
            query['id'] = {'$in': object_ids}
        if object_types:
            query['type'] = {'$in': object_types}
        
        # Fetch objects
        collection = self.db.mongodb.get_collection('stix_objects')
        cursor = collection.find(query)
        objects = await cursor.to_list(length=None)
        
        # Include relationships if requested
        if include_relationships and objects:
            object_ids = [obj['id'] for obj in objects]
            rel_query = {
                'type': {'$in': ['relationship', 'sighting']},
                '$or': [
                    {'source_ref': {'$in': object_ids}},
                    {'target_ref': {'$in': object_ids}},
                    {'sighting_of_ref': {'$in': object_ids}}
                ]
            }
            
            relationships = await collection.find(rel_query).to_list(length=None)
            objects.extend(relationships)
        
        # Create bundle
        bundle = STIXBundle(
            id=f"bundle--{str(uuid.uuid4())}",
            objects=objects
        )
        
        logger.info(f"📦 Created bundle with {len(objects)} objects")
        return bundle
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            **self.stats,
            'success_rate': (
                (self.stats['objects_created'] + self.stats['objects_updated']) /
                max(1, self.stats['objects_created'] + self.stats['objects_updated'] + self.stats['errors'])
            ) * 100
        }


# =============================================================================
# STIX Processing Utilities
# =============================================================================

def create_sample_stix_bundle() -> STIXBundle:
    """Create sample STIX bundle for testing"""
    
    # Generate unique IDs
    indicator_id = f"indicator--{str(uuid.uuid4())}"
    malware_id = f"malware--{str(uuid.uuid4())}"
    relationship_id = f"relationship--{str(uuid.uuid4())}"
    bundle_id = f"bundle--{str(uuid.uuid4())}"
    
    # Create sample indicator
    indicator = STIXIndicator(
        id=indicator_id,
        pattern="[ipv4-addr:value = '192.168.1.100']",
        labels=['malicious-activity'],
        valid_from=datetime.utcnow(),
        confidence=75,
        x_opencti_detection=True
    )
    
    # Create sample malware
    malware = STIXMalware(
        id=malware_id,
        name="Sample Trojan",
        malware_types=['trojan'],
        is_family=False,
        description="Sample trojan for testing",
        labels=['trojan', 'malware']
    )
    
    # Create relationship
    relationship = STIXRelationship(
        id=relationship_id,
        source_ref=indicator_id,
        target_ref=malware_id,
        relationship_type='indicates',
        description="Indicator indicates malware presence"
    )
    
    # Create bundle
    bundle = STIXBundle(
        id=bundle_id,
        objects=[
            indicator.dict(),
            malware.dict(),
            relationship.dict()
        ]
    )
    
    return bundle


async def process_stix_file(file_path: str, processor: STIXProcessor) -> ProcessingResult:
    """Process STIX file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            bundle_data = f.read()
        
        result = await processor.process_bundle(bundle_data)
        logger.info(f"✅ Processed STIX file: {file_path}")
        return result
        
    except Exception as e:
        logger.error(f"❌ Failed to process STIX file {file_path}: {str(e)}")
        raise
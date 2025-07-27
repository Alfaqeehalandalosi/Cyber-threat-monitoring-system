# =============================================================================
# CYBER THREAT MONITORING SYSTEM - STIX 2.1 DATA MODELS
# =============================================================================
# OpenCTI-inspired STIX 2.1 compliant data models for enhanced compatibility

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator
import uuid


# =============================================================================
# STIX 2.1 Base Classes and Enums
# =============================================================================

class STIXDomainObjectType(str, Enum):
    """STIX Domain Object (SDO) types"""
    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    COURSE_OF_ACTION = "course-of-action"
    GROUPING = "grouping"
    IDENTITY = "identity"
    INDICATOR = "indicator"
    INFRASTRUCTURE = "infrastructure"
    INTRUSION_SET = "intrusion-set"
    LOCATION = "location"
    MALWARE = "malware"
    MALWARE_ANALYSIS = "malware-analysis"
    NOTE = "note"
    OBSERVED_DATA = "observed-data"
    OPINION = "opinion"
    REPORT = "report"
    THREAT_ACTOR = "threat-actor"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"


class STIXCyberObservableType(str, Enum):
    """STIX Cyber Observable (SCO) types"""
    ARTIFACT = "artifact"
    AUTONOMOUS_SYSTEM = "autonomous-system"
    DIRECTORY = "directory"
    DOMAIN_NAME = "domain-name"
    EMAIL_ADDR = "email-addr"
    EMAIL_MESSAGE = "email-message"
    FILE = "file"
    IPV4_ADDR = "ipv4-addr"
    IPV6_ADDR = "ipv6-addr"
    MAC_ADDR = "mac-addr"
    MUTEX = "mutex"
    NETWORK_TRAFFIC = "network-traffic"
    PROCESS = "process"
    SOFTWARE = "software"
    URL = "url"
    USER_ACCOUNT = "user-account"
    WINDOWS_REGISTRY_KEY = "windows-registry-key"
    X509_CERTIFICATE = "x509-certificate"


class STIXRelationshipType(str, Enum):
    """STIX Relationship Object (SRO) types"""
    RELATIONSHIP = "relationship"
    SIGHTING = "sighting"


class TLPLevel(str, Enum):
    """Traffic Light Protocol levels"""
    TLP_CLEAR = "TLP:CLEAR"
    TLP_GREEN = "TLP:GREEN"
    TLP_AMBER = "TLP:AMBER"
    TLP_RED = "TLP:RED"


class ConfidenceLevel(int, Enum):
    """OpenCTI confidence levels"""
    UNKNOWN = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    FULLY_TRUSTED = 100


# =============================================================================
# Base STIX Objects
# =============================================================================

class STIXDomainObject(BaseModel):
    """Base class for all STIX Domain Objects"""
    type: STIXDomainObjectType
    spec_version: str = Field(default="2.1", description="STIX version")
    id: str = Field(description="STIX identifier")
    created_by_ref: Optional[str] = Field(description="Creator identity reference")
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: datetime = Field(default_factory=datetime.utcnow)
    revoked: bool = Field(default=False)
    labels: List[str] = Field(default_factory=list)
    confidence: Optional[int] = Field(description="Confidence level 0-100")
    lang: Optional[str] = Field(description="Language identifier")
    external_references: List[Dict[str, Any]] = Field(default_factory=list)
    object_marking_refs: List[str] = Field(default_factory=list)
    granular_markings: List[Dict[str, Any]] = Field(default_factory=list)
    
    # OpenCTI extensions
    x_opencti_id: Optional[str] = Field(description="OpenCTI internal ID")
    x_opencti_entity_type: Optional[str] = Field(description="OpenCTI entity type")
    x_opencti_stix_ids: List[str] = Field(default_factory=list)
    x_opencti_created_by_ref: Optional[str] = Field(description="OpenCTI creator reference")
    x_opencti_labels: List[str] = Field(default_factory=list)
    x_opencti_score: Optional[int] = Field(description="OpenCTI risk score")
    
    @validator('id', pre=True, always=True)
    def generate_id(cls, v, values):
        if not v and 'type' in values:
            return f"{values['type']}--{str(uuid.uuid4())}"
        return v
    
    class Config:
        """Pydantic model configuration"""
        use_enum_values = True
        validate_assignment = True


class STIXCyberObservable(BaseModel):
    """Base class for all STIX Cyber Observables"""
    type: STIXCyberObservableType
    spec_version: str = Field(default="2.1")
    id: str = Field(description="Observable identifier")
    
    # OpenCTI extensions
    x_opencti_id: Optional[str] = Field(description="OpenCTI internal ID")
    x_opencti_description: Optional[str] = Field(description="Observable description")
    x_opencti_score: Optional[int] = Field(description="Observable score")
    x_opencti_labels: List[str] = Field(default_factory=list)
    
    @validator('id', pre=True, always=True)
    def generate_observable_id(cls, v, values):
        if not v and 'type' in values:
            return f"{values['type']}--{str(uuid.uuid4())}"
        return v
    
    class Config:
        use_enum_values = True


class STIXRelationshipObject(BaseModel):
    """Base class for STIX Relationship Objects"""
    type: STIXRelationshipType
    spec_version: str = Field(default="2.1")
    id: str = Field(description="Relationship identifier")
    created_by_ref: Optional[str] = Field(description="Creator identity reference")
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: datetime = Field(default_factory=datetime.utcnow)
    revoked: bool = Field(default=False)
    confidence: Optional[int] = Field(description="Confidence level 0-100")
    lang: Optional[str] = Field(description="Language identifier")
    external_references: List[Dict[str, Any]] = Field(default_factory=list)
    object_marking_refs: List[str] = Field(default_factory=list)
    granular_markings: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Relationship-specific fields
    source_ref: str = Field(description="Source object reference")
    target_ref: str = Field(description="Target object reference")
    relationship_type: str = Field(description="Type of relationship")
    
    # OpenCTI extensions
    x_opencti_id: Optional[str] = Field(description="OpenCTI internal ID")
    x_opencti_source_ref: Optional[str] = Field(description="OpenCTI source reference")
    x_opencti_target_ref: Optional[str] = Field(description="OpenCTI target reference")
    
    @validator('id', pre=True, always=True)
    def generate_relationship_id(cls, v, values):
        if not v and 'type' in values:
            return f"{values['type']}--{str(uuid.uuid4())}"
        return v
    
    class Config:
        use_enum_values = True


# =============================================================================
# Specific STIX Domain Objects
# =============================================================================

class STIXIndicator(STIXDomainObject):
    """STIX 2.1 Indicator object"""
    type: STIXDomainObjectType = Field(default=STIXDomainObjectType.INDICATOR, const=True)
    pattern: str = Field(description="Detection pattern in STIX format")
    pattern_type: str = Field(default="stix", description="Pattern type")
    pattern_version: Optional[str] = Field(description="Pattern version")
    valid_from: datetime = Field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = Field(description="Indicator expiration")
    kill_chain_phases: List[Dict[str, str]] = Field(default_factory=list)
    
    # OpenCTI specific fields
    x_opencti_detection: bool = Field(default=True, description="Enable detection")
    x_opencti_main_observable_type: Optional[str] = Field(description="Primary observable type")
    x_opencti_pattern_type: str = Field(default="stix", description="OpenCTI pattern type")


class STIXThreatActor(STIXDomainObject):
    """STIX 2.1 Threat Actor object"""
    type: STIXDomainObjectType = Field(default=STIXDomainObjectType.THREAT_ACTOR, const=True)
    name: str = Field(description="Threat actor name")
    description: Optional[str] = Field(description="Threat actor description")
    threat_actor_types: List[str] = Field(description="Types of threat actor")
    aliases: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = Field(description="First observation date")
    last_seen: Optional[datetime] = Field(description="Last observation date")
    roles: List[str] = Field(default_factory=list)
    goals: List[str] = Field(default_factory=list)
    sophistication: Optional[str] = Field(description="Sophistication level")
    resource_level: Optional[str] = Field(description="Resource level")
    primary_motivation: Optional[str] = Field(description="Primary motivation")
    secondary_motivations: List[str] = Field(default_factory=list)
    personal_motivations: List[str] = Field(default_factory=list)


class STIXMalware(STIXDomainObject):
    """STIX 2.1 Malware object"""
    type: STIXDomainObjectType = Field(default=STIXDomainObjectType.MALWARE, const=True)
    name: str = Field(description="Malware name")
    description: Optional[str] = Field(description="Malware description")
    malware_types: List[str] = Field(description="Types of malware")
    is_family: bool = Field(default=False, description="Is malware family")
    aliases: List[str] = Field(default_factory=list)
    kill_chain_phases: List[Dict[str, str]] = Field(default_factory=list)
    first_seen: Optional[datetime] = Field(description="First observation date")
    last_seen: Optional[datetime] = Field(description="Last observation date")
    operating_system_refs: List[str] = Field(default_factory=list)
    architecture_execution_envs: List[str] = Field(default_factory=list)
    implementation_languages: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)


class STIXAttackPattern(STIXDomainObject):
    """STIX 2.1 Attack Pattern object"""
    type: STIXDomainObjectType = Field(default=STIXDomainObjectType.ATTACK_PATTERN, const=True)
    name: str = Field(description="Attack pattern name")
    description: Optional[str] = Field(description="Attack pattern description")
    aliases: List[str] = Field(default_factory=list)
    kill_chain_phases: List[Dict[str, str]] = Field(default_factory=list)
    
    # MITRE ATT&CK extensions
    x_mitre_id: Optional[str] = Field(description="MITRE ATT&CK ID")
    x_mitre_version: Optional[str] = Field(description="MITRE version")
    x_mitre_platforms: List[str] = Field(default_factory=list)
    x_mitre_data_sources: List[str] = Field(default_factory=list)
    x_mitre_detection: Optional[str] = Field(description="Detection guidance")
    x_mitre_is_subtechnique: bool = Field(default=False)


class STIXIntrusionSet(STIXDomainObject):
    """STIX 2.1 Intrusion Set object"""
    type: STIXDomainObjectType = Field(default=STIXDomainObjectType.INTRUSION_SET, const=True)
    name: str = Field(description="Intrusion set name")
    description: Optional[str] = Field(description="Intrusion set description")
    aliases: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = Field(description="First observation date")
    last_seen: Optional[datetime] = Field(description="Last observation date")
    goals: List[str] = Field(default_factory=list)
    resource_level: Optional[str] = Field(description="Resource level")
    primary_motivation: Optional[str] = Field(description="Primary motivation")
    secondary_motivations: List[str] = Field(default_factory=list)


class STIXCampaign(STIXDomainObject):
    """STIX 2.1 Campaign object"""
    type: STIXDomainObjectType = Field(default=STIXDomainObjectType.CAMPAIGN, const=True)
    name: str = Field(description="Campaign name")
    description: Optional[str] = Field(description="Campaign description")
    aliases: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = Field(description="First observation date")
    last_seen: Optional[datetime] = Field(description="Last observation date")
    objective: Optional[str] = Field(description="Campaign objective")


class STIXReport(STIXDomainObject):
    """STIX 2.1 Report object"""
    type: STIXDomainObjectType = Field(default=STIXDomainObjectType.REPORT, const=True)
    name: str = Field(description="Report name")
    description: Optional[str] = Field(description="Report description")
    report_types: List[str] = Field(description="Types of report")
    published: datetime = Field(default_factory=datetime.utcnow)
    object_refs: List[str] = Field(description="Referenced STIX objects")
    
    # OpenCTI report extensions
    x_opencti_report_status: Optional[str] = Field(description="Report status")
    x_opencti_report_class: Optional[str] = Field(description="Report classification")


# =============================================================================
# STIX Cyber Observables
# =============================================================================

class STIXIPv4Address(STIXCyberObservable):
    """STIX 2.1 IPv4 Address observable"""
    type: STIXCyberObservableType = Field(default=STIXCyberObservableType.IPV4_ADDR, const=True)
    value: str = Field(description="IPv4 address value")
    resolves_to_refs: List[str] = Field(default_factory=list)
    belongs_to_refs: List[str] = Field(default_factory=list)


class STIXIPv6Address(STIXCyberObservable):
    """STIX 2.1 IPv6 Address observable"""
    type: STIXCyberObservableType = Field(default=STIXCyberObservableType.IPV6_ADDR, const=True)
    value: str = Field(description="IPv6 address value")
    resolves_to_refs: List[str] = Field(default_factory=list)
    belongs_to_refs: List[str] = Field(default_factory=list)


class STIXDomainName(STIXCyberObservable):
    """STIX 2.1 Domain Name observable"""
    type: STIXCyberObservableType = Field(default=STIXCyberObservableType.DOMAIN_NAME, const=True)
    value: str = Field(description="Domain name value")
    resolves_to_refs: List[str] = Field(default_factory=list)


class STIXURL(STIXCyberObservable):
    """STIX 2.1 URL observable"""
    type: STIXCyberObservableType = Field(default=STIXCyberObservableType.URL, const=True)
    value: str = Field(description="URL value")


class STIXEmailAddress(STIXCyberObservable):
    """STIX 2.1 Email Address observable"""
    type: STIXCyberObservableType = Field(default=STIXCyberObservableType.EMAIL_ADDR, const=True)
    value: str = Field(description="Email address value")
    display_name: Optional[str] = Field(description="Display name")
    belongs_to_ref: Optional[str] = Field(description="User account reference")


class STIXFile(STIXCyberObservable):
    """STIX 2.1 File observable"""
    type: STIXCyberObservableType = Field(default=STIXCyberObservableType.FILE, const=True)
    hashes: Dict[str, str] = Field(description="File hashes")
    size: Optional[int] = Field(description="File size in bytes")
    name: Optional[str] = Field(description="File name")
    name_enc: Optional[str] = Field(description="File name encoding")
    magic_number_hex: Optional[str] = Field(description="Magic number")
    mime_type: Optional[str] = Field(description="MIME type")
    ctime: Optional[datetime] = Field(description="Creation time")
    mtime: Optional[datetime] = Field(description="Modification time")
    atime: Optional[datetime] = Field(description="Access time")
    parent_directory_ref: Optional[str] = Field(description="Parent directory reference")
    contains_refs: List[str] = Field(default_factory=list)
    content_ref: Optional[str] = Field(description="Content reference")


# =============================================================================
# STIX Relationship Objects
# =============================================================================

class STIXRelationship(STIXRelationshipObject):
    """STIX 2.1 Relationship object"""
    type: STIXRelationshipType = Field(default=STIXRelationshipType.RELATIONSHIP, const=True)
    description: Optional[str] = Field(description="Relationship description")
    start_time: Optional[datetime] = Field(description="Relationship start time")
    stop_time: Optional[datetime] = Field(description="Relationship stop time")
    
    # OpenCTI relationship extensions
    x_opencti_weight: Optional[int] = Field(description="Relationship weight")
    x_opencti_ignore_dates: bool = Field(default=False)


class STIXSighting(STIXRelationshipObject):
    """STIX 2.1 Sighting object"""
    type: STIXRelationshipType = Field(default=STIXRelationshipType.SIGHTING, const=True)
    first_seen: Optional[datetime] = Field(description="First sighting time")
    last_seen: Optional[datetime] = Field(description="Last sighting time")
    count: Optional[int] = Field(description="Number of sightings")
    sighting_of_ref: str = Field(description="Sighted object reference")
    observed_data_refs: List[str] = Field(default_factory=list)
    where_sighted_refs: List[str] = Field(default_factory=list)
    summary: bool = Field(default=False)
    
    # Override base relationship fields for sighting-specific usage
    source_ref: Optional[str] = Field(description="Source object reference")
    target_ref: Optional[str] = Field(description="Target object reference")
    relationship_type: str = Field(default="sighting", const=True)


# =============================================================================
# STIX Bundle
# =============================================================================

class STIXBundle(BaseModel):
    """STIX 2.1 Bundle object"""
    type: str = Field(default="bundle", const=True)
    id: str = Field(description="Bundle identifier")
    objects: List[Dict[str, Any]] = Field(description="STIX objects in bundle")
    
    @validator('id', pre=True, always=True)
    def generate_bundle_id(cls, v):
        if not v:
            return f"bundle--{str(uuid.uuid4())}"
        return v
    
    class Config:
        validate_assignment = True


# =============================================================================
# OpenCTI Extensions
# =============================================================================

class OpenCTIMarkingDefinition(BaseModel):
    """OpenCTI Marking Definition"""
    type: str = Field(default="marking-definition", const=True)
    spec_version: str = Field(default="2.1")
    id: str = Field(description="Marking definition ID")
    created: datetime = Field(default_factory=datetime.utcnow)
    definition_type: str = Field(description="Type of marking definition")
    name: str = Field(description="Marking name")
    definition: Dict[str, Any] = Field(description="Marking definition")
    
    @validator('id', pre=True, always=True)
    def generate_marking_id(cls, v):
        if not v:
            return f"marking-definition--{str(uuid.uuid4())}"
        return v


class OpenCTILabel(BaseModel):
    """OpenCTI Label object"""
    id: str = Field(description="Label ID")
    value: str = Field(description="Label value")
    color: Optional[str] = Field(description="Label color")
    
    @validator('id', pre=True, always=True)
    def generate_label_id(cls, v):
        if not v:
            return f"label--{str(uuid.uuid4())}"
        return v


# =============================================================================
# Model Registry for Dynamic Access
# =============================================================================

STIX_MODEL_REGISTRY = {
    # Domain Objects
    "indicator": STIXIndicator,
    "threat-actor": STIXThreatActor,
    "malware": STIXMalware,
    "attack-pattern": STIXAttackPattern,
    "intrusion-set": STIXIntrusionSet,
    "campaign": STIXCampaign,
    "report": STIXReport,
    
    # Cyber Observables
    "ipv4-addr": STIXIPv4Address,
    "ipv6-addr": STIXIPv6Address,
    "domain-name": STIXDomainName,
    "url": STIXURL,
    "email-addr": STIXEmailAddress,
    "file": STIXFile,
    
    # Relationship Objects
    "relationship": STIXRelationship,
    "sighting": STIXSighting,
    
    # Bundles and Extensions
    "bundle": STIXBundle,
    "marking-definition": OpenCTIMarkingDefinition,
    "label": OpenCTILabel,
}


def get_stix_model(object_type: str):
    """Get STIX model class by object type"""
    return STIX_MODEL_REGISTRY.get(object_type)


def create_stix_object(object_type: str, **kwargs):
    """Create STIX object instance by type"""
    model_class = get_stix_model(object_type)
    if model_class:
        return model_class(**kwargs)
    raise ValueError(f"Unknown STIX object type: {object_type}")
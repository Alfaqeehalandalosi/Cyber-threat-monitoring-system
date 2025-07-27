# 🔗 OpenCTI Integration Guide

## Overview

This Cyber Threat Monitoring System has been enhanced with OpenCTI-inspired features, bringing enterprise-grade threat intelligence capabilities to our platform. This integration provides STIX 2.1 compliance, advanced data processing, and a modular connector architecture.

## 🎯 Key Features Inspired by OpenCTI

### 1. STIX 2.1 Compliance
- **Full STIX 2.1 Data Models**: Complete implementation of STIX Domain Objects (SDOs), Cyber Observables (SCOs), and Relationship Objects (SROs)
- **OpenCTI Extensions**: Support for OpenCTI-specific extensions like scoring, labels, and metadata
- **Bundle Processing**: Advanced STIX bundle import/export with validation and enrichment

### 2. Advanced Data Processing Engine
- **Pattern Parsing**: Extract cyber observables from STIX patterns
- **Relationship Management**: Automatic relationship creation and management
- **Enrichment Engine**: AI-powered data enrichment with confidence scoring
- **Deduplication**: Smart object merging and duplicate detection

### 3. Connector Architecture
- **Modular Design**: Plugin-based connector system supporting multiple connector types
- **MITRE ATT&CK Integration**: Built-in connector for MITRE ATT&CK framework data
- **Health Monitoring**: Real-time connector status and health checking
- **Background Processing**: Asynchronous connector execution with work tracking

## 🏗️ Architecture Components

### STIX Data Models (`ctms/database/stix_models.py`)

Complete STIX 2.1 implementation with OpenCTI extensions:

```python
# Core STIX objects supported
- STIXIndicator (with detection patterns)
- STIXThreatActor (threat actor intelligence)
- STIXMalware (malware analysis)
- STIXAttackPattern (MITRE ATT&CK techniques)
- STIXIntrusionSet (threat groups)
- STIXCampaign (threat campaigns)
- STIXRelationship (object relationships)
- STIXSighting (indicator sightings)

# Cyber Observables
- STIXIPv4Address / STIXIPv6Address
- STIXDomainName
- STIXURL
- STIXEmailAddress
- STIXFile (with hashes)
```

### STIX Processor (`ctms/intelligence/stix_processor.py`)

Advanced STIX bundle processing engine:

```python
class STIXProcessor:
    """OpenCTI-inspired STIX 2.1 processing engine"""
    
    # Key capabilities:
    - Bundle validation and processing
    - Object enrichment and scoring
    - Relationship auto-creation
    - Export functionality
    - Processing statistics
```

### Connector Framework (`ctms/connectors/`)

Modular connector architecture:

```python
# Connector Types (OpenCTI-compatible)
ConnectorType.EXTERNAL_IMPORT    # Import from external sources
ConnectorType.INTERNAL_ENRICHMENT # Enrich existing data
ConnectorType.INTERNAL_EXPORT_FILE # Export to files
ConnectorType.STREAM             # Real-time data streaming

# Built-in Connectors
- MitreAttackConnector: MITRE ATT&CK framework integration
- [Extensible for custom connectors]
```

## 🚀 API Endpoints

### STIX Operations

#### Import STIX Bundle
```http
POST /api/v1/stix/import
Content-Type: application/json
Authorization: Bearer {token}

{
    "type": "bundle",
    "id": "bundle--uuid",
    "objects": [...]
}
```

#### Export STIX Bundle
```http
GET /api/v1/stix/export?object_types=indicator,malware&include_relationships=true
Authorization: Bearer {token}
```

#### Get Sample STIX Bundle
```http
GET /api/v1/stix/sample
Authorization: Bearer {token}
```

### Connector Management

#### List Connectors
```http
GET /api/v1/connectors
Authorization: Bearer {token}
```

#### Start MITRE Connector
```http
POST /api/v1/connectors/mitre/start
Content-Type: application/json
Authorization: Bearer {token}

{
    "domains": ["enterprise", "mobile"],
    "interval_hours": 24
}
```

#### Get Connector Status
```http
GET /api/v1/connectors/{connector_id}/status
Authorization: Bearer {token}
```

## 🔧 Configuration

### STIX Processing Configuration

Add to your `.env` file:

```bash
# STIX Processing
STIX_AUTO_ENRICH=true
STIX_UPDATE_EXISTING=true
STIX_CONFIDENCE_THRESHOLD=50

# Connector Settings
CONNECTOR_REGISTRY_PATH=./connectors
CONNECTOR_LOG_LEVEL=info
CONNECTOR_HEALTH_CHECK_INTERVAL=60

# MITRE ATT&CK Connector
MITRE_DOMAINS=enterprise,mobile
MITRE_UPDATE_INTERVAL=86400  # 24 hours
MITRE_CONFIDENCE_LEVEL=75
```

### Database Schema

The system automatically creates STIX-compatible collections:

```javascript
// MongoDB Collections
stix_objects          // All STIX objects
stix_relationships    // Object relationships
stix_bundles         // Processed bundles
connector_states     // Connector state storage

// Elasticsearch Indices
stix_indicator       // Searchable indicators
stix_malware        // Malware intelligence
stix_threat_actor   // Threat actor data
stix_attack_pattern // MITRE techniques
```

## 💡 Usage Examples

### 1. Import Threat Intelligence

```python
import requests

# Prepare STIX bundle
bundle = {
    "type": "bundle",
    "id": "bundle--sample",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--sample",
            "pattern": "[ipv4-addr:value = '192.168.1.100']",
            "labels": ["malicious-activity"],
            "valid_from": "2024-01-01T00:00:00Z"
        }
    ]
}

# Import via API
response = requests.post(
    "http://localhost:8000/api/v1/stix/import",
    json=bundle,
    headers={"Authorization": "Bearer demo_token_for_development_12345"}
)

print(response.json())
```

### 2. Start MITRE Connector

```python
import requests

# Start MITRE ATT&CK connector
response = requests.post(
    "http://localhost:8000/api/v1/connectors/mitre/start",
    json={
        "domains": ["enterprise"],
        "interval_hours": 24
    },
    headers={"Authorization": "Bearer demo_token_for_development_12345"}
)

print(response.json())
```

### 3. Export Threat Data

```python
import requests

# Export indicators as STIX bundle
response = requests.get(
    "http://localhost:8000/api/v1/stix/export?object_types=indicator&include_relationships=true",
    headers={"Authorization": "Bearer demo_token_for_development_12345"}
)

bundle = response.json()
print(f"Exported {len(bundle['objects'])} objects")
```

## 🔍 Advanced Features

### 1. Pattern Analysis

The system can parse complex STIX patterns:

```python
# Supported pattern types
"[ipv4-addr:value = '192.168.1.1']"
"[domain-name:value = 'malicious.com']"
"[file:hashes.'SHA-256' = 'abc123...']"
"[url:value = 'http://evil.com/malware.exe']"

# Complex patterns with AND/OR
"[ipv4-addr:value = '192.168.1.1' AND url:value = 'http://evil.com']"
```

### 2. Relationship Auto-Creation

Indicators automatically create relationships with extracted observables:

```json
{
    "type": "relationship",
    "relationship_type": "indicates",
    "source_ref": "indicator--uuid",
    "target_ref": "ipv4-addr--uuid",
    "description": "Indicator indicates IPv4 address"
}
```

### 3. Enrichment Engine

Objects are automatically enriched with:
- Risk scores (0-100)
- Classification labels
- OpenCTI metadata
- Confidence levels
- Kill chain phases

### 4. MITRE ATT&CK Integration

Automatic import of:
- Attack techniques and sub-techniques
- Threat actor groups
- Malware families
- Relationships and mappings
- Platform-specific data

## 📊 Dashboard Integration

The Streamlit dashboard includes new OpenCTI-inspired features:

### STIX Management Tab
- View imported STIX objects
- Browse relationships
- Export functionality
- Processing statistics

### Connector Status Tab
- Active connector monitoring
- Health status indicators
- Start/stop connector controls
- Processing metrics

### Intelligence Analytics
- MITRE ATT&CK technique coverage
- Threat actor analysis
- Campaign tracking
- IOC relationship graphs

## 🔐 Security Considerations

### Data Validation
- STIX schema validation
- Input sanitization
- Bundle integrity checks
- Relationship validation

### Access Control
- API authentication required
- Role-based permissions
- Audit logging
- Secure defaults

### Data Privacy
- TLP (Traffic Light Protocol) support
- Marking definitions
- Granular markings
- Data retention policies

## 🚀 Performance Optimization

### Database Optimization
- Elasticsearch indexing for fast search
- MongoDB sharding support
- Connection pooling
- Query optimization

### Processing Optimization
- Asynchronous bundle processing
- Batch operations
- Memory-efficient streaming
- Background task queuing

### Connector Optimization
- Circuit breaker patterns
- Rate limiting
- Health monitoring
- Auto-retry mechanisms

## 📈 Monitoring and Metrics

### STIX Processing Metrics
- Objects processed per hour
- Processing success rate
- Error rates and types
- Bundle size statistics

### Connector Metrics
- Active connector count
- Data import volume
- Processing latency
- Health status

### System Metrics
- Database performance
- Memory usage
- Network throughput
- Error rates

## 🔄 Migration from OpenCTI

If migrating from OpenCTI, the system supports:

### Data Migration
1. Export STIX bundles from OpenCTI
2. Import via `/api/v1/stix/import` endpoint
3. Verify data integrity
4. Update configurations

### Connector Migration
1. Review OpenCTI connector configurations
2. Adapt to CTMS connector format
3. Test connector functionality
4. Deploy and monitor

## 🛠️ Development and Customization

### Creating Custom Connectors

```python
from ctms.connectors.base_connector import BaseConnector, ConnectorWork
from ctms.connectors import register_connector, ConnectorType

@register_connector
class CustomConnector(BaseConnector):
    async def _initialize(self):
        # Connector initialization
        pass
    
    async def _execute_work(self, work: ConnectorWork):
        # Main processing logic
        pass
    
    async def _cleanup(self):
        # Cleanup resources
        pass
```

### Extending STIX Models

```python
from ctms.database.stix_models import STIXDomainObject

class CustomSTIXObject(STIXDomainObject):
    custom_field: str
    x_custom_extension: Dict[str, Any]
```

## 📚 References

- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [OpenCTI Documentation](https://docs.opencti.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)

## ✨ Benefits of OpenCTI Integration

1. **Standardization**: Full STIX 2.1 compliance ensures interoperability
2. **Scalability**: Enterprise-grade architecture supports large-scale deployments  
3. **Flexibility**: Modular connector system enables custom integrations
4. **Intelligence**: Advanced analytics and relationship mapping
5. **Automation**: Automated data processing and enrichment
6. **Compatibility**: Works with existing OpenCTI ecosystems

This integration transforms our threat monitoring system into an enterprise-ready threat intelligence platform, combining the best of OpenCTI's architecture with our specialized monitoring capabilities.
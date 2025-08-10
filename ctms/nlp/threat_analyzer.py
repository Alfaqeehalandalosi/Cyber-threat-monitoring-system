# =============================================================================
# THREAT ANALYSIS NLP ENGINE
# =============================================================================
"""
Advanced NLP engine for threat intelligence analysis, entity extraction,
and security content classification using spaCy and machine learning models.
"""

import re
import spacy
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
from collections import defaultdict, Counter
import asyncio

from ctms.core.logger import get_logger
from ctms.database.models import (
    NLPAnalysis, ScrapedContent, IndicatorOfCompromise, 
    ThreatIntelligence, IndicatorType, ThreatType, SeverityLevel
)
from ctms.database.connection import get_database

logger = get_logger(__name__)


# =============================================================================
# IOC EXTRACTION PATTERNS
# =============================================================================
class IOCPatterns:
    """
    Regular expression patterns for extracting indicators of compromise.
    Covers common IOC types with high accuracy patterns.
    """
    
    # IP Address patterns
    IPV4_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    
    # Domain patterns
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    # URL patterns
    URL_PATTERN = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    
    # Hash patterns
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    SHA512_PATTERN = r'\b[a-fA-F0-9]{128}\b'
    
    # Email patterns
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # File path patterns
    WINDOWS_PATH_PATTERN = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
    UNIX_PATH_PATTERN = r'/(?:[^/\0]+/)*[^/\0]*'
    
    # Registry key patterns
    REGISTRY_PATTERN = r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CURRENT_CONFIG|CLASSES_ROOT)\\[^\\]+(?:\\[^\\]+)*'
    
    # Bitcoin address patterns
    BITCOIN_PATTERN = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'


# =============================================================================
# THREAT KEYWORDS AND INDICATORS
# =============================================================================
class ThreatKeywords:
    """
    Comprehensive threat keywords categorized by threat type.
    Used for content classification and threat scoring.
    """
    
    MALWARE_KEYWORDS = {
        'trojan', 'virus', 'worm', 'backdoor', 'rootkit', 'spyware', 'adware',
        'keylogger', 'botnet', 'rat', 'remote access', 'payload', 'dropper',
        'loader', 'banker', 'stealer', 'ransomware', 'cryptolocker', 'wannacry',
        'maze', 'sodinokibi', 'ryuk', 'emotet', 'trickbot', 'dridex'
    }
    
    PHISHING_KEYWORDS = {
        'phishing', 'spear phishing', 'social engineering', 'credential harvesting',
        'fake login', 'impersonation', 'business email compromise', 'bec',
        'invoice fraud', 'wire fraud', 'spoofed', 'deceptive', 'fraudulent'
    }
    
    EXPLOIT_KEYWORDS = {
        'exploit', 'vulnerability', 'zero-day', '0day', 'cve-', 'buffer overflow',
        'sql injection', 'xss', 'csrf', 'rce', 'remote code execution',
        'privilege escalation', 'arbitrary code', 'memory corruption'
    }
    
    APT_KEYWORDS = {
        'apt', 'advanced persistent threat', 'nation state', 'state-sponsored',
        'cyber espionage', 'intelligence gathering', 'lateral movement',
        'persistence', 'exfiltration', 'targeted attack', 'sophisticated'
    }
    
    NETWORK_KEYWORDS = {
        'botnet', 'c2', 'command and control', 'dns tunneling', 'beacon',
        'communication', 'infrastructure', 'proxy', 'tor', 'anonymization'
    }
    
    CRYPTO_KEYWORDS = {
        'cryptocurrency', 'bitcoin', 'ethereum', 'monero', 'crypto mining',
        'cryptojacking', 'crypto wallet', 'blockchain', 'smart contract'
    }


# =============================================================================
# THREAT CLASSIFIER
# =============================================================================
class ThreatClassifier:
    """
    Classifies content based on threat keywords and patterns.
    Provides threat scoring and severity assessment.
    """
    
    def __init__(self):
        """Initialize threat classifier."""
        self.threat_keywords = ThreatKeywords()
        logger.info("🎯 Threat classifier initialized")
    
    def classify_content(self, content: str, title: str = "") -> Dict[str, Any]:
        """
        Classify content for threat types and calculate scores.
        
        Args:
            content: Content to classify
            title: Optional title for additional context
            
        Returns:
            Dict[str, Any]: Classification results
        """
        # Combine content and title for analysis
        full_text = f"{title} {content}".lower()
        
        # Calculate threat scores for each category
        threat_scores = {
            'malware': self._calculate_keyword_score(full_text, self.threat_keywords.MALWARE_KEYWORDS),
            'phishing': self._calculate_keyword_score(full_text, self.threat_keywords.PHISHING_KEYWORDS),
            'exploit': self._calculate_keyword_score(full_text, self.threat_keywords.EXPLOIT_KEYWORDS),
            'apt': self._calculate_keyword_score(full_text, self.threat_keywords.APT_KEYWORDS),
            'network': self._calculate_keyword_score(full_text, self.threat_keywords.NETWORK_KEYWORDS),
            'crypto': self._calculate_keyword_score(full_text, self.threat_keywords.CRYPTO_KEYWORDS)
        }
        
        # Find primary threat type
        primary_threat_type = max(threat_scores.items(), key=lambda x: x[1])[0]
        threat_score = threat_scores[primary_threat_type]
        
        # Calculate severity
        severity = self._calculate_severity(full_text, threat_scores)
        
        # Calculate confidence
        confidence = self._calculate_confidence(threat_scores, full_text)
        
        # Extract found keywords
        keywords_found = self._extract_found_keywords(full_text)
        
        return {
            "primary_threat_type": primary_threat_type,
            "threat_score": threat_score,
            "threat_scores": threat_scores,
            "severity": severity,
            "confidence": confidence,
            "keywords_found": keywords_found
        }
    
    def _calculate_keyword_score(self, text: str, keywords: Set[str]) -> float:
        """
        Calculate threat score based on keyword matches.
        
        Args:
            text: Text to analyze
            keywords: Set of threat keywords
            
        Returns:
            float: Threat score (0.0 to 1.0)
        """
        matches = sum(1 for keyword in keywords if keyword in text)
        total_keywords = len(keywords)
        
        if total_keywords == 0:
            return 0.0
        
        # Normalize score and apply logarithmic scaling
        base_score = matches / total_keywords
        return min(1.0, base_score * 10)  # Scale up for better sensitivity
    
    def _calculate_severity(self, text: str, threat_scores: Dict[str, float]) -> SeverityLevel:
        """
        Calculate threat severity level.
        
        Args:
            text: Text content
            threat_scores: Threat scores by category
            
        Returns:
            SeverityLevel: Calculated severity
        """
        max_score = max(threat_scores.values())
        
        if max_score >= 0.8:
            return SeverityLevel.CRITICAL
        elif max_score >= 0.6:
            return SeverityLevel.HIGH
        elif max_score >= 0.4:
            return SeverityLevel.MEDIUM
        elif max_score >= 0.2:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _calculate_confidence(self, threat_scores: Dict[str, float], text: str) -> float:
        """
        Calculate confidence in the threat assessment.
        
        Args:
            threat_scores: Threat scores by category
            text: Text content
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        max_score = max(threat_scores.values())
        text_length = len(text)
        
        # Base confidence on score and text length
        score_confidence = max_score
        length_confidence = min(1.0, text_length / 1000)  # More text = higher confidence
        
        return (score_confidence + length_confidence) / 2
    
    def _extract_found_keywords(self, text: str) -> List[str]:
        """
        Extract all found threat keywords from text.
        
        Args:
            text: Text to search
            
        Returns:
            List[str]: Found keywords
        """
        all_keywords = (
            self.threat_keywords.MALWARE_KEYWORDS |
            self.threat_keywords.PHISHING_KEYWORDS |
            self.threat_keywords.EXPLOIT_KEYWORDS |
            self.threat_keywords.APT_KEYWORDS |
            self.threat_keywords.NETWORK_KEYWORDS |
            self.threat_keywords.CRYPTO_KEYWORDS
        )
        
        found = [keyword for keyword in all_keywords if keyword in text.lower()]
        return list(set(found))  # Remove duplicates


# =============================================================================
# IOC EXTRACTOR
# =============================================================================
class IOCExtractor:
    """
    Extracts indicators of compromise from text content.
    Uses regex patterns and validation for accurate IOC detection.
    """
    
    def __init__(self):
        """Initialize IOC extractor."""
        self.patterns = IOCPatterns()
        logger.info("🔍 IOC extractor initialized")
    
    def extract_iocs(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract all types of IOCs from content.
        
        Args:
            content: Text content to analyze
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Extracted IOCs by type
        """
        iocs = {
            'ip_addresses': [],
            'domains': [],
            'urls': [],
            'hashes': [],
            'emails': [],
            'file_paths': [],
            'registry_keys': [],
            'bitcoin_addresses': []
        }
        
        # Extract IPv4 addresses
        ipv4_matches = re.finditer(self.patterns.IPV4_PATTERN, content)
        for match in ipv4_matches:
            ip = match.group()
            if self._is_valid_ioc(ip, IndicatorType.IP_ADDRESS):
                iocs['ip_addresses'].append({
                    'value': ip,
                    'type': 'ipv4',
                    'position': match.span(),
                    'context': self._extract_context(content, match.span()),
                    'confidence': self._calculate_ioc_confidence(ip, IndicatorType.IP_ADDRESS)
                })
        
        # Extract domains
        domain_matches = re.finditer(self.patterns.DOMAIN_PATTERN, content)
        for match in domain_matches:
            domain = match.group()
            if self._is_valid_ioc(domain, IndicatorType.DOMAIN):
                iocs['domains'].append({
                    'value': domain,
                    'type': 'domain',
                    'position': match.span(),
                    'context': self._extract_context(content, match.span()),
                    'confidence': self._calculate_ioc_confidence(domain, IndicatorType.DOMAIN)
                })
        
        # Extract URLs
        url_matches = re.finditer(self.patterns.URL_PATTERN, content)
        for match in url_matches:
            url = match.group()
            if self._is_valid_ioc(url, IndicatorType.URL):
                iocs['urls'].append({
                    'value': url,
                    'type': 'url',
                    'position': match.span(),
                    'context': self._extract_context(content, match.span()),
                    'confidence': self._calculate_ioc_confidence(url, IndicatorType.URL)
                })
        
        # Extract hashes
        for hash_pattern, hash_type in [
            (self.patterns.MD5_PATTERN, 'md5'),
            (self.patterns.SHA1_PATTERN, 'sha1'),
            (self.patterns.SHA256_PATTERN, 'sha256'),
            (self.patterns.SHA512_PATTERN, 'sha512')
        ]:
            hash_matches = re.finditer(hash_pattern, content)
            for match in hash_matches:
                hash_value = match.group()
                if self._is_valid_ioc(hash_value, IndicatorType.HASH):
                    iocs['hashes'].append({
                        'value': hash_value,
                        'type': hash_type,
                        'position': match.span(),
                        'context': self._extract_context(content, match.span()),
                        'confidence': self._calculate_ioc_confidence(hash_value, IndicatorType.HASH)
                    })
        
        # Extract emails
        email_matches = re.finditer(self.patterns.EMAIL_PATTERN, content)
        for match in email_matches:
            email = match.group()
            if self._is_valid_ioc(email, IndicatorType.EMAIL):
                iocs['emails'].append({
                    'value': email,
                    'type': 'email',
                    'position': match.span(),
                    'context': self._extract_context(content, match.span()),
                    'confidence': self._calculate_ioc_confidence(email, IndicatorType.EMAIL)
                })
        
        # Extract file paths
        for path_pattern, path_type in [
            (self.patterns.WINDOWS_PATH_PATTERN, 'windows_path'),
            (self.patterns.UNIX_PATH_PATTERN, 'unix_path')
        ]:
            path_matches = re.finditer(path_pattern, content)
            for match in path_matches:
                path = match.group()
                iocs['file_paths'].append({
                    'value': path,
                    'type': path_type,
                    'position': match.span(),
                    'context': self._extract_context(content, match.span()),
                    'confidence': 0.8  # High confidence for well-formed paths
                })
        
        # Extract registry keys
        registry_matches = re.finditer(self.patterns.REGISTRY_PATTERN, content)
        for match in registry_matches:
            registry = match.group()
            iocs['registry_keys'].append({
                'value': registry,
                'type': 'registry_key',
                'position': match.span(),
                'context': self._extract_context(content, match.span()),
                'confidence': 0.9  # High confidence for registry patterns
            })
        
        # Extract Bitcoin addresses
        bitcoin_matches = re.finditer(self.patterns.BITCOIN_PATTERN, content)
        for match in bitcoin_matches:
            bitcoin = match.group()
            iocs['bitcoin_addresses'].append({
                'value': bitcoin,
                'type': 'bitcoin_address',
                'position': match.span(),
                'context': self._extract_context(content, match.span()),
                'confidence': 0.7  # Medium confidence for Bitcoin addresses
            })
        
        # Remove duplicates and filter by confidence
        for ioc_type in iocs:
            iocs[ioc_type] = self._deduplicate_iocs(iocs[ioc_type])
            iocs[ioc_type] = [ioc for ioc in iocs[ioc_type] if ioc['confidence'] > 0.3]
        
        return iocs
    
    def _is_valid_ioc(self, value: str, ioc_type: IndicatorType) -> bool:
        """
        Validate IOC value based on type.
        
        Args:
            value: IOC value to validate
            ioc_type: Type of IOC
            
        Returns:
            bool: True if valid
        """
        if not value or len(value.strip()) == 0:
            return False
        
        try:
            if ioc_type == IndicatorType.IP_ADDRESS:
                return self._validate_ip_address(value)
            elif ioc_type == IndicatorType.DOMAIN:
                return self._validate_domain(value)
            elif ioc_type == IndicatorType.HASH:
                return self._validate_hash(value)
            elif ioc_type == IndicatorType.EMAIL:
                return self._validate_email(value)
            else:
                return True
        except Exception:
            return False
    
    def _validate_ip_address(self, ip: str) -> bool:
        """
        Validate IP address format and range.
        
        Args:
            ip: IP address to validate
            
        Returns:
            bool: True if valid
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not part.isdigit():
                    return False
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            # Filter out private IP ranges
            if ip.startswith(('10.', '192.168.', '172.')):
                return False
            
            return True
        except Exception:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """
        Validate domain format.
        
        Args:
            domain: Domain to validate
            
        Returns:
            bool: True if valid
        """
        try:
            # Basic domain validation
            if len(domain) < 3 or len(domain) > 253:
                return False
            
            # Check for valid TLD
            valid_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.io', '.co', '.uk', '.de', '.fr', '.jp', '.cn', '.ru'}
            has_valid_tld = any(domain.endswith(tld) for tld in valid_tlds)
            
            # Check for suspicious patterns
            suspicious_patterns = ['malware', 'virus', 'trojan', 'hack', 'crack', 'warez']
            has_suspicious = any(pattern in domain.lower() for pattern in suspicious_patterns)
            
            return has_valid_tld and not has_suspicious
        except Exception:
            return False
    
    def _validate_hash(self, hash_value: str) -> bool:
        """
        Validate hash format.
        
        Args:
            hash_value: Hash to validate
            
        Returns:
            bool: True if valid
        """
        # Check if it's a valid hex string
        try:
            int(hash_value, 16)
            return True
        except ValueError:
            return False
    
    def _validate_email(self, email: str) -> bool:
        """
        Validate email format.
        
        Args:
            email: Email to validate
            
        Returns:
            bool: True if valid
        """
        try:
            # Basic email validation
            if '@' not in email or '.' not in email:
                return False
            
            local, domain = email.split('@', 1)
            if len(local) < 1 or len(domain) < 3:
                return False
            
            return True
        except Exception:
            return False
    
    def _extract_context(self, content: str, position: Tuple[int, int], context_size: int = 50) -> str:
        """
        Extract context around IOC position.
        
        Args:
            content: Full content
            position: IOC position (start, end)
            context_size: Number of characters around IOC
            
        Returns:
            str: Context string
        """
        start, end = position
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        
        return content[context_start:context_end].strip()
    
    def _calculate_ioc_confidence(self, value: str, ioc_type: IndicatorType) -> float:
        """
        Calculate confidence score for IOC.
        
        Args:
            value: IOC value
            ioc_type: Type of IOC
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        base_confidence = 0.8
        
        # Adjust based on IOC type
        if ioc_type == IndicatorType.IP_ADDRESS:
            if self._validate_ip_address(value):
                return 0.9
        elif ioc_type == IndicatorType.DOMAIN:
            if self._validate_domain(value):
                return 0.8
        elif ioc_type == IndicatorType.HASH:
            if self._validate_hash(value):
                return 0.95
        elif ioc_type == IndicatorType.EMAIL:
            if self._validate_email(value):
                return 0.85
        
        return base_confidence
    
    def _deduplicate_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate IOCs based on value.
        
        Args:
            iocs: List of IOC dictionaries
            
        Returns:
            List[Dict[str, Any]]: Deduplicated IOCs
        """
        seen = set()
        unique_iocs = []
        
        for ioc in iocs:
            if ioc['value'] not in seen:
                seen.add(ioc['value'])
                unique_iocs.append(ioc)
        
        return unique_iocs


# =============================================================================
# ENTITY EXTRACTOR
# =============================================================================
class EntityExtractor:
    """
    Extracts named entities and security-relevant information from text.
    Uses spaCy for advanced NLP processing.
    """
    
    def __init__(self):
        """Initialize entity extractor."""
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            # Fallback to basic English model
            self.nlp = spacy.load("en_core_web_sm", disable=["ner"])
            logger.warning("⚠️ Using basic spaCy model (NER disabled)")
        
        logger.info("🏷️ Entity extractor initialized")
    
    def extract_entities(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract named entities from content.
        
        Args:
            content: Text content to analyze
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Extracted entities by type
        """
        entities = {
            'organizations': [],
            'persons': [],
            'locations': [],
            'dates': [],
            'security_entities': []
        }
        
        try:
            # Process with spaCy
            doc = self.nlp(content)
            
            # Extract standard named entities
            for ent in doc.ents:
                entity_info = {
                    'text': ent.text,
                    'label': ent.label_,
                    'start': ent.start_char,
                    'end': ent.end_char,
                    'confidence': 0.8
                }
                
                if ent.label_ == 'ORG':
                    entities['organizations'].append(entity_info)
                elif ent.label_ == 'PERSON':
                    entities['persons'].append(entity_info)
                elif ent.label_ == 'GPE' or ent.label_ == 'LOC':
                    entities['locations'].append(entity_info)
                elif ent.label_ == 'DATE':
                    entities['dates'].append(entity_info)
            
            # Extract security-specific entities
            security_entities = self._extract_security_entities(content)
            entities['security_entities'] = security_entities
            
            # Extract keywords
            keywords = self._extract_keywords(doc)
            entities['keywords'] = keywords
            
        except Exception as e:
            logger.error(f"❌ Entity extraction failed: {e}")
        
        return entities
    
    def _extract_security_entities(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract security-specific entities and terms.
        
        Args:
            content: Text content
            
        Returns:
            List[Dict[str, Any]]: Security entities
        """
        security_terms = [
            'malware', 'virus', 'trojan', 'ransomware', 'phishing', 'apt',
            'exploit', 'vulnerability', 'zero-day', 'cve', 'mitre', 'att&ck',
            'firewall', 'ids', 'ips', 'siem', 'edr', 'xdr', 'soar'
        ]
        
        entities = []
        content_lower = content.lower()
        
        for term in security_terms:
            if term in content_lower:
                start = content_lower.find(term)
                entities.append({
                    'text': term,
                    'label': 'SECURITY_TERM',
                    'start': start,
                    'end': start + len(term),
                    'confidence': 0.9
                })
        
        return entities
    
    def _extract_keywords(self, doc) -> List[Dict[str, Any]]:
        """
        Extract important keywords from document.
        
        Args:
            doc: spaCy document
            
        Returns:
            List[Dict[str, Any]]: Keywords with scores
        """
        keywords = []
        
        # Extract noun chunks and important tokens
        for chunk in doc.noun_chunks:
            if len(chunk.text) > 3:  # Filter short chunks
                keywords.append({
                    'text': chunk.text,
                    'label': 'NOUN_CHUNK',
                    'start': chunk.start_char,
                    'end': chunk.end_char,
                    'confidence': 0.7
                })
        
        # Extract verbs
        for token in doc:
            if token.pos_ == 'VERB' and len(token.text) > 3:
                keywords.append({
                    'text': token.text,
                    'label': 'VERB',
                    'start': token.idx,
                    'end': token.idx + len(token.text),
                    'confidence': 0.6
                })
        
        return keywords


# =============================================================================
# MAIN THREAT ANALYZER
# =============================================================================
class ThreatAnalyzer:
    """
    Main threat analysis engine that orchestrates all NLP components
    for comprehensive threat intelligence analysis.
    """
    
    def __init__(self):
        """Initialize threat analyzer."""
        self.classifier = ThreatClassifier()
        self.ioc_extractor = IOCExtractor()
        self.entity_extractor = EntityExtractor()
        
        logger.info("🧠 Threat analyzer initialized")
    
    async def analyze_content(self, content: ScrapedContent) -> NLPAnalysis:
        """
        Perform comprehensive threat analysis on scraped content.
        
        Args:
            content: Scraped content to analyze
            
        Returns:
            NLPAnalysis: Complete analysis results
        """
        start_time = time.time()
        
        try:
            text = content.content
            title = content.title or ""
            
            logger.info(f"🔍 Analyzing content: {content.id} ({len(text)} chars)")
            
            # 1. Threat classification
            classification = self.classifier.classify_content(text, title)
            
            # 2. IOC extraction
            iocs = self.ioc_extractor.extract_iocs(text)
            
            # 3. Entity extraction
            entities = self.entity_extractor.extract_entities(text)
            
            # 4. Language detection (simple heuristic)
            language = self._detect_language(text)
            
            # 5. Calculate processing time
            processing_time = time.time() - start_time
            
            # 6. Create analysis document
            analysis = NLPAnalysis(
                content_id=str(content.id),
                content_type="scraped_content",
                entities=entities,
                keywords=classification.get("keywords_found", []),
                topics=[{
                    "threat_type": classification["primary_threat_type"],
                    "score": classification["threat_score"]
                }],
                sentiment={"threat_level": classification["threat_score"]},
                threat_indicators=[{
                    "type": ioc_type,
                    "indicators": ioc_list,
                    "count": len(ioc_list)
                } for ioc_type, ioc_list in iocs.items()],
                classification={
                    "primary_threat": classification["primary_threat_type"],
                    "severity": classification["severity"],
                    "confidence": classification["confidence"],
                    "threat_scores": classification["threat_scores"]
                },
                language=language,
                model_version="ctms-analyzer-v1.0",
                processing_time=processing_time,
                confidence=classification["confidence"]
            )
            
            # 7. Update content with analysis results
            await self._update_content_analysis(content, analysis, iocs)
            
            logger.info(
                f"✅ Analysis completed for {content.id}: "
                f"{len(iocs)} IOC types, {classification['primary_threat_type']} threat, "
                f"{classification['severity']} severity"
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Analysis failed for content {content.id}: {e}")
            raise
    
    async def _update_content_analysis(
        self, 
        content: ScrapedContent, 
        analysis: NLPAnalysis,
        iocs: Dict[str, List[Dict[str, Any]]]
    ) -> None:
        """
        Update scraped content with analysis results and create IOC records.
        
        Args:
            content: Scraped content
            analysis: Analysis results
            iocs: Extracted IOCs
        """
        try:
            db = await get_database()
            
            # Update content with analysis reference
            await db.scraped_content.update_one(
                {"_id": content.id},
                {
                    "$set": {
                        "analysis_id": str(analysis.id),
                        "threat_score": analysis.classification["primary_threat"],
                        "severity": analysis.classification["severity"],
                        "analyzed_at": datetime.utcnow()
                    }
                }
            )
            
            # Create IOC records
            for ioc_type, ioc_list in iocs.items():
                for ioc in ioc_list:
                    ioc_doc = {
                        "value": ioc["value"],
                        "type": ioc_type,
                        "source_content_id": str(content.id),
                        "source_url": content.url,
                        "confidence": ioc["confidence"],
                        "context": ioc["context"],
                        "first_seen": datetime.utcnow(),
                        "last_seen": datetime.utcnow(),
                        "occurrence_count": 1
                    }
                    
                    # Check if IOC already exists
                    existing_ioc = await db.iocs.find_one({"value": ioc["value"], "type": ioc_type})
                    if existing_ioc:
                        # Update existing IOC
                        await db.iocs.update_one(
                            {"_id": existing_ioc["_id"]},
                            {
                                "$inc": {"occurrence_count": 1},
                                "$set": {"last_seen": datetime.utcnow()}
                            }
                        )
                    else:
                        # Create new IOC
                        await db.iocs.insert_one(ioc_doc)
            
            logger.info(f"💾 Updated content {content.id} with analysis results")
            
        except Exception as e:
            logger.error(f"❌ Failed to update content analysis: {e}")
    
    def _detect_language(self, text: str) -> str:
        """
        Simple language detection heuristic.
        
        Args:
            text: Text to analyze
            
        Returns:
            str: Detected language code
        """
        # Simple English detection
        english_chars = sum(1 for c in text if c.isalpha() and ord(c) < 128)
        total_chars = sum(1 for c in text if c.isalpha())
        
        if total_chars == 0:
            return "unknown"
        
        english_ratio = english_chars / total_chars
        
        if english_ratio > 0.8:
            return "en"
        elif english_ratio > 0.5:
            return "en-mixed"
        else:
            return "unknown"
    
    async def batch_analyze(self, content_list: List[ScrapedContent]) -> List[NLPAnalysis]:
        """
        Analyze multiple content items concurrently.
        
        Args:
            content_list: List of content to analyze
            
        Returns:
            List[NLPAnalysis]: Analysis results
        """
        logger.info(f"🔄 Starting batch analysis of {len(content_list)} items")
        
        # Use semaphore to limit concurrent processing
        semaphore = asyncio.Semaphore(5)
        
        async def analyze_with_semaphore(content: ScrapedContent) -> NLPAnalysis:
            async with semaphore:
                return await self.analyze_content(content)
        
        # Process all content concurrently
        tasks = [analyze_with_semaphore(content) for content in content_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        successful_results = []
        for result in results:
            if isinstance(result, NLPAnalysis):
                successful_results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"❌ Batch analysis item failed: {result}")
        
        logger.info(f"✅ Batch analysis completed: {len(successful_results)} successful")
        return successful_results

    # =============================================================================
    # BACKWARD COMPATIBILITY METHOD
    # =============================================================================
    async def analyze_latest_threats(self) -> Dict[str, Any]:
        """
        Analyze the latest scraped content for threats.
        This method provides backward compatibility for older code.
        
        Returns:
            Dict[str, Any]: Analysis results
        """
        logger.info("🔍 Analyzing latest threats (backward compatibility)")
        
        try:
            db = await get_database()
            
            # Get latest unanalyzed content
            latest_content = await db.scraped_content.find(
                {"analysis_id": {"$exists": False}},
                sort=[("scraped_at", -1)],
                limit=50
            ).to_list(length=50)
            
            if not latest_content:
                logger.info("📭 No new content to analyze")
                return {
                    "status": "no_content",
                    "message": "No new content to analyze",
                    "analyzed_count": 0
                }
            
            # Convert to ScrapedContent objects
            content_objects = [ScrapedContent(**doc) for doc in latest_content]
            
            # Analyze content
            analyses = await self.batch_analyze(content_objects)
            
            logger.info(f"✅ Analyzed {len(analyses)} latest threats")
            
            return {
                "status": "completed",
                "analyzed_count": len(analyses),
                "analyses": [analysis.dict() for analysis in analyses],
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Latest threats analysis failed: {e}")
            raise


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================
async def analyze_single_content(content: ScrapedContent) -> NLPAnalysis:
    """
    Convenience function to analyze a single content item.
    
    Args:
        content: Content to analyze
        
    Returns:
        NLPAnalysis: Analysis results
    """
    analyzer = ThreatAnalyzer()
    return await analyzer.analyze_content(content)


async def extract_iocs_from_text(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convenience function to extract IOCs from text.
    
    Args:
        text: Text to analyze
        
    Returns:
        Dict[str, List[Dict[str, Any]]]: Extracted IOCs
    """
    extractor = IOCExtractor()
    return extractor.extract_iocs(text)
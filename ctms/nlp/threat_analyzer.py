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
        'cryptocurrency', 'bitcoin', 'monero', 'ethereum', 'mining', 'cryptojacking',
        'wallet', 'blockchain', 'ransom payment', 'crypto theft'
    }


# =============================================================================
# THREAT CLASSIFICATION ENGINE
# =============================================================================
class ThreatClassifier:
    """
    Machine learning-based threat classification engine.
    Analyzes content and assigns threat types and severity levels.
    """
    
    def __init__(self):
        """Initialize threat classifier."""
        self.threat_keywords = ThreatKeywords()
        self.severity_weights = {
            'critical': ['zero-day', 'exploit', 'ransomware', 'apt', 'breach'],
            'high': ['malware', 'trojan', 'vulnerability', 'phishing', 'botnet'],
            'medium': ['suspicious', 'anomaly', 'indicator', 'threat'],
            'low': ['information', 'advisory', 'notice', 'recommendation']
        }
    
    def classify_content(self, content: str, title: str = "") -> Dict[str, Any]:
        """
        Classify content for threat types and severity.
        
        Args:
            content: Text content to analyze
            title: Optional title for additional context
            
        Returns:
            Dict[str, Any]: Classification results
        """
        text = f"{title} {content}".lower()
        
        # Calculate threat type scores
        threat_scores = {}
        
        # Malware detection
        malware_score = self._calculate_keyword_score(text, self.threat_keywords.MALWARE_KEYWORDS)
        if malware_score > 0:
            threat_scores[ThreatType.MALWARE] = malware_score
        
        # Phishing detection
        phishing_score = self._calculate_keyword_score(text, self.threat_keywords.PHISHING_KEYWORDS)
        if phishing_score > 0:
            threat_scores[ThreatType.PHISHING] = phishing_score
        
        # Exploit detection
        exploit_score = self._calculate_keyword_score(text, self.threat_keywords.EXPLOIT_KEYWORDS)
        if exploit_score > 0:
            threat_scores[ThreatType.EXPLOIT] = exploit_score
        
        # APT detection
        apt_score = self._calculate_keyword_score(text, self.threat_keywords.APT_KEYWORDS)
        if apt_score > 0:
            threat_scores[ThreatType.APT] = apt_score
        
        # Botnet detection
        network_score = self._calculate_keyword_score(text, self.threat_keywords.NETWORK_KEYWORDS)
        if network_score > 0:
            threat_scores[ThreatType.BOTNET] = network_score
        
        # Determine primary threat type
        primary_threat = ThreatType.UNKNOWN
        if threat_scores:
            primary_threat = max(threat_scores.keys(), key=lambda k: threat_scores[k])
        
        # Calculate severity
        severity = self._calculate_severity(text, threat_scores)
        
        # Calculate overall threat score (0-10)
        threat_score = min(10.0, sum(threat_scores.values()) * 2)
        
        # Calculate confidence
        confidence = self._calculate_confidence(threat_scores, text)
        
        return {
            "primary_threat_type": primary_threat,
            "threat_scores": threat_scores,
            "severity": severity,
            "threat_score": threat_score,
            "confidence": confidence,
            "keywords_found": self._extract_found_keywords(text)
        }
    
    def _calculate_keyword_score(self, text: str, keywords: Set[str]) -> float:
        """Calculate score based on keyword presence and frequency."""
        score = 0.0
        found_keywords = []
        
        for keyword in keywords:
            if keyword in text:
                # Count occurrences
                count = text.count(keyword)
                # Weight by keyword length (longer keywords are more specific)
                weight = len(keyword.split()) * 0.5 + 1
                score += count * weight
                found_keywords.append(keyword)
        
        # Normalize score
        if found_keywords:
            score = min(score / len(keywords), 1.0)
        
        return score
    
    def _calculate_severity(self, text: str, threat_scores: Dict[str, float]) -> SeverityLevel:
        """Calculate severity level based on content analysis."""
        severity_score = 0.0
        
        # Check severity indicators
        for severity, keywords in self.severity_weights.items():
            for keyword in keywords:
                if keyword in text:
                    if severity == 'critical':
                        severity_score += 4
                    elif severity == 'high':
                        severity_score += 3
                    elif severity == 'medium':
                        severity_score += 2
                    else:
                        severity_score += 1
        
        # Factor in threat scores
        if threat_scores:
            max_threat_score = max(threat_scores.values())
            severity_score += max_threat_score * 5
        
        # Map to severity levels
        if severity_score >= 7:
            return SeverityLevel.CRITICAL
        elif severity_score >= 5:
            return SeverityLevel.HIGH
        elif severity_score >= 3:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _calculate_confidence(self, threat_scores: Dict[str, float], text: str) -> float:
        """Calculate confidence in the classification."""
        if not threat_scores:
            return 0.1
        
        # Base confidence on number of different threat indicators
        indicator_diversity = len(threat_scores)
        max_score = max(threat_scores.values())
        
        # Higher confidence for multiple indicators and higher scores
        confidence = min(0.9, (indicator_diversity * 0.2) + (max_score * 0.6) + 0.1)
        
        return confidence
    
    def _extract_found_keywords(self, text: str) -> List[str]:
        """Extract all threat-related keywords found in text."""
        found_keywords = []
        
        all_keywords = (
            self.threat_keywords.MALWARE_KEYWORDS |
            self.threat_keywords.PHISHING_KEYWORDS |
            self.threat_keywords.EXPLOIT_KEYWORDS |
            self.threat_keywords.APT_KEYWORDS |
            self.threat_keywords.NETWORK_KEYWORDS |
            self.threat_keywords.CRYPTO_KEYWORDS
        )
        
        for keyword in all_keywords:
            if keyword in text:
                found_keywords.append(keyword)
        
        return found_keywords


# =============================================================================
# IOC EXTRACTOR ENGINE
# =============================================================================
class IOCExtractor:
    """
    Extracts indicators of compromise from text content using
    pattern matching and validation techniques.
    """
    
    def __init__(self):
        """Initialize IOC extractor."""
        self.patterns = IOCPatterns()
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = {
            IndicatorType.IP_ADDRESS: [
                re.compile(self.patterns.IPV4_PATTERN),
                re.compile(self.patterns.IPV6_PATTERN)
            ],
            IndicatorType.DOMAIN: [re.compile(self.patterns.DOMAIN_PATTERN)],
            IndicatorType.URL: [re.compile(self.patterns.URL_PATTERN)],
            IndicatorType.FILE_HASH: [
                re.compile(self.patterns.MD5_PATTERN),
                re.compile(self.patterns.SHA1_PATTERN),
                re.compile(self.patterns.SHA256_PATTERN),
                re.compile(self.patterns.SHA512_PATTERN)
            ],
            IndicatorType.EMAIL: [re.compile(self.patterns.EMAIL_PATTERN)],
            IndicatorType.FILE_PATH: [
                re.compile(self.patterns.WINDOWS_PATH_PATTERN),
                re.compile(self.patterns.UNIX_PATH_PATTERN)
            ],
            IndicatorType.REGISTRY_KEY: [re.compile(self.patterns.REGISTRY_PATTERN)]
        }
        
        # Common false positive patterns to exclude
        self.false_positive_patterns = {
            IndicatorType.IP_ADDRESS: [
                r'^0\.0\.0\.0$', r'^127\.0\.0\.1$', r'^255\.255\.255\.255$',
                r'^192\.168\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
            ],
            IndicatorType.DOMAIN: [
                r'^localhost$', r'^example\.(com|org|net)$', r'^test\.',
                r'\.local$', r'\.internal$'
            ]
        }
    
    def extract_iocs(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract all IOCs from content.
        
        Args:
            content: Text content to analyze
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Extracted IOCs by type
        """
        extracted_iocs = defaultdict(list)
        
        for ioc_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.finditer(content)
                
                for match in matches:
                    ioc_value = match.group().strip()
                    
                    # Validate and filter false positives
                    if self._is_valid_ioc(ioc_value, ioc_type):
                        ioc_info = {
                            "value": ioc_value,
                            "type": ioc_type,
                            "position": match.span(),
                            "context": self._extract_context(content, match.span()),
                            "confidence": self._calculate_ioc_confidence(ioc_value, ioc_type)
                        }
                        extracted_iocs[ioc_type].append(ioc_info)
        
        # Remove duplicates
        for ioc_type in extracted_iocs:
            extracted_iocs[ioc_type] = self._deduplicate_iocs(extracted_iocs[ioc_type])
        
        return dict(extracted_iocs)
    
    def _is_valid_ioc(self, value: str, ioc_type: IndicatorType) -> bool:
        """
        Validate IOC and filter false positives.
        
        Args:
            value: IOC value to validate
            ioc_type: Type of IOC
            
        Returns:
            bool: True if valid IOC
        """
        # Check against false positive patterns
        if ioc_type in self.false_positive_patterns:
            for fp_pattern in self.false_positive_patterns[ioc_type]:
                if re.match(fp_pattern, value):
                    return False
        
        # Additional validation by type
        if ioc_type == IndicatorType.IP_ADDRESS:
            return self._validate_ip_address(value)
        elif ioc_type == IndicatorType.DOMAIN:
            return self._validate_domain(value)
        elif ioc_type == IndicatorType.FILE_HASH:
            return self._validate_hash(value)
        elif ioc_type == IndicatorType.EMAIL:
            return self._validate_email(value)
        
        return True
    
    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format and ranges."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            # Exclude broadcast and reserved ranges
            if ip.startswith('0.') or ip.startswith('255.'):
                return False
            
            return True
        except ValueError:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        if len(domain) > 253 or len(domain) < 4:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        
        # Must have at least one dot
        if '.' not in domain:
            return False
        
        # Check TLD
        tld = domain.split('.')[-1]
        if len(tld) < 2 or not tld.isalpha():
            return False
        
        return True
    
    def _validate_hash(self, hash_value: str) -> bool:
        """Validate hash format."""
        # Check if it's a valid hex string
        try:
            int(hash_value, 16)
            return True
        except ValueError:
            return False
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format."""
        if '@' not in email or email.count('@') != 1:
            return False
        
        local, domain = email.split('@')
        if not local or not domain:
            return False
        
        return self._validate_domain(domain)
    
    def _extract_context(self, content: str, position: Tuple[int, int], context_size: int = 50) -> str:
        """Extract context around IOC position."""
        start, end = position
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        
        return content[context_start:context_end].strip()
    
    def _calculate_ioc_confidence(self, value: str, ioc_type: IndicatorType) -> float:
        """Calculate confidence score for extracted IOC."""
        confidence = 0.7  # Base confidence
        
        # Adjust based on IOC type
        if ioc_type == IndicatorType.FILE_HASH:
            confidence = 0.95  # Hashes are very reliable
        elif ioc_type == IndicatorType.IP_ADDRESS:
            confidence = 0.8
        elif ioc_type == IndicatorType.DOMAIN:
            # Lower confidence for common domains
            if any(common in value for common in ['google', 'microsoft', 'apple']):
                confidence = 0.4
        
        return confidence
    
    def _deduplicate_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate IOCs."""
        seen = set()
        unique_iocs = []
        
        for ioc in iocs:
            if ioc["value"] not in seen:
                seen.add(ioc["value"])
                unique_iocs.append(ioc)
        
        return unique_iocs


# =============================================================================
# ENTITY EXTRACTION ENGINE
# =============================================================================
class EntityExtractor:
    """
    Extracts named entities and security-relevant information
    using spaCy NLP models.
    """
    
    def __init__(self):
        """Initialize entity extractor."""
        try:
            # Load spaCy model (use English model)
            self.nlp = spacy.load("en_core_web_sm")
            logger.info("✅ spaCy model loaded successfully")
        except IOError:
            logger.warning("⚠️ spaCy model not found, using blank model")
            self.nlp = spacy.blank("en")
        
        # Custom entity patterns for security context
        self.security_patterns = {
            "CVE": r'CVE-\d{4}-\d{4,}',
            "PORT": r'\b(?:port\s+)?(\d{1,5})\b',
            "PROTOCOL": r'\b(tcp|udp|http|https|ftp|ssh|telnet|smtp|dns)\b',
            "OS": r'\b(windows|linux|macos|ubuntu|centos|debian|android|ios)\b'
        }
    
    def extract_entities(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract named entities and security-relevant information.
        
        Args:
            content: Text content to analyze
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Extracted entities by type
        """
        entities = defaultdict(list)
        
        try:
            # Process with spaCy
            doc = self.nlp(content)
            
            # Extract standard named entities
            for ent in doc.ents:
                entity_info = {
                    "text": ent.text,
                    "label": ent.label_,
                    "description": spacy.explain(ent.label_),
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "confidence": 0.8  # Default confidence for spaCy entities
                }
                entities[ent.label_].append(entity_info)
            
            # Extract custom security entities
            security_entities = self._extract_security_entities(content)
            for entity_type, entity_list in security_entities.items():
                entities[entity_type].extend(entity_list)
            
            # Extract keywords and noun phrases
            keywords = self._extract_keywords(doc)
            if keywords:
                entities["KEYWORDS"] = keywords
                
        except Exception as e:
            logger.error(f"❌ Entity extraction failed: {e}")
        
        return dict(entities)
    
    def _extract_security_entities(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """Extract security-specific entities."""
        entities = defaultdict(list)
        
        for entity_type, pattern in self.security_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                entity_info = {
                    "text": match.group(),
                    "label": entity_type,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.9
                }
                entities[entity_type].append(entity_info)
        
        return dict(entities)
    
    def _extract_keywords(self, doc) -> List[Dict[str, Any]]:
        """Extract important keywords and noun phrases."""
        keywords = []
        
        # Extract noun phrases
        for chunk in doc.noun_chunks:
            if len(chunk.text) > 3 and chunk.text.lower() not in ['the', 'this', 'that']:
                keywords.append({
                    "text": chunk.text,
                    "label": "NOUN_PHRASE",
                    "start": chunk.start_char,
                    "end": chunk.end_char,
                    "confidence": 0.6
                })
        
        # Extract significant single tokens
        for token in doc:
            if (token.pos_ in ['NOUN', 'PROPN'] and 
                len(token.text) > 4 and 
                not token.is_stop and 
                not token.is_punct):
                keywords.append({
                    "text": token.text,
                    "label": "KEYWORD",
                    "start": token.idx,
                    "end": token.idx + len(token.text),
                    "confidence": 0.5
                })
        
        return keywords[:20]  # Limit to top 20 keywords


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
            content: Original scraped content
            analysis: NLP analysis results
            iocs: Extracted IOCs
        """
        try:
            db = await get_database()
            
            # Update scraped content
            await db.scraped_content.update_one(
                {"_id": content.id},
                {
                    "$set": {
                        "processed": True,
                        "threat_score": analysis.classification.get("threat_scores", {}).get(
                            analysis.classification["primary_threat"], 0
                        ),
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            # Create IOC records
            ioc_ids = []
            for ioc_type, ioc_list in iocs.items():
                for ioc_info in ioc_list:
                    ioc_doc = IndicatorOfCompromise(
                        type=ioc_info["type"],
                        value=ioc_info["value"],
                        confidence=ioc_info["confidence"],
                        severity=analysis.classification["severity"],
                        source=content.source_url,
                        source_type="dark_web" if "onion" in content.source_url else "surface_web",
                        threat_types=[analysis.classification["primary_threat"]]
                    )
                    
                    # Check if IOC already exists
                    existing = await db.iocs.find_one({
                        "value": ioc_doc.value,
                        "type": ioc_doc.type
                    })
                    
                    if not existing:
                        result = await db.iocs.insert_one(ioc_doc.dict())
                        ioc_ids.append(str(result.inserted_id))
                    else:
                        ioc_ids.append(str(existing["_id"]))
            
            # Update content with IOC references
            if ioc_ids:
                await db.scraped_content.update_one(
                    {"_id": content.id},
                    {"$set": {"extracted_iocs": ioc_ids}}
                )
            
        except Exception as e:
            logger.error(f"❌ Failed to update content analysis: {e}")
    
    def _detect_language(self, text: str) -> str:
        """
        Simple language detection based on character patterns.
        
        Args:
            text: Text to analyze
            
        Returns:
            str: Detected language code
        """
        # Simple heuristic - count common English words
        english_words = {'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        words = set(text.lower().split())
        english_count = len(words.intersection(english_words))
        
        if english_count > 5:
            return "en"
        else:
            return "unknown"
    
    async def batch_analyze(self, content_list: List[ScrapedContent]) -> List[NLPAnalysis]:
        """
        Analyze multiple content items in batch.
        
        Args:
            content_list: List of scraped content to analyze
            
        Returns:
            List[NLPAnalysis]: Analysis results
        """
        logger.info(f"🔄 Starting batch analysis of {len(content_list)} items")
        
        # Process with controlled concurrency
        semaphore = asyncio.Semaphore(5)  # Limit concurrent analysis
        
        async def analyze_with_semaphore(content: ScrapedContent) -> NLPAnalysis:
            async with semaphore:
                return await self.analyze_content(content)
        
        tasks = [analyze_with_semaphore(content) for content in content_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        successful_results = []
        for result in results:
            if isinstance(result, NLPAnalysis):
                successful_results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"❌ Batch analysis task failed: {result}")
        
        logger.info(f"✅ Batch analysis completed: {len(successful_results)}/{len(content_list)} successful")
        
        return successful_results


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================
async def analyze_single_content(content: ScrapedContent) -> NLPAnalysis:
    """
    Convenience function to analyze a single piece of content.
    
    Args:
        content: Scraped content to analyze
        
    Returns:
        NLPAnalysis: Analysis results
    """
    analyzer = ThreatAnalyzer()
    return await analyzer.analyze_content(content)


async def extract_iocs_from_text(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convenience function to extract IOCs from raw text.
    
    Args:
        text: Text to analyze
        
    Returns:
        Dict: Extracted IOCs by type
    """
    extractor = IOCExtractor()
    return extractor.extract_iocs(text)
"""
ECS-specific parser that applies ECS field mappings with presets.
This is the main parser for ECS schema compliance.
"""

import yaml
from typing import Dict, Any, Optional
from datetime import datetime
try:
    from ..schemas.ecs import ECSMapper, get_ecs_template
    from .json_parser import JSONParser
    from .regex_parser import RegexParser
except ImportError:
    from schemas.ecs import ECSMapper, get_ecs_template
    from parsers.json_parser import JSONParser
    from parsers.regex_parser import RegexParser

class ECSParser:
    """
    Main ECS parser that combines JSON, regex, and custom mapping capabilities.
    Provides ECS presets and custom YAML mapping support.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize ECS parser with configuration.
        
        Args:
            config: Parser configuration dictionary
        """
        self.config = config or {}
        self.ecs_mapper = ECSMapper()
        
        # Initialize sub-parsers
        self.json_parser = JSONParser(self.ecs_mapper)
        self.regex_parser = None  # Will be initialized based on config
        
        # Load custom mappings if provided
        self._load_custom_mappings()
        
        # Set up regex parser if pattern is specified
        self._setup_regex_parser()
    
    def parse(self, log_line: str, parser_type: str = "auto", dataset: str = "generic") -> Dict[str, Any]:
        """
        Parse log line using specified parser type or auto-detection.
        
        Args:
            log_line: Raw log line
            parser_type: Parser type ("json", "regex", "auto")
            dataset: Dataset name for event classification
            
        Returns:
            Parsed event in ECS format
        """
        log_line = log_line.strip()
        
        if parser_type == "auto":
            parser_type = self._detect_parser_type(log_line)
        
        try:
            if parser_type == "json":
                return self.json_parser.parse(log_line, dataset)
            elif parser_type == "regex" and self.regex_parser:
                return self.regex_parser.parse(log_line, dataset)
            else:
                # Fallback to basic ECS mapping
                return self._parse_basic(log_line, dataset)
        
        except Exception as e:
            return self._handle_parse_error(log_line, dataset, str(e))
    
    def _detect_parser_type(self, log_line: str) -> str:
        """
        Auto-detect the appropriate parser type for the log line.
        
        Args:
            log_line: Raw log line
            
        Returns:
            Detected parser type
        """
        # Try JSON first
        if log_line.startswith('{') and log_line.endswith('}'):
            return "json"
        
        # If regex parser is configured, use it
        if self.regex_parser:
            return "regex"
        
        # Default to basic parsing
        return "basic"
    
    def _parse_basic(self, log_line: str, dataset: str) -> Dict[str, Any]:
        """
        Basic parsing for unstructured logs.
        
        Args:
            log_line: Raw log line
            dataset: Dataset name
            
        Returns:
            Basic ECS event
        """
        # Get ECS template based on dataset
        template = get_ecs_template(dataset)
        
        # Fill in basic fields
        ecs_event = {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': log_line,
            'event.dataset': dataset,
            'event.kind': 'event',
            'event.category': template.get('event.category', ['process']),
            'event.type': template.get('event.type', ['info']),
            'event.ingested': datetime.utcnow().isoformat() + 'Z',
            'log.source.type': 'basic'
        }
        
        # Try to extract basic information
        ecs_event.update(self._extract_basic_fields(log_line))
        
        return ecs_event
    
    def _extract_basic_fields(self, log_line: str) -> Dict[str, Any]:
        """
        Extract basic fields from unstructured log line.
        
        Args:
            log_line: Raw log line
            
        Returns:
            Dictionary of extracted fields
        """
        fields = {}
        
        # Simple heuristics for common patterns
        import re
        
        # Extract IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, log_line)
        if ips:
            fields['source.ip'] = ips[0]  # Take first IP as source
            if len(ips) > 1:
                fields['destination.ip'] = ips[1]
        
        # Extract common log levels
        level_pattern = r'\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b'
        level_match = re.search(level_pattern, log_line, re.IGNORECASE)
        if level_match:
            fields['log.level'] = level_match.group(1).upper()
        
        # Extract potential timestamps (basic detection)
        timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
        timestamp_match = re.search(timestamp_pattern, log_line)
        if timestamp_match:
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(timestamp_match.group(0).replace(' ', 'T'))
                fields['@timestamp'] = ts.isoformat() + 'Z'
            except ValueError:
                pass
        
        return fields
    
    def _load_custom_mappings(self):
        """Load custom field mappings from configuration."""
        if 'custom_mappings' in self.config:
            mappings = self.config['custom_mappings']
            if isinstance(mappings, str):
                # Load from YAML file
                try:
                    with open(mappings, 'r') as f:
                        mappings = yaml.safe_load(f)
                except Exception as e:
                    print(f"[WARN] Failed to load custom mappings from {mappings}: {e}")
                    return
            
            if isinstance(mappings, dict):
                self.ecs_mapper.load_custom_mappings(mappings)
    
    def _setup_regex_parser(self):
        """Set up regex parser based on configuration."""
        if 'regex_pattern' in self.config:
            self.regex_parser = RegexParser(
                pattern=self.config['regex_pattern'],
                ecs_mapper=self.ecs_mapper
            )
        elif 'regex_preset' in self.config:
            self.regex_parser = RegexParser(
                pattern_name=self.config['regex_preset'],
                ecs_mapper=self.ecs_mapper
            )
    
    def _handle_parse_error(self, log_line: str, dataset: str, error: str) -> Dict[str, Any]:
        """
        Handle parsing errors.
        
        Args:
            log_line: Original log line
            dataset: Dataset name
            error: Error message
            
        Returns:
            ECS event with error information
        """
        return {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': log_line,
            'event.dataset': dataset,
            'event.kind': 'event',
            'event.category': ['process'],
            'event.type': ['error'],
            'event.outcome': 'failure',
            'error.message': f"ECS parse error: {error}",
            'log.source.type': 'ecs',
            'event.ingested': datetime.utcnow().isoformat() + 'Z'
        }
    
    def get_supported_presets(self) -> Dict[str, str]:
        """
        Get supported ECS presets and their descriptions.
        
        Returns:
            Dictionary of preset names and descriptions
        """
        return {
            'syslog': 'System log events with host and process information',
            'firewall': 'Network firewall events with source/destination IPs',
            'web': 'Web server access logs with HTTP details',
            'generic': 'Generic events with basic ECS fields'
        }
    
    def validate_ecs_compliance(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate ECS compliance of an event.
        
        Args:
            event: Event to validate
            
        Returns:
            Validation results with compliance status and issues
        """
        issues = []
        
        # Required fields check
        required_fields = ['@timestamp', 'event.dataset', 'event.kind']
        for field in required_fields:
            if field not in event:
                issues.append(f"Missing required field: {field}")
        
        # Field type validation (basic)
        if '@timestamp' in event:
            try:
                datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                issues.append("Invalid @timestamp format")
        
        # Category validation
        if 'event.category' in event:
            valid_categories = ['authentication', 'configuration', 'database', 'driver', 
                             'email', 'file', 'host', 'iam', 'intrusion_detection', 
                             'malware', 'network', 'package', 'process', 'registry', 
                             'session', 'threat', 'vulnerability', 'web']
            if isinstance(event['event.category'], list):
                for cat in event['event.category']:
                    if cat not in valid_categories:
                        issues.append(f"Invalid event.category: {cat}")
        
        return {
            'compliant': len(issues) == 0,
            'issues': issues,
            'score': max(0, 100 - len(issues) * 10)  # Simple scoring
        }

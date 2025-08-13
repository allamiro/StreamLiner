"""
Regex-based log parser for StreamLiner.
Handles pattern-based log parsing with named capture groups.
"""

import re
from typing import Dict, Any, Optional, List
from datetime import datetime
try:
    from ..schemas.ecs import ECSMapper
except ImportError:
    from schemas.ecs import ECSMapper

class RegexParser:
    """Parser for regex pattern-based log parsing."""
    
    # Common regex patterns for different log types
    COMMON_PATTERNS = {
        'syslog': r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)',
        'apache_common': r'(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)',
        'apache_combined': r'(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"',
        'nginx_access': r'(?P<src_ip>\S+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"',
        'firewall': r'(?P<timestamp>\S+\s+\S+)\s+(?P<hostname>\S+)\s+.*src=(?P<src_ip>\S+)\s+dst=(?P<dest_ip>\S+)\s+sport=(?P<src_port>\d+)\s+dport=(?P<dest_port>\d+)\s+proto=(?P<protocol>\S+)',
        'generic_kv': r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<level>\w+)\s+(?P<message>.*)'
    }
    
    def __init__(self, pattern: str = None, pattern_name: str = None, ecs_mapper: Optional[ECSMapper] = None):
        """
        Initialize regex parser.
        
        Args:
            pattern: Custom regex pattern with named groups
            pattern_name: Name of predefined pattern to use
            ecs_mapper: ECS mapper instance for field mapping
        """
        self.ecs_mapper = ecs_mapper or ECSMapper()
        
        if pattern:
            self.pattern = re.compile(pattern)
            self.pattern_name = "custom"
        elif pattern_name and pattern_name in self.COMMON_PATTERNS:
            self.pattern = re.compile(self.COMMON_PATTERNS[pattern_name])
            self.pattern_name = pattern_name
        else:
            # Default to generic key-value pattern
            self.pattern = re.compile(self.COMMON_PATTERNS['generic_kv'])
            self.pattern_name = "generic_kv"
    
    def parse(self, log_line: str, dataset: str = None) -> Dict[str, Any]:
        """
        Parse log line using regex pattern and convert to ECS format.
        
        Args:
            log_line: Raw log line
            dataset: Dataset name for event classification
            
        Returns:
            Parsed event in ECS format
        """
        if not dataset:
            dataset = self.pattern_name
        
        try:
            match = self.pattern.match(log_line.strip())
            
            if match:
                raw_data = match.groupdict()
                
                # Clean up captured groups
                raw_data = {k: v for k, v in raw_data.items() if v is not None}
                
                # Process timestamp if present
                if 'timestamp' in raw_data:
                    processed_timestamp = self._process_timestamp(raw_data['timestamp'])
                    if processed_timestamp:
                        raw_data['timestamp'] = processed_timestamp
                
                # Map to ECS format
                ecs_event = self.ecs_mapper.map_to_ecs(raw_data, dataset)
                
                # Add parser-specific fields
                ecs_event['event.ingested'] = datetime.utcnow().isoformat() + 'Z'
                ecs_event['log.source.type'] = 'regex'
                ecs_event['log.source.pattern'] = self.pattern_name
                
                # Handle specific log types
                ecs_event = self._enhance_by_type(ecs_event, raw_data)
                
                return ecs_event
            else:
                # Pattern didn't match, create basic event
                return self._handle_no_match(log_line, dataset)
                
        except Exception as e:
            return self._handle_parse_error(log_line, dataset, str(e))
    
    def _process_timestamp(self, timestamp_str: str) -> Optional[str]:
        """
        Process timestamp string into ISO format.
        
        Args:
            timestamp_str: Raw timestamp string
            
        Returns:
            ISO formatted timestamp or None
        """
        # Common timestamp formats
        formats = [
            '%b %d %H:%M:%S',  # Syslog format
            '%d/%b/%Y:%H:%M:%S %z',  # Apache format
            '%Y-%m-%d %H:%M:%S',  # Generic format
            '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO format
            '%Y-%m-%dT%H:%M:%SZ',  # ISO format without microseconds
        ]
        
        for fmt in formats:
            try:
                if fmt == '%b %d %H:%M:%S':
                    # Add current year for syslog format
                    timestamp_str = f"{datetime.now().year} {timestamp_str}"
                    fmt = '%Y %b %d %H:%M:%S'
                
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.isoformat() + 'Z'
            except ValueError:
                continue
        
        return None
    
    def _enhance_by_type(self, ecs_event: Dict[str, Any], raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance ECS event based on log type.
        
        Args:
            ecs_event: Base ECS event
            raw_data: Raw parsed data
            
        Returns:
            Enhanced ECS event
        """
        if self.pattern_name == 'syslog':
            ecs_event['event.category'] = ['system']
            ecs_event['event.type'] = ['info']
            if 'pid' in raw_data:
                ecs_event['process.pid'] = int(raw_data['pid'])
        
        elif self.pattern_name in ['apache_common', 'apache_combined', 'nginx_access']:
            ecs_event['event.category'] = ['web']
            ecs_event['event.type'] = ['access']
            
            if 'status' in raw_data:
                status_code = int(raw_data['status'])
                ecs_event['http.response.status_code'] = status_code
                
                # Determine outcome based on status code
                if 200 <= status_code < 400:
                    ecs_event['event.outcome'] = 'success'
                elif 400 <= status_code < 500:
                    ecs_event['event.outcome'] = 'failure'
                else:
                    ecs_event['event.outcome'] = 'unknown'
            
            if 'method' in raw_data:
                ecs_event['http.request.method'] = raw_data['method']
            if 'path' in raw_data:
                ecs_event['url.path'] = raw_data['path']
            if 'user_agent' in raw_data:
                ecs_event['user_agent.original'] = raw_data['user_agent']
        
        elif self.pattern_name == 'firewall':
            ecs_event['event.category'] = ['network']
            ecs_event['event.type'] = ['connection']
            
            if 'protocol' in raw_data:
                ecs_event['network.transport'] = raw_data['protocol'].lower()
        
        return ecs_event
    
    def _handle_no_match(self, log_line: str, dataset: str) -> Dict[str, Any]:
        """
        Handle case where regex pattern doesn't match.
        
        Args:
            log_line: Original log line
            dataset: Dataset name
            
        Returns:
            Basic ECS event
        """
        return {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': log_line.strip(),
            'event.dataset': dataset,
            'event.kind': 'event',
            'event.category': ['process'],
            'event.type': ['info'],
            'event.outcome': 'unknown',
            'log.source.type': 'regex',
            'log.source.pattern': self.pattern_name,
            'event.ingested': datetime.utcnow().isoformat() + 'Z',
            'labels.parse_status': 'no_match'
        }
    
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
            'message': log_line.strip(),
            'event.dataset': dataset,
            'event.kind': 'event',
            'event.category': ['process'],
            'event.type': ['error'],
            'event.outcome': 'failure',
            'error.message': f"Regex parse error: {error}",
            'log.source.type': 'regex',
            'log.source.pattern': self.pattern_name,
            'event.ingested': datetime.utcnow().isoformat() + 'Z'
        }
    
    @classmethod
    def get_available_patterns(cls) -> List[str]:
        """Get list of available predefined patterns."""
        return list(cls.COMMON_PATTERNS.keys())

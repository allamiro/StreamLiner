"""
JSON log parser for StreamLiner.
Handles structured JSON logs and maps them to ECS format.
"""

import json
import re
from typing import Dict, Any, Optional
from datetime import datetime
try:
    from ..schemas.ecs import ECSMapper
except ImportError:
    from schemas.ecs import ECSMapper

class JSONParser:
    """Parser for JSON-formatted log entries."""
    
    def __init__(self, ecs_mapper: Optional[ECSMapper] = None):
        """
        Initialize JSON parser.
        
        Args:
            ecs_mapper: ECS mapper instance for field mapping
        """
        self.ecs_mapper = ecs_mapper or ECSMapper()
        self.timestamp_fields = ['timestamp', '@timestamp', 'time', 'datetime', 'ts']
        self.message_fields = ['message', 'msg', 'log', 'text']
    
    def parse(self, log_line: str, dataset: str = "json") -> Dict[str, Any]:
        """
        Parse JSON log line and convert to ECS format.
        
        Args:
            log_line: Raw JSON log line
            dataset: Dataset name for event classification
            
        Returns:
            Parsed event in ECS format
        """
        try:
            # Parse JSON
            raw_data = json.loads(log_line.strip())
            
            # Handle nested JSON strings
            raw_data = self._flatten_nested_json(raw_data)
            
            # Extract timestamp if present
            timestamp = self._extract_timestamp(raw_data)
            if timestamp:
                raw_data['timestamp'] = timestamp
            
            # Map to ECS format
            ecs_event = self.ecs_mapper.map_to_ecs(raw_data, dataset)
            
            # Add parser metadata
            ecs_event['event.ingested'] = datetime.utcnow().isoformat() + 'Z'
            ecs_event['log.source.type'] = 'json'
            
            return ecs_event
            
        except json.JSONDecodeError as e:
            # If JSON parsing fails, treat as raw message
            return self._handle_parse_error(log_line, dataset, str(e))
    
    def _flatten_nested_json(self, data: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Flatten nested JSON objects with dot notation.
        
        Args:
            data: JSON data to flatten
            prefix: Prefix for nested keys
            
        Returns:
            Flattened dictionary
        """
        flattened = {}
        
        for key, value in data.items():
            new_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                flattened.update(self._flatten_nested_json(value, new_key))
            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                # Handle arrays of objects by taking the first element
                flattened.update(self._flatten_nested_json(value[0], new_key))
            else:
                flattened[new_key] = value
        
        return flattened
    
    def _extract_timestamp(self, data: Dict[str, Any]) -> Optional[str]:
        """
        Extract timestamp from various possible fields.
        
        Args:
            data: Parsed JSON data
            
        Returns:
            ISO formatted timestamp string or None
        """
        for field in self.timestamp_fields:
            if field in data:
                timestamp_value = data[field]
                try:
                    # Handle various timestamp formats
                    if isinstance(timestamp_value, (int, float)):
                        # Unix timestamp (seconds or milliseconds)
                        if timestamp_value > 1e10:  # Milliseconds
                            dt = datetime.fromtimestamp(timestamp_value / 1000)
                        else:  # Seconds
                            dt = datetime.fromtimestamp(timestamp_value)
                        return dt.isoformat() + 'Z'
                    elif isinstance(timestamp_value, str):
                        # Try to parse ISO format or common formats
                        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%SZ']:
                            try:
                                dt = datetime.strptime(timestamp_value, fmt)
                                return dt.isoformat() + 'Z'
                            except ValueError:
                                continue
                except (ValueError, OSError):
                    continue
        
        return None
    
    def _handle_parse_error(self, log_line: str, dataset: str, error: str) -> Dict[str, Any]:
        """
        Handle JSON parsing errors by creating a basic ECS event.
        
        Args:
            log_line: Original log line
            dataset: Dataset name
            error: Error message
            
        Returns:
            Basic ECS event with error information
        """
        return {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': log_line.strip(),
            'event.dataset': dataset,
            'event.kind': 'event',
            'event.category': ['process'],
            'event.type': ['error'],
            'event.outcome': 'failure',
            'error.message': f"JSON parse error: {error}",
            'log.source.type': 'json',
            'event.ingested': datetime.utcnow().isoformat() + 'Z'
        }

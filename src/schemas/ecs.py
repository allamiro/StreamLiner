"""
Elastic Common Schema (ECS) field definitions and mapping utilities.
Based on ECS specification: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
"""

from datetime import datetime
from typing import Dict, Any, Optional
import json

class ECSMapper:
    """Maps raw log data to ECS-compliant format."""
    
    # Core ECS fields that should be present in most events
    BASE_FIELDS = {
        '@timestamp': 'timestamp',
        'message': 'message',
        'event.dataset': 'dataset',
        'event.module': 'module',
        'event.kind': 'kind',
        'event.category': 'category',
        'event.type': 'type',
        'event.outcome': 'outcome'
    }
    
    # Host-related fields
    HOST_FIELDS = {
        'host.name': 'hostname',
        'host.ip': 'host_ip',
        'host.os.name': 'os_name',
        'host.os.kernel': 'os_kernel',
        'host.hostname': 'hostname'
    }
    
    # Network-related fields
    NETWORK_FIELDS = {
        'source.ip': 'src_ip',
        'source.port': 'src_port',
        'destination.ip': 'dest_ip',
        'destination.port': 'dest_port',
        'network.protocol': 'protocol',
        'network.transport': 'transport'
    }
    
    # User and process fields
    USER_FIELDS = {
        'user.name': 'username',
        'user.id': 'user_id',
        'process.name': 'process_name',
        'process.pid': 'process_id'
    }
    
    def __init__(self):
        """Initialize ECS mapper with default field mappings."""
        self.field_mappings = {}
        self.field_mappings.update(self.BASE_FIELDS)
        self.field_mappings.update(self.HOST_FIELDS)
        self.field_mappings.update(self.NETWORK_FIELDS)
        self.field_mappings.update(self.USER_FIELDS)
    
    def map_to_ecs(self, raw_data: Dict[str, Any], dataset: str = "generic") -> Dict[str, Any]:
        """
        Map raw log data to ECS format.
        
        Args:
            raw_data: Raw log data dictionary
            dataset: Dataset name for event.dataset field
            
        Returns:
            ECS-compliant event dictionary
        """
        ecs_event = {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'event.dataset': dataset,
            'event.kind': 'event',
            'event.category': ['network'],  # Default category
            'event.type': ['info']  # Default type
        }
        
        # Map known fields
        for ecs_field, raw_field in self.field_mappings.items():
            if raw_field in raw_data:
                ecs_event[ecs_field] = raw_data[raw_field]
        
        # Handle message field specially
        if 'message' not in ecs_event and 'message' in raw_data:
            ecs_event['message'] = raw_data['message']
        elif 'message' not in ecs_event:
            # Create message from raw data if not present
            ecs_event['message'] = json.dumps(raw_data)
        
        # Add any unmapped fields under 'labels' for preservation
        labels = {}
        for key, value in raw_data.items():
            if key not in self.field_mappings.values() and key != 'message':
                labels[f"custom.{key}"] = value
        
        if labels:
            ecs_event['labels'] = labels
        
        return ecs_event
    
    def add_custom_mapping(self, ecs_field: str, raw_field: str):
        """Add custom field mapping."""
        self.field_mappings[ecs_field] = raw_field
    
    def load_custom_mappings(self, mappings: Dict[str, str]):
        """Load custom field mappings from configuration."""
        self.field_mappings.update(mappings)

def get_ecs_template(event_type: str = "generic") -> Dict[str, Any]:
    """
    Get ECS template for specific event types.
    
    Args:
        event_type: Type of event (syslog, firewall, web, etc.)
        
    Returns:
        ECS template dictionary
    """
    templates = {
        "syslog": {
            '@timestamp': None,
            'message': None,
            'event.dataset': 'syslog',
            'event.module': 'syslog',
            'event.kind': 'event',
            'event.category': ['system'],
            'event.type': ['info'],
            'host.name': None,
            'host.ip': None,
            'log.level': None,
            'process.name': None
        },
        "firewall": {
            '@timestamp': None,
            'message': None,
            'event.dataset': 'firewall',
            'event.module': 'firewall',
            'event.kind': 'event',
            'event.category': ['network'],
            'event.type': ['connection'],
            'source.ip': None,
            'source.port': None,
            'destination.ip': None,
            'destination.port': None,
            'network.protocol': None,
            'event.outcome': None
        },
        "web": {
            '@timestamp': None,
            'message': None,
            'event.dataset': 'web',
            'event.module': 'web',
            'event.kind': 'event',
            'event.category': ['web'],
            'event.type': ['access'],
            'source.ip': None,
            'http.request.method': None,
            'url.path': None,
            'http.response.status_code': None,
            'user_agent.original': None
        }
    }
    
    return templates.get(event_type, templates["syslog"])

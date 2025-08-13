"""
YAML-based custom schema mapping for StreamLiner.
Allows users to define custom field mappings via YAML configuration.
"""

import yaml
from typing import Dict, Any, Optional
from pathlib import Path
import logging

class YAMLSchemaMapper:
    """Custom schema mapper using YAML configuration files."""
    
    def __init__(self, yaml_path: Optional[str] = None):
        """
        Initialize YAML schema mapper.
        
        Args:
            yaml_path: Path to YAML mapping file
        """
        self.yaml_path = yaml_path
        self.mappings = {}
        self.transformations = {}
        self.defaults = {}
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        if yaml_path:
            self.load_mappings(yaml_path)
    
    def load_mappings(self, yaml_path: str):
        """
        Load field mappings from YAML file.
        
        Args:
            yaml_path: Path to YAML mapping file
        """
        try:
            yaml_file = Path(yaml_path)
            if not yaml_file.exists():
                raise FileNotFoundError(f"YAML mapping file not found: {yaml_path}")
            
            with open(yaml_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # Load field mappings
            self.mappings = config.get('field_mappings', {})
            self.transformations = config.get('transformations', {})
            self.defaults = config.get('defaults', {})
            
            self.logger.info(f"Loaded {len(self.mappings)} field mappings from {yaml_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load YAML mappings from {yaml_path}: {e}")
            raise
    
    def map_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map raw event using YAML-defined mappings.
        
        Args:
            raw_event: Raw event data
            
        Returns:
            Mapped event
        """
        mapped_event = {}
        
        # Apply default values first
        mapped_event.update(self.defaults)
        
        # Apply field mappings
        for target_field, source_config in self.mappings.items():
            if isinstance(source_config, str):
                # Simple field mapping
                if source_config in raw_event:
                    mapped_event[target_field] = raw_event[source_config]
            elif isinstance(source_config, dict):
                # Complex mapping with transformations
                value = self._extract_value(raw_event, source_config)
                if value is not None:
                    mapped_event[target_field] = value
        
        # Apply transformations
        for field, transform_config in self.transformations.items():
            if field in mapped_event:
                mapped_event[field] = self._apply_transformation(mapped_event[field], transform_config)
        
        # Copy unmapped fields if configured
        if self.defaults.get('preserve_unmapped', False):
            for key, value in raw_event.items():
                if key not in [v for v in self.mappings.values() if isinstance(v, str)]:
                    mapped_event[f"custom.{key}"] = value
        
        return mapped_event
    
    def _extract_value(self, raw_event: Dict[str, Any], config: Dict[str, Any]) -> Any:
        """
        Extract value from raw event using complex configuration.
        
        Args:
            raw_event: Raw event data
            config: Extraction configuration
            
        Returns:
            Extracted value or None
        """
        # Handle different extraction methods
        if 'field' in config:
            # Simple field extraction
            field_name = config['field']
            if field_name in raw_event:
                value = raw_event[field_name]
                
                # Apply field-level transformation
                if 'transform' in config:
                    value = self._apply_transformation(value, config['transform'])
                
                return value
        
        elif 'fields' in config:
            # Multi-field extraction (concatenation or first non-null)
            fields = config['fields']
            method = config.get('method', 'first')
            
            if method == 'concat':
                # Concatenate fields
                separator = config.get('separator', ' ')
                values = []
                for field in fields:
                    if field in raw_event and raw_event[field]:
                        values.append(str(raw_event[field]))
                return separator.join(values) if values else None
            
            elif method == 'first':
                # Return first non-null value
                for field in fields:
                    if field in raw_event and raw_event[field] is not None:
                        return raw_event[field]
        
        elif 'regex' in config:
            # Regex extraction
            import re
            pattern = config['regex']
            source_field = config.get('source_field', 'message')
            
            if source_field in raw_event:
                match = re.search(pattern, str(raw_event[source_field]))
                if match:
                    if 'group' in config:
                        return match.group(config['group'])
                    else:
                        return match.group(0)
        
        elif 'constant' in config:
            # Constant value
            return config['constant']
        
        return None
    
    def _apply_transformation(self, value: Any, transform_config: Dict[str, Any]) -> Any:
        """
        Apply transformation to a value.
        
        Args:
            value: Value to transform
            transform_config: Transformation configuration
            
        Returns:
            Transformed value
        """
        if not isinstance(transform_config, dict):
            return value
        
        transform_type = transform_config.get('type')
        
        if transform_type == 'lowercase':
            return str(value).lower() if value else value
        
        elif transform_type == 'uppercase':
            return str(value).upper() if value else value
        
        elif transform_type == 'strip':
            chars = transform_config.get('chars')
            return str(value).strip(chars) if value else value
        
        elif transform_type == 'replace':
            old = transform_config.get('old', '')
            new = transform_config.get('new', '')
            return str(value).replace(old, new) if value else value
        
        elif transform_type == 'split':
            separator = transform_config.get('separator', ' ')
            index = transform_config.get('index', 0)
            parts = str(value).split(separator) if value else []
            return parts[index] if 0 <= index < len(parts) else value
        
        elif transform_type == 'map':
            # Value mapping
            mapping = transform_config.get('mapping', {})
            default = transform_config.get('default', value)
            return mapping.get(str(value), default)
        
        elif transform_type == 'int':
            try:
                return int(value)
            except (ValueError, TypeError):
                return transform_config.get('default', 0)
        
        elif transform_type == 'float':
            try:
                return float(value)
            except (ValueError, TypeError):
                return transform_config.get('default', 0.0)
        
        elif transform_type == 'bool':
            if isinstance(value, bool):
                return value
            elif isinstance(value, str):
                return value.lower() in ['true', '1', 'yes', 'on']
            else:
                return bool(value)
        
        elif transform_type == 'timestamp':
            # Timestamp parsing
            from datetime import datetime
            format_str = transform_config.get('format', '%Y-%m-%d %H:%M:%S')
            try:
                if isinstance(value, (int, float)):
                    # Unix timestamp
                    if value > 1e10:  # Milliseconds
                        dt = datetime.fromtimestamp(value / 1000)
                    else:  # Seconds
                        dt = datetime.fromtimestamp(value)
                    return dt.isoformat() + 'Z'
                else:
                    # String timestamp
                    dt = datetime.strptime(str(value), format_str)
                    return dt.isoformat() + 'Z'
            except (ValueError, OSError):
                return value
        
        return value
    
    def validate_mapping(self) -> Dict[str, Any]:
        """
        Validate the loaded mapping configuration.
        
        Returns:
            Validation results
        """
        issues = []
        warnings = []
        
        # Check for required sections
        if not self.mappings:
            issues.append("No field mappings defined")
        
        # Validate field mappings
        for target_field, source_config in self.mappings.items():
            if not target_field:
                issues.append("Empty target field name")
                continue
            
            if isinstance(source_config, dict):
                # Validate complex mapping
                if not any(key in source_config for key in ['field', 'fields', 'regex', 'constant']):
                    issues.append(f"Invalid mapping configuration for {target_field}")
                
                # Check regex patterns
                if 'regex' in source_config:
                    try:
                        import re
                        re.compile(source_config['regex'])
                    except re.error as e:
                        issues.append(f"Invalid regex pattern for {target_field}: {e}")
        
        # Validate transformations
        for field, transform_config in self.transformations.items():
            if isinstance(transform_config, dict) and 'type' in transform_config:
                transform_type = transform_config['type']
                valid_types = ['lowercase', 'uppercase', 'strip', 'replace', 'split', 
                              'map', 'int', 'float', 'bool', 'timestamp']
                if transform_type not in valid_types:
                    warnings.append(f"Unknown transformation type '{transform_type}' for field {field}")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'field_count': len(self.mappings),
            'transformation_count': len(self.transformations)
        }
    
    @staticmethod
    def create_sample_mapping(output_path: str):
        """
        Create a sample YAML mapping file.
        
        Args:
            output_path: Path to create sample file
        """
        sample_config = {
            'defaults': {
                'event.kind': 'event',
                'event.category': ['process'],
                'event.type': ['info'],
                'preserve_unmapped': True
            },
            'field_mappings': {
                '@timestamp': {
                    'field': 'timestamp',
                    'transform': {
                        'type': 'timestamp',
                        'format': '%Y-%m-%d %H:%M:%S'
                    }
                },
                'message': 'msg',
                'host.name': 'hostname',
                'host.ip': 'host_ip',
                'source.ip': 'src_ip',
                'source.port': {
                    'field': 'src_port',
                    'transform': {'type': 'int'}
                },
                'destination.ip': 'dst_ip',
                'destination.port': {
                    'field': 'dst_port',
                    'transform': {'type': 'int'}
                },
                'log.level': {
                    'field': 'level',
                    'transform': {
                        'type': 'map',
                        'mapping': {
                            'WARN': 'WARNING',
                            'ERR': 'ERROR',
                            'CRIT': 'CRITICAL'
                        }
                    }
                },
                'user.name': {
                    'fields': ['username', 'user', 'login'],
                    'method': 'first'
                },
                'process.name': {
                    'regex': r'process=(\w+)',
                    'source_field': 'message',
                    'group': 1
                }
            },
            'transformations': {
                'message': {
                    'type': 'strip'
                },
                'host.name': {
                    'type': 'lowercase'
                }
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(sample_config, f, default_flow_style=False, indent=2)
        
        print(f"Sample YAML mapping created at: {output_path}")

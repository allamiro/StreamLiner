import configparser
import os
from typing import Dict, Any
import logging

def load_config(path: str) -> Dict[str, Any]:
    """
    Load StreamLiner configuration from INI file.
    
    Args:
        path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    config = configparser.ConfigParser()
    config.read(path)

    cfg_dict = {section: dict(config[section]) for section in config.sections()}
    
    # Process and validate configuration
    cfg_dict = _process_config(cfg_dict)
    
    return cfg_dict

def _process_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process and validate configuration values.
    
    Args:
        config: Raw configuration dictionary
        
    Returns:
        Processed configuration
    """
    processed = {}
    
    # Process input configurations
    if 'input.syslog_udp' in config:
        processed['syslog_udp'] = {
            'enabled': config['input.syslog_udp'].get('enabled', 'true').lower() == 'true',
            'host': config['input.syslog_udp'].get('host', '0.0.0.0'),
            'port': int(config['input.syslog_udp'].get('port', '514')),
            'buffer_size': int(config['input.syslog_udp'].get('buffer_size', '65536'))
        }
    
    if 'input.syslog_tcp' in config:
        processed['syslog_tcp'] = {
            'enabled': config['input.syslog_tcp'].get('enabled', 'false').lower() == 'true',
            'host': config['input.syslog_tcp'].get('host', '0.0.0.0'),
            'port': int(config['input.syslog_tcp'].get('port', '514')),
            'max_connections': int(config['input.syslog_tcp'].get('max_connections', '100'))
        }
    
    if 'input.file' in config:
        files_config = config['input.file'].get('paths', '').split(',')
        processed['files'] = [
            {
                'path': path.strip(),
                'follow': config['input.file'].get('follow', 'false').lower() == 'true',
                'start_from_end': config['input.file'].get('start_from_end', 'true').lower() == 'true'
            }
            for path in files_config if path.strip()
        ]
    
    # Process parser configuration
    if 'parser' in config:
        processed['parser'] = {
            'type': config['parser'].get('type', 'auto'),
            'dataset': config['parser'].get('dataset', 'generic'),
            'regex_preset': config['parser'].get('regex_preset'),
            'regex_pattern': config['parser'].get('regex_pattern'),
            'custom_mappings': config['parser'].get('custom_mappings')
        }
    
    # Process output configurations
    if 'output.elasticsearch' in config:
        processed['elasticsearch'] = {
            'enabled': config['output.elasticsearch'].get('enabled', 'true').lower() == 'true',
            'host': config['output.elasticsearch'].get('host', 'localhost'),
            'port': int(config['output.elasticsearch'].get('port', '9200')),
            'scheme': config['output.elasticsearch'].get('scheme', 'http'),
            'index': config['output.elasticsearch'].get('index', 'logs'),
            'username': config['output.elasticsearch'].get('username'),
            'password': config['output.elasticsearch'].get('password'),
            'api_key': config['output.elasticsearch'].get('api_key'),
            'verify_ssl': config['output.elasticsearch'].get('verify_ssl', 'true').lower() == 'true',
            'batch_size': int(config['output.elasticsearch'].get('batch_size', '100')),
            'flush_interval': int(config['output.elasticsearch'].get('flush_interval', '5')),
            'date_based_index': config['output.elasticsearch'].get('date_based_index', 'false').lower() == 'true'
        }
    
    if 'output.opensearch' in config:
        processed['opensearch'] = {
            'enabled': config['output.opensearch'].get('enabled', 'false').lower() == 'true',
            'host': config['output.opensearch'].get('host', 'localhost'),
            'port': int(config['output.opensearch'].get('port', '9200')),
            'scheme': config['output.opensearch'].get('scheme', 'http'),
            'index': config['output.opensearch'].get('index', 'logs'),
            'username': config['output.opensearch'].get('username'),
            'password': config['output.opensearch'].get('password'),
            'verify_ssl': config['output.opensearch'].get('verify_ssl', 'true').lower() == 'true',
            'batch_size': int(config['output.opensearch'].get('batch_size', '100')),
            'flush_interval': int(config['output.opensearch'].get('flush_interval', '5')),
            'date_based_index': config['output.opensearch'].get('date_based_index', 'false').lower() == 'true'
        }
    
    # Legacy support for old config format
    if 'output.elastic' in config:
        processed['elasticsearch'] = {
            'enabled': True,
            'host': config['output.elastic'].get('host', 'localhost'),
            'port': int(config['output.elastic'].get('port', '9200')),
            'scheme': 'http',
            'index': config['output.elastic'].get('index', 'logs'),
            'batch_size': 100,
            'flush_interval': 5,
            'date_based_index': False
        }
    
    # Add logging configuration
    if 'logging' in config:
        processed['logging'] = {
            'level': config['logging'].get('level', 'INFO'),
            'format': config['logging'].get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            'file': config['logging'].get('file')
        }
    else:
        processed['logging'] = {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }
    
    return processed

def setup_logging(config: Dict[str, Any]):
    """
    Setup logging based on configuration.
    
    Args:
        config: Configuration dictionary
    """
    logging_config = config.get('logging', {})
    
    level = getattr(logging, logging_config.get('level', 'INFO').upper())
    format_str = logging_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    logging.basicConfig(
        level=level,
        format=format_str,
        filename=logging_config.get('file')
    )
    
    # Set specific logger levels
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

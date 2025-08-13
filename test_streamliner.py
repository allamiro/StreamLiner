#!/usr/bin/env python3
"""
Test script for StreamLiner functionality.
Tests all major components: parsers, inputs, outputs, and ECS compliance.
"""

import json
import tempfile
import os
from datetime import datetime

# Add src to path for testing
import sys
sys.path.insert(0, 'src')

# Import with absolute imports to avoid relative import issues
try:
    from src.schemas.ecs import ECSMapper, get_ecs_template
    from src.parsers.json_parser import JSONParser
    from src.parsers.regex_parser import RegexParser
    from src.parsers.ecs_parser import ECSParser
    from src.schemas.yaml_mapper import YAMLSchemaMapper
    from src.config.loader import load_config
except ImportError:
    # Fallback for direct execution
    from schemas.ecs import ECSMapper, get_ecs_template
    from parsers.json_parser import JSONParser
    from parsers.regex_parser import RegexParser
    from parsers.ecs_parser import ECSParser
    from schemas.yaml_mapper import YAMLSchemaMapper
    from config.loader import load_config

def test_ecs_mapper():
    """Test ECS mapper functionality."""
    print("Testing ECS Mapper...")
    
    mapper = ECSMapper()
    
    # Test basic mapping
    raw_data = {
        'timestamp': '2024-01-15T10:24:02Z',
        'hostname': 'web01',
        'src_ip': '192.168.1.100',
        'message': 'User login successful'
    }
    
    ecs_event = mapper.map_to_ecs(raw_data, 'test')
    
    assert '@timestamp' in ecs_event
    assert ecs_event['event.dataset'] == 'test'
    assert ecs_event['host.name'] == 'web01'
    assert ecs_event['source.ip'] == '192.168.1.100'
    assert ecs_event['message'] == 'User login successful'
    
    print("✓ ECS Mapper test passed")

def test_json_parser():
    """Test JSON parser."""
    print("Testing JSON Parser...")
    
    parser = JSONParser()
    
    # Test valid JSON
    json_log = '{"timestamp": "2024-01-15T10:24:02Z", "level": "INFO", "message": "Test message", "user": "john"}'
    result = parser.parse(json_log, 'json_test')
    
    assert result['event.dataset'] == 'json_test'
    assert result['message'] == 'Test message'
    assert 'event.ingested' in result
    assert result['log.source.type'] == 'json'
    
    # Test invalid JSON (should handle gracefully)
    invalid_json = 'not valid json'
    result = parser.parse(invalid_json, 'json_test')
    
    assert result['event.type'] == ['error']
    assert 'error.message' in result
    
    print("✓ JSON Parser test passed")

def test_regex_parser():
    """Test regex parser."""
    print("Testing Regex Parser...")
    
    # Test syslog pattern
    parser = RegexParser(pattern_name='syslog')
    
    syslog_line = 'Apr 15 10:24:02 web01 nginx[1234]: 192.168.1.100 - GET /api/users'
    result = parser.parse(syslog_line, 'syslog_test')
    
    assert result['event.dataset'] == 'syslog_test'
    assert result['host.name'] == 'web01'
    assert result['process.name'] == 'nginx'
    assert result['process.pid'] == 1234
    assert result['log.source.type'] == 'regex'
    
    # Test Apache pattern
    apache_parser = RegexParser(pattern_name='apache_common')
    apache_line = '192.168.1.100 - - [15/Apr/2024:10:24:02 +0000] "GET /api/users HTTP/1.1" 200 1234'
    result = apache_parser.parse(apache_line, 'apache_test')
    
    assert result['source.ip'] == '192.168.1.100'
    assert result['http.request.method'] == 'GET'
    assert result['http.response.status_code'] == 200
    assert result['event.outcome'] == 'success'
    
    print("✓ Regex Parser test passed")

def test_ecs_parser():
    """Test ECS parser with auto-detection."""
    print("Testing ECS Parser...")
    
    parser = ECSParser()
    
    # Test JSON auto-detection
    json_log = '{"level": "INFO", "message": "Test", "user": "john"}'
    result = parser.parse(json_log, 'auto', 'test')
    
    assert result['event.dataset'] == 'test'
    assert result['message'] == 'Test'
    
    # Test basic parsing
    basic_log = 'Simple log message with IP 192.168.1.100'
    result = parser.parse(basic_log, 'auto', 'test')
    
    assert result['message'] == basic_log
    assert result['source.ip'] == '192.168.1.100'  # Should extract IP
    
    print("✓ ECS Parser test passed")

def test_yaml_mapper():
    """Test YAML schema mapper."""
    print("Testing YAML Mapper...")
    
    # Create temporary YAML mapping
    yaml_content = """
defaults:
  event.kind: event
  event.category: [process]

field_mappings:
  '@timestamp':
    field: ts
    transform:
      type: timestamp
      format: '%Y-%m-%d %H:%M:%S'
  'host.name': hostname
  'source.ip': src_ip
  'log.level':
    field: level
    transform:
      type: map
      mapping:
        WARN: WARNING
        ERR: ERROR

transformations:
  'host.name':
    type: lowercase
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        yaml_path = f.name
    
    try:
        mapper = YAMLSchemaMapper(yaml_path)
        
        raw_event = {
            'ts': '2024-01-15 10:24:02',
            'hostname': 'WEB01',
            'src_ip': '192.168.1.100',
            'level': 'WARN',
            'message': 'Test message'
        }
        
        mapped_event = mapper.map_event(raw_event)
        
        assert mapped_event['event.kind'] == 'event'
        assert mapped_event['host.name'] == 'web01'  # Should be lowercase
        assert mapped_event['source.ip'] == '192.168.1.100'
        assert mapped_event['log.level'] == 'WARNING'  # Should be mapped
        assert '@timestamp' in mapped_event
        
        print("✓ YAML Mapper test passed")
        
    finally:
        os.unlink(yaml_path)

def test_config_loader():
    """Test configuration loader."""
    print("Testing Config Loader...")
    
    # Create temporary config file
    config_content = """
[logging]
level = INFO

[parser]
type = auto
dataset = test

[input.syslog_udp]
enabled = true
port = 1514

[output.elasticsearch]
enabled = true
host = localhost
port = 9200
index = test-logs
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
        f.write(config_content)
        config_path = f.name
    
    try:
        config = load_config(config_path)
        
        assert config['logging']['level'] == 'INFO'
        assert config['parser']['type'] == 'auto'
        assert config['syslog_udp']['enabled'] == True
        assert config['syslog_udp']['port'] == 1514
        assert config['elasticsearch']['enabled'] == True
        assert config['elasticsearch']['index'] == 'test-logs'
        
        print("✓ Config Loader test passed")
        
    finally:
        os.unlink(config_path)

def test_ecs_templates():
    """Test ECS templates."""
    print("Testing ECS Templates...")
    
    # Test different event types
    syslog_template = get_ecs_template('syslog')
    assert syslog_template['event.dataset'] == 'syslog'
    assert syslog_template['event.category'] == ['system']
    
    firewall_template = get_ecs_template('firewall')
    assert firewall_template['event.dataset'] == 'firewall'
    assert firewall_template['event.category'] == ['network']
    
    web_template = get_ecs_template('web')
    assert web_template['event.dataset'] == 'web'
    assert web_template['event.category'] == ['web']
    
    print("✓ ECS Templates test passed")

def test_ecs_compliance():
    """Test ECS compliance validation."""
    print("Testing ECS Compliance...")
    
    parser = ECSParser()
    
    # Create a test event
    test_event = {
        '@timestamp': datetime.utcnow().isoformat() + 'Z',
        'message': 'Test message',
        'event.dataset': 'test',
        'event.kind': 'event',
        'event.category': ['process'],
        'event.type': ['info']
    }
    
    validation = parser.validate_ecs_compliance(test_event)
    
    assert validation['compliant'] == True
    assert len(validation['issues']) == 0
    assert validation['score'] >= 90
    
    # Test non-compliant event
    bad_event = {
        'message': 'Test message',
        '@timestamp': 'invalid-timestamp',
        'event.category': ['invalid_category']
    }
    
    validation = parser.validate_ecs_compliance(bad_event)
    
    assert validation['compliant'] == False
    assert len(validation['issues']) > 0
    
    print("✓ ECS Compliance test passed")

def run_all_tests():
    """Run all tests."""
    print("=" * 50)
    print("StreamLiner Component Tests")
    print("=" * 50)
    
    try:
        test_ecs_mapper()
        test_json_parser()
        test_regex_parser()
        test_ecs_parser()
        test_yaml_mapper()
        test_config_loader()
        test_ecs_templates()
        test_ecs_compliance()
        
        print("\n" + "=" * 50)
        print("✅ All tests passed successfully!")
        print("StreamLiner is ready for use.")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

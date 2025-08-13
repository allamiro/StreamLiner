# StreamLiner Usage Guide

## Quick Start

### 1. Installation

```bash
# Install from source
cd StreamLiner
pip install .

# Or install in development mode
pip install -e .
```

### 2. Basic Usage

#### Parse a Single Log Line
```bash
python3 src/main.py --config examples/streamliner_full.ini --log "Apr 15 10:24:02 web01 nginx: 192.168.1.100 GET /api/users"
```

#### Run as Daemon (Syslog Server)
```bash
python3 src/main.py --config examples/streamliner_full.ini
```

#### Create Sample YAML Mapping
```bash
python3 src/main.py --create-sample-mapping custom_mapping.yaml
```

#### Validate Configuration
```bash
python3 src/main.py --config examples/streamliner_full.ini --validate-config
```

## Configuration

### INI Configuration Format

StreamLiner uses INI-based configuration with the following sections:

#### Logging
```ini
[logging]
level = INFO
format = %(asctime)s - %(name)s - %(levelname)s - %(message)s
file = /var/log/streamliner.log  # Optional
```

#### Parser
```ini
[parser]
type = auto                    # auto, json, regex, basic
dataset = generic             # Dataset name for ECS events
regex_preset = syslog        # Predefined regex patterns
custom_mappings = mapping.yaml # Custom YAML field mappings
```

#### Inputs

**Syslog UDP:**
```ini
[input.syslog_udp]
enabled = true
host = 0.0.0.0
port = 514
buffer_size = 65536
```

**Syslog TCP:**
```ini
[input.syslog_tcp]
enabled = false
host = 0.0.0.0
port = 514
max_connections = 100
```

**File Monitoring:**
```ini
[input.file]
paths = /var/log/app.log,/var/log/nginx/access.log
follow = true
start_from_end = true
```

#### Outputs

**Elasticsearch:**
```ini
[output.elasticsearch]
enabled = true
host = localhost
port = 9200
scheme = http
index = logs
username = elastic           # Optional
password = changeme         # Optional
api_key = your_key_here     # Optional
verify_ssl = true
batch_size = 100
flush_interval = 5
date_based_index = false
```

**OpenSearch:**
```ini
[output.opensearch]
enabled = false
host = localhost
port = 9200
scheme = http
index = logs
username = admin            # Optional
password = admin           # Optional
verify_ssl = true
batch_size = 100
flush_interval = 5
date_based_index = false
```

## Parser Types

### 1. Auto Detection (Recommended)
Automatically detects the best parser for each log line:
- JSON logs → JSON parser
- Structured logs → Regex parser (if configured)
- Unstructured logs → Basic parser

### 2. JSON Parser
Handles structured JSON logs with automatic ECS mapping:
```json
{"timestamp": "2024-01-15T10:24:02Z", "level": "INFO", "message": "User login", "user": "john"}
```

### 3. Regex Parser
Uses predefined patterns or custom regex for structured parsing.

**Available Presets:**
- `syslog` - Standard syslog format
- `apache_common` - Apache Common Log Format
- `apache_combined` - Apache Combined Log Format
- `nginx_access` - Nginx access logs
- `firewall` - Firewall logs
- `generic_kv` - Generic key-value format

### 4. Basic Parser
Fallback parser for unstructured logs with basic field extraction.

## Custom YAML Mappings

Create custom field mappings using YAML configuration:

```yaml
defaults:
  event.kind: event
  event.category: [process]
  preserve_unmapped: true

field_mappings:
  '@timestamp':
    field: timestamp
    transform:
      type: timestamp
      format: '%Y-%m-%d %H:%M:%S'
  
  'host.name': hostname
  'source.ip': src_ip
  'source.port':
    field: src_port
    transform:
      type: int
  
  'log.level':
    field: level
    transform:
      type: map
      mapping:
        WARN: WARNING
        ERR: ERROR

transformations:
  message:
    type: strip
  'host.name':
    type: lowercase
```

### Transformation Types
- `lowercase` / `uppercase` - Case conversion
- `strip` - Remove whitespace
- `replace` - String replacement
- `split` - Split and extract by index
- `map` - Value mapping
- `int` / `float` / `bool` - Type conversion
- `timestamp` - Timestamp parsing

## ECS Compliance

StreamLiner generates ECS-compliant events with:

### Core Fields
- `@timestamp` - Event timestamp
- `message` - Log message
- `event.dataset` - Dataset classification
- `event.kind` - Event kind (always "event")
- `event.category` - Event category array
- `event.type` - Event type array

### Common Field Sets
- **Host**: `host.name`, `host.ip`, `host.os.name`
- **Network**: `source.ip`, `destination.ip`, `network.protocol`
- **User**: `user.name`, `user.id`
- **Process**: `process.name`, `process.pid`
- **HTTP**: `http.request.method`, `http.response.status_code`

## Examples

### Syslog Processing
```bash
# Send syslog to StreamLiner
logger -n localhost -P 514 "Test message from application"

# Or use netcat
echo "Apr 15 10:24:02 web01 app[1234]: User login successful" | nc -u localhost 514
```

### File Monitoring
```ini
[input.file]
paths = /var/log/nginx/access.log
follow = true
start_from_end = false
```

### Custom Regex Pattern
```ini
[parser]
type = regex
regex_pattern = (?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<message>.*)
```

## Troubleshooting

### Common Issues

1. **Permission Denied (Port 514)**
   ```bash
   # Run with sudo for privileged ports
   sudo python src/main.py --config streamliner.ini
   
   # Or use unprivileged port
   [input.syslog_udp]
   port = 1514
   ```

2. **Connection Refused (Elasticsearch)**
   - Check Elasticsearch is running
   - Verify host/port configuration
   - Check authentication credentials

3. **No Events Received**
   - Verify input configuration
   - Check firewall settings
   - Enable DEBUG logging

### Debug Mode
```ini
[logging]
level = DEBUG
```

### Validate Configuration
```bash
python src/main.py --config streamliner.ini --validate-config
```

## Performance Tips

1. **Batch Processing**: Increase `batch_size` for high-volume environments
2. **Flush Interval**: Adjust `flush_interval` based on latency requirements
3. **Date-based Indices**: Enable for better Elasticsearch performance
4. **File Monitoring**: Use `start_from_end = true` for active log files

## Security Considerations

1. **Network Security**: Restrict syslog input access
2. **Authentication**: Use API keys or username/password for outputs
3. **SSL/TLS**: Enable `verify_ssl` for secure connections
4. **File Permissions**: Ensure proper log file access permissions

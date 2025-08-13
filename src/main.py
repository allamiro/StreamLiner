#!/usr/bin/env python3
"""
StreamLiner - Universal Log Parser for Any SIEM
Main application entry point with full ECS support.
"""

import argparse
import signal
import sys
import time
from typing import Dict, Any, List
import logging

# Handle imports for both direct execution and package installation
try:
    # Try relative imports first (when run as module)
    from .config.loader import load_config, setup_logging
    from .parsers.ecs_parser import ECSParser
    from .inputs.syslog_input import SyslogInputManager
    from .inputs.file_input import FileInputManager
    from .connectors.elasticsearch import ElasticsearchConnector
    from .connectors.opensearch import OpenSearchConnector
    from .schemas.yaml_mapper import YAMLSchemaMapper
except ImportError:
    # Fallback to absolute imports (when run directly)
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    
    from config.loader import load_config, setup_logging
    from parsers.ecs_parser import ECSParser
    from inputs.syslog_input import SyslogInputManager
    from inputs.file_input import FileInputManager
    from connectors.elasticsearch import ElasticsearchConnector
    from connectors.opensearch import OpenSearchConnector
    from schemas.yaml_mapper import YAMLSchemaMapper

class StreamLinerApp:
    """Main StreamLiner application."""
    
    def __init__(self, config_path: str):
        """Initialize StreamLiner with configuration."""
        self.config_path = config_path
        self.config = None
        self.parser = None
        self.input_managers = []
        self.connectors = []
        self.running = False
        
        # Setup logging first
        self.logger = None
        
        # Load configuration
        self._load_config()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self):
        """Load and validate configuration."""
        try:
            self.config = load_config(self.config_path)
            setup_logging(self.config)
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"Loaded configuration from {self.config_path}")
        except Exception as e:
            print(f"[ERROR] Failed to load configuration: {e}")
            sys.exit(1)
    
    def _setup_parser(self):
        """Setup the ECS parser with configuration."""
        parser_config = self.config.get('parser', {})
        
        # Initialize ECS parser
        self.parser = ECSParser(parser_config)
        
        self.logger.info(f"Parser initialized with type: {parser_config.get('type', 'auto')}")
    
    def _setup_inputs(self):
        """Setup input managers."""
        # Setup syslog inputs
        if (self.config.get('syslog_udp', {}).get('enabled') or 
            self.config.get('syslog_tcp', {}).get('enabled')):
            syslog_manager = SyslogInputManager(self.config)
            syslog_manager.start(self._handle_message)
            self.input_managers.append(syslog_manager)
            self.logger.info("Syslog input manager started")
        
        # Setup file inputs
        if self.config.get('files'):
            file_manager = FileInputManager(self.config)
            file_manager.start(self._handle_message)
            self.input_managers.append(file_manager)
            self.logger.info("File input manager started")
    
    def _setup_connectors(self):
        """Setup output connectors."""
        # Setup Elasticsearch connector
        if self.config.get('elasticsearch', {}).get('enabled'):
            try:
                es_connector = ElasticsearchConnector(self.config['elasticsearch'])
                # Create index template
                es_connector.create_index_template()
                self.connectors.append(es_connector)
                self.logger.info("Elasticsearch connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Elasticsearch connector: {e}")
        
        # Setup OpenSearch connector
        if self.config.get('opensearch', {}).get('enabled'):
            try:
                os_connector = OpenSearchConnector(self.config['opensearch'])
                # Create index template
                os_connector.create_index_template()
                self.connectors.append(os_connector)
                self.logger.info("OpenSearch connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize OpenSearch connector: {e}")
        
        if not self.connectors:
            self.logger.warning("No output connectors configured")
    
    def _handle_message(self, message: str, metadata: Dict[str, Any]):
        """Handle incoming log message."""
        try:
            # Parse message
            parser_config = self.config.get('parser', {})
            parsed_event = self.parser.parse(
                message,
                parser_type=parser_config.get('type', 'auto'),
                dataset=parser_config.get('dataset', 'generic')
            )
            
            # Add metadata
            if metadata:
                parsed_event.update({
                    'log.source.metadata': metadata
                })
                
                # Add source IP if available
                if 'source_ip' in metadata:
                    parsed_event['source.ip'] = metadata['source_ip']
                
                # Add file information if available
                if 'source_file' in metadata:
                    parsed_event['log.file.path'] = metadata['source_file']
                    if 'line_number' in metadata:
                        parsed_event['log.file.line'] = metadata['line_number']
            
            # Send to all configured connectors
            for connector in self.connectors:
                try:
                    connector.send_event(parsed_event)
                except Exception as e:
                    self.logger.error(f"Failed to send event to connector: {e}")
            
            # Log successful processing
            self.logger.debug(f"Processed message: {message[:100]}...")
            
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self):
        """Start the StreamLiner application."""
        try:
            self.logger.info("Starting StreamLiner...")
            
            # Setup components
            self._setup_parser()
            self._setup_connectors()
            self._setup_inputs()
            
            self.running = True
            self.logger.info("StreamLiner started successfully")
            
            # Keep running until stopped
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Error starting StreamLiner: {e}")
            raise
        finally:
            self.stop()
    
    def stop(self):
        """Stop the StreamLiner application."""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping StreamLiner...")
        
        # Stop input managers
        for input_manager in self.input_managers:
            try:
                input_manager.stop()
            except Exception as e:
                self.logger.error(f"Error stopping input manager: {e}")
        
        # Close connectors
        for connector in self.connectors:
            try:
                connector.close()
            except Exception as e:
                self.logger.error(f"Error closing connector: {e}")
        
        self.logger.info("StreamLiner stopped")
    
    def parse_single_log(self, log_line: str) -> Dict[str, Any]:
        """Parse a single log line (for CLI mode)."""
        if not self.parser:
            self._setup_parser()
        
        parser_config = self.config.get('parser', {})
        return self.parser.parse(
            log_line,
            parser_type=parser_config.get('type', 'auto'),
            dataset=parser_config.get('dataset', 'generic')
        )

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="StreamLiner - Universal Log Parser for Any SIEM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start as daemon with syslog inputs
  python main.py --config streamliner.ini
  
  # Parse single log line
  python main.py --config streamliner.ini --log "Apr 15 10:24:02 web01 nginx: 192.168.1.100 GET /api/users"
  
  # Create sample YAML mapping
  python main.py --create-sample-mapping custom_mapping.yaml
        """
    )
    
    parser.add_argument(
        "--config", 
        required=False, 
        help="Path to streamliner.ini configuration file"
    )
    
    parser.add_argument(
        "--log", 
        help="Single log line to parse and send (CLI mode)"
    )
    
    parser.add_argument(
        "--create-sample-mapping",
        metavar="PATH",
        help="Create sample YAML mapping file at specified path"
    )
    
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration and exit"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="StreamLiner 0.1.0 (Community Edition)"
    )
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.create_sample_mapping:
        YAMLSchemaMapper.create_sample_mapping(args.create_sample_mapping)
        return
    
    # Check if config is required
    if not args.config:
        parser.error("--config is required unless using --create-sample-mapping")
    
    # Initialize application
    try:
        app = StreamLinerApp(args.config)
        
        if args.validate_config:
            print("[INFO] Configuration is valid")
            return
        
        if args.log:
            # CLI mode - parse single log
            app._setup_parser()
            parsed_event = app.parse_single_log(args.log)
            
            print("[INFO] Parsed event:")
            import json
            print(json.dumps(parsed_event, indent=2))
            
            # Send to connectors if configured
            if app.config.get('elasticsearch', {}).get('enabled') or app.config.get('opensearch', {}).get('enabled'):
                app._setup_connectors()
                for connector in app.connectors:
                    connector.send_event(parsed_event)
                    connector.close()
                print("[INFO] Event sent to configured outputs")
        else:
            # Daemon mode - start inputs and run continuously
            app.start()
            
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

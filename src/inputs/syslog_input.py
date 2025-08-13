"""
Syslog input handlers for UDP and TCP protocols.
Receives syslog messages and forwards them to the parsing pipeline.
"""

import socket
import threading
import time
from typing import Callable, Optional, Dict, Any
from datetime import datetime
import logging

class SyslogUDPInput:
    """UDP Syslog input handler."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 514, buffer_size: int = 65536):
        """
        Initialize UDP syslog input.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            buffer_size: UDP buffer size
        """
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.socket = None
        self.running = False
        self.thread = None
        self.message_handler = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def start(self, message_handler: Callable[[str, Dict[str, Any]], None]):
        """
        Start the UDP syslog listener.
        
        Args:
            message_handler: Function to handle received messages
        """
        self.message_handler = message_handler
        self.running = True
        
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            
            self.logger.info(f"UDP Syslog listener started on {self.host}:{self.port}")
            
            # Start listening thread
            self.thread = threading.Thread(target=self._listen, daemon=True)
            self.thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start UDP syslog listener: {e}")
            self.running = False
            raise
    
    def stop(self):
        """Stop the UDP syslog listener."""
        self.running = False
        
        if self.socket:
            self.socket.close()
            self.socket = None
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        self.logger.info("UDP Syslog listener stopped")
    
    def _listen(self):
        """Main listening loop."""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(self.buffer_size)
                message = data.decode('utf-8', errors='replace').strip()
                
                if message and self.message_handler:
                    # Create metadata about the message
                    metadata = {
                        'source_ip': addr[0],
                        'source_port': addr[1],
                        'transport': 'udp',
                        'received_at': datetime.utcnow().isoformat() + 'Z'
                    }
                    
                    # Handle message in separate thread to avoid blocking
                    threading.Thread(
                        target=self._handle_message,
                        args=(message, metadata),
                        daemon=True
                    ).start()
                    
            except socket.error as e:
                if self.running:  # Only log if we're supposed to be running
                    self.logger.error(f"Socket error in UDP listener: {e}")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in UDP listener: {e}")
                time.sleep(0.1)  # Brief pause to prevent tight error loop
    
    def _handle_message(self, message: str, metadata: Dict[str, Any]):
        """Handle received message."""
        try:
            self.message_handler(message, metadata)
        except Exception as e:
            self.logger.error(f"Error handling UDP message: {e}")

class SyslogTCPInput:
    """TCP Syslog input handler."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 514, max_connections: int = 100):
        """
        Initialize TCP syslog input.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            max_connections: Maximum concurrent connections
        """
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.socket = None
        self.running = False
        self.thread = None
        self.message_handler = None
        self.client_threads = []
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def start(self, message_handler: Callable[[str, Dict[str, Any]], None]):
        """
        Start the TCP syslog listener.
        
        Args:
            message_handler: Function to handle received messages
        """
        self.message_handler = message_handler
        self.running = True
        
        try:
            # Create TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(self.max_connections)
            
            self.logger.info(f"TCP Syslog listener started on {self.host}:{self.port}")
            
            # Start accepting thread
            self.thread = threading.Thread(target=self._accept_connections, daemon=True)
            self.thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start TCP syslog listener: {e}")
            self.running = False
            raise
    
    def stop(self):
        """Stop the TCP syslog listener."""
        self.running = False
        
        if self.socket:
            self.socket.close()
            self.socket = None
        
        # Wait for main thread
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        # Wait for client threads
        for client_thread in self.client_threads:
            if client_thread.is_alive():
                client_thread.join(timeout=1)
        
        self.logger.info("TCP Syslog listener stopped")
    
    def _accept_connections(self):
        """Accept incoming connections."""
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                
                # Create client handler thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
                self.client_threads.append(client_thread)
                
                # Clean up finished threads
                self.client_threads = [t for t in self.client_threads if t.is_alive()]
                
            except socket.error as e:
                if self.running:
                    self.logger.error(f"Socket error accepting connections: {e}")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error accepting connections: {e}")
    
    def _handle_client(self, client_socket: socket.socket, addr: tuple):
        """Handle individual client connection."""
        try:
            self.logger.debug(f"New TCP connection from {addr[0]}:{addr[1]}")
            
            buffer = ""
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    buffer += data.decode('utf-8', errors='replace')
                    
                    # Process complete lines
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        message = line.strip()
                        
                        if message and self.message_handler:
                            metadata = {
                                'source_ip': addr[0],
                                'source_port': addr[1],
                                'transport': 'tcp',
                                'received_at': datetime.utcnow().isoformat() + 'Z'
                            }
                            
                            # Handle message
                            threading.Thread(
                                target=self._handle_message,
                                args=(message, metadata),
                                daemon=True
                            ).start()
                
                except socket.timeout:
                    continue
                except socket.error:
                    break
                    
        except Exception as e:
            self.logger.error(f"Error handling TCP client {addr}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            self.logger.debug(f"TCP connection closed for {addr[0]}:{addr[1]}")
    
    def _handle_message(self, message: str, metadata: Dict[str, Any]):
        """Handle received message."""
        try:
            self.message_handler(message, metadata)
        except Exception as e:
            self.logger.error(f"Error handling TCP message: {e}")

class SyslogInputManager:
    """Manager for both UDP and TCP syslog inputs."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize syslog input manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.udp_input = None
        self.tcp_input = None
        self.message_handler = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def start(self, message_handler: Callable[[str, Dict[str, Any]], None]):
        """
        Start configured syslog inputs.
        
        Args:
            message_handler: Function to handle received messages
        """
        self.message_handler = message_handler
        
        # Start UDP input if configured
        if self.config.get('syslog_udp', {}).get('enabled', True):
            udp_config = self.config.get('syslog_udp', {})
            self.udp_input = SyslogUDPInput(
                host=udp_config.get('host', '0.0.0.0'),
                port=udp_config.get('port', 514),
                buffer_size=udp_config.get('buffer_size', 65536)
            )
            self.udp_input.start(message_handler)
        
        # Start TCP input if configured
        if self.config.get('syslog_tcp', {}).get('enabled', False):
            tcp_config = self.config.get('syslog_tcp', {})
            self.tcp_input = SyslogTCPInput(
                host=tcp_config.get('host', '0.0.0.0'),
                port=tcp_config.get('port', 514),
                max_connections=tcp_config.get('max_connections', 100)
            )
            self.tcp_input.start(message_handler)
        
        self.logger.info("Syslog input manager started")
    
    def stop(self):
        """Stop all syslog inputs."""
        if self.udp_input:
            self.udp_input.stop()
            self.udp_input = None
        
        if self.tcp_input:
            self.tcp_input.stop()
            self.tcp_input = None
        
        self.logger.info("Syslog input manager stopped")

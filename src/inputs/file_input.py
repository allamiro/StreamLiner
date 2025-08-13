"""
File input handler for reading log files.
Supports tailing files and batch processing.
"""

import os
import time
import threading
from typing import Callable, Optional, Dict, Any
from datetime import datetime
import logging

class FileInput:
    """File input handler for log files."""
    
    def __init__(self, file_path: str, follow: bool = False, start_from_end: bool = True):
        """
        Initialize file input.
        
        Args:
            file_path: Path to the log file
            follow: Whether to follow the file for new lines (tail -f behavior)
            start_from_end: If following, start from end of file
        """
        self.file_path = file_path
        self.follow = follow
        self.start_from_end = start_from_end
        self.running = False
        self.thread = None
        self.message_handler = None
        self.file_handle = None
        self.last_position = 0
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def start(self, message_handler: Callable[[str, Dict[str, Any]], None]):
        """
        Start reading the file.
        
        Args:
            message_handler: Function to handle each line
        """
        self.message_handler = message_handler
        self.running = True
        
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"Log file not found: {self.file_path}")
            
            self.file_handle = open(self.file_path, 'r', encoding='utf-8', errors='replace')
            
            # If following and starting from end, seek to end
            if self.follow and self.start_from_end:
                self.file_handle.seek(0, 2)  # Seek to end
                self.last_position = self.file_handle.tell()
            
            self.logger.info(f"File input started for {self.file_path}")
            
            if self.follow:
                # Start following thread
                self.thread = threading.Thread(target=self._follow_file, daemon=True)
                self.thread.start()
            else:
                # Read entire file once
                self.thread = threading.Thread(target=self._read_file, daemon=True)
                self.thread.start()
                
        except Exception as e:
            self.logger.error(f"Failed to start file input: {e}")
            self.running = False
            raise
    
    def stop(self):
        """Stop reading the file."""
        self.running = False
        
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        self.logger.info(f"File input stopped for {self.file_path}")
    
    def _read_file(self):
        """Read entire file once."""
        try:
            line_number = 0
            for line in self.file_handle:
                if not self.running:
                    break
                
                line = line.strip()
                if line:
                    line_number += 1
                    metadata = {
                        'source_file': self.file_path,
                        'line_number': line_number,
                        'read_at': datetime.utcnow().isoformat() + 'Z'
                    }
                    
                    self._handle_message(line, metadata)
            
            self.logger.info(f"Finished reading {line_number} lines from {self.file_path}")
            
        except Exception as e:
            self.logger.error(f"Error reading file {self.file_path}: {e}")
        finally:
            self.running = False
    
    def _follow_file(self):
        """Follow file for new lines (tail -f behavior)."""
        line_number = 0
        
        try:
            while self.running:
                # Check if file was rotated
                if self._file_rotated():
                    self._reopen_file()
                
                line = self.file_handle.readline()
                
                if line:
                    line = line.strip()
                    if line:
                        line_number += 1
                        metadata = {
                            'source_file': self.file_path,
                            'line_number': line_number,
                            'read_at': datetime.utcnow().isoformat() + 'Z'
                        }
                        
                        self._handle_message(line, metadata)
                    
                    # Update position
                    self.last_position = self.file_handle.tell()
                else:
                    # No new data, sleep briefly
                    time.sleep(0.1)
                    
        except Exception as e:
            self.logger.error(f"Error following file {self.file_path}: {e}")
        finally:
            self.running = False
    
    def _file_rotated(self) -> bool:
        """Check if file was rotated."""
        try:
            # Get current file stats
            current_stat = os.stat(self.file_path)
            file_stat = os.fstat(self.file_handle.fileno())
            
            # Check if it's the same file
            return (current_stat.st_ino != file_stat.st_ino or 
                    current_stat.st_dev != file_stat.st_dev or
                    current_stat.st_size < self.last_position)
        except (OSError, AttributeError):
            return True
    
    def _reopen_file(self):
        """Reopen file after rotation."""
        try:
            self.logger.info(f"File rotation detected, reopening {self.file_path}")
            
            if self.file_handle:
                self.file_handle.close()
            
            # Wait a bit for the new file to be created
            time.sleep(0.5)
            
            self.file_handle = open(self.file_path, 'r', encoding='utf-8', errors='replace')
            self.last_position = 0
            
        except Exception as e:
            self.logger.error(f"Error reopening file {self.file_path}: {e}")
            self.running = False
    
    def _handle_message(self, message: str, metadata: Dict[str, Any]):
        """Handle a line from the file."""
        try:
            if self.message_handler:
                self.message_handler(message, metadata)
        except Exception as e:
            self.logger.error(f"Error handling file message: {e}")

class FileInputManager:
    """Manager for multiple file inputs."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize file input manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.file_inputs = []
        self.message_handler = None
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def start(self, message_handler: Callable[[str, Dict[str, Any]], None]):
        """
        Start configured file inputs.
        
        Args:
            message_handler: Function to handle received messages
        """
        self.message_handler = message_handler
        
        # Get file configurations
        file_configs = self.config.get('files', [])
        if isinstance(file_configs, str):
            # Single file path
            file_configs = [{'path': file_configs}]
        elif isinstance(file_configs, list) and len(file_configs) > 0 and isinstance(file_configs[0], str):
            # List of file paths
            file_configs = [{'path': path} for path in file_configs]
        
        # Start file inputs
        for file_config in file_configs:
            if isinstance(file_config, dict) and 'path' in file_config:
                try:
                    file_input = FileInput(
                        file_path=file_config['path'],
                        follow=file_config.get('follow', False),
                        start_from_end=file_config.get('start_from_end', True)
                    )
                    file_input.start(message_handler)
                    self.file_inputs.append(file_input)
                    
                except Exception as e:
                    self.logger.error(f"Failed to start file input for {file_config['path']}: {e}")
        
        self.logger.info(f"File input manager started with {len(self.file_inputs)} inputs")
    
    def stop(self):
        """Stop all file inputs."""
        for file_input in self.file_inputs:
            file_input.stop()
        
        self.file_inputs.clear()
        self.logger.info("File input manager stopped")

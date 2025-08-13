"""
Elasticsearch connector for StreamLiner.
Sends parsed events to Elasticsearch clusters.
"""

import json
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from urllib.parse import urljoin

class ElasticsearchConnector:
    """Connector for sending events to Elasticsearch."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Elasticsearch connector.
        
        Args:
            config: Elasticsearch configuration
        """
        self.config = config
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 9200)
        self.scheme = config.get('scheme', 'http')
        self.index = config.get('index', 'logs')
        self.username = config.get('username')
        self.password = config.get('password')
        self.api_key = config.get('api_key')
        self.ca_cert = config.get('ca_cert')
        self.verify_ssl = config.get('verify_ssl', True)
        self.timeout = config.get('timeout', 30)
        self.batch_size = config.get('batch_size', 100)
        self.flush_interval = config.get('flush_interval', 5)  # seconds
        
        # Build base URL
        self.base_url = f"{self.scheme}://{self.host}:{self.port}"
        
        # Setup authentication
        self.auth = None
        self.headers = {'Content-Type': 'application/json'}
        
        if self.api_key:
            self.headers['Authorization'] = f'ApiKey {self.api_key}'
        elif self.username and self.password:
            self.auth = (self.username, self.password)
        
        # Batch processing
        self.batch = []
        self.last_flush = datetime.utcnow()
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Test connection on initialization
        self._test_connection()
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """
        Send a single event to Elasticsearch.
        
        Args:
            event: ECS-formatted event
            
        Returns:
            Success status
        """
        try:
            # Add to batch
            self.batch.append(event)
            
            # Check if we should flush
            if (len(self.batch) >= self.batch_size or 
                (datetime.utcnow() - self.last_flush).total_seconds() >= self.flush_interval):
                return self.flush_batch()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding event to batch: {e}")
            return False
    
    def flush_batch(self) -> bool:
        """
        Flush current batch to Elasticsearch.
        
        Returns:
            Success status
        """
        if not self.batch:
            return True
        
        try:
            # Prepare bulk request
            bulk_body = []
            for event in self.batch:
                # Index action
                index_action = {
                    "index": {
                        "_index": self._get_index_name(event),
                        "_type": "_doc"
                    }
                }
                bulk_body.append(json.dumps(index_action))
                bulk_body.append(json.dumps(event))
            
            bulk_data = '\n'.join(bulk_body) + '\n'
            
            # Send bulk request
            url = urljoin(self.base_url, '/_bulk')
            response = requests.post(
                url,
                data=bulk_data,
                headers=self.headers,
                auth=self.auth,
                timeout=self.timeout,
                verify=self.verify_ssl if self.ca_cert else self.verify_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Check for errors in bulk response
                if result.get('errors'):
                    error_count = 0
                    for item in result.get('items', []):
                        if 'index' in item and item['index'].get('error'):
                            error_count += 1
                            self.logger.error(f"Bulk index error: {item['index']['error']}")
                    
                    if error_count > 0:
                        self.logger.warning(f"Bulk request had {error_count} errors out of {len(self.batch)} events")
                
                self.logger.info(f"Successfully sent {len(self.batch)} events to Elasticsearch")
                
                # Clear batch
                self.batch.clear()
                self.last_flush = datetime.utcnow()
                return True
            else:
                self.logger.error(f"Elasticsearch bulk request failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error flushing batch to Elasticsearch: {e}")
            return False
    
    def _get_index_name(self, event: Dict[str, Any]) -> str:
        """
        Get index name for event, supporting date-based indices.
        
        Args:
            event: Event data
            
        Returns:
            Index name
        """
        base_index = self.index
        
        # Support date-based indices
        if self.config.get('date_based_index', False):
            try:
                timestamp = event.get('@timestamp', datetime.utcnow().isoformat() + 'Z')
                date_str = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).strftime('%Y.%m.%d')
                return f"{base_index}-{date_str}"
            except Exception:
                pass
        
        return base_index
    
    def _test_connection(self):
        """Test connection to Elasticsearch."""
        try:
            url = urljoin(self.base_url, '/')
            response = requests.get(
                url,
                headers={'Content-Type': 'application/json'},
                auth=self.auth,
                timeout=10,
                verify=self.verify_ssl if self.ca_cert else self.verify_ssl
            )
            
            if response.status_code == 200:
                cluster_info = response.json()
                self.logger.info(f"Connected to Elasticsearch cluster: {cluster_info.get('cluster_name', 'unknown')}")
                self.logger.info(f"Elasticsearch version: {cluster_info.get('version', {}).get('number', 'unknown')}")
            else:
                self.logger.warning(f"Elasticsearch connection test returned: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Failed to test Elasticsearch connection: {e}")
    
    def create_index_template(self, template_name: str = None) -> bool:
        """
        Create an index template for ECS compliance.
        
        Args:
            template_name: Template name (defaults to index name)
            
        Returns:
            Success status
        """
        if not template_name:
            template_name = f"{self.index}-template"
        
        # ECS-compliant index template
        template = {
            "index_patterns": [f"{self.index}*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "index.mapping.total_fields.limit": 2000
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "message": {"type": "text"},
                        "event": {
                            "properties": {
                                "dataset": {"type": "keyword"},
                                "module": {"type": "keyword"},
                                "kind": {"type": "keyword"},
                                "category": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "outcome": {"type": "keyword"},
                                "ingested": {"type": "date"}
                            }
                        },
                        "host": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "ip": {"type": "ip"},
                                "hostname": {"type": "keyword"},
                                "os": {
                                    "properties": {
                                        "name": {"type": "keyword"},
                                        "kernel": {"type": "keyword"}
                                    }
                                }
                            }
                        },
                        "source": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "long"}
                            }
                        },
                        "destination": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "long"}
                            }
                        },
                        "network": {
                            "properties": {
                                "protocol": {"type": "keyword"},
                                "transport": {"type": "keyword"}
                            }
                        },
                        "user": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "id": {"type": "keyword"}
                            }
                        },
                        "process": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "pid": {"type": "long"}
                            }
                        },
                        "http": {
                            "properties": {
                                "request": {
                                    "properties": {
                                        "method": {"type": "keyword"}
                                    }
                                },
                                "response": {
                                    "properties": {
                                        "status_code": {"type": "long"}
                                    }
                                }
                            }
                        },
                        "url": {
                            "properties": {
                                "path": {"type": "keyword"}
                            }
                        },
                        "user_agent": {
                            "properties": {
                                "original": {"type": "text"}
                            }
                        },
                        "log": {
                            "properties": {
                                "level": {"type": "keyword"},
                                "source": {
                                    "properties": {
                                        "type": {"type": "keyword"},
                                        "pattern": {"type": "keyword"}
                                    }
                                }
                            }
                        },
                        "labels": {"type": "object"},
                        "error": {
                            "properties": {
                                "message": {"type": "text"}
                            }
                        }
                    }
                }
            }
        }
        
        try:
            url = urljoin(self.base_url, f'/_index_template/{template_name}')
            response = requests.put(
                url,
                json=template,
                headers=self.headers,
                auth=self.auth,
                timeout=self.timeout,
                verify=self.verify_ssl if self.ca_cert else self.verify_ssl
            )
            
            if response.status_code in [200, 201]:
                self.logger.info(f"Successfully created index template: {template_name}")
                return True
            else:
                self.logger.error(f"Failed to create index template: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error creating index template: {e}")
            return False
    
    def close(self):
        """Close connector and flush any remaining events."""
        if self.batch:
            self.flush_batch()
        self.logger.info("Elasticsearch connector closed")

import os
import yaml
import json
import logging

logger = logging.getLogger("config_drift_detector.sample_data")

INTENDED_APP_YAML = """# Server Configurations
server:
  replicas: 3
  ssl: true
  port: 443
  api_keys: "prod-secret-key-12345"

# Database Configurations
database:
  backup: true
  replication: true
  max_connections: 50

# Application Logging
logging:
  level: "info"
  metrics: true

# UI Configurations
ui:
  theme: "dark"
"""

ACTUAL_APP_YAML = """# Server Configurations
server:
  replicas: 1
  ssl: false
  port: 8080
  api_keys: "prod-secret-key-12345"

# Database Configurations
database:
  backup: false
  replication: false

# Application Logging
logging:
  level: "debug"
  metrics: false

# UI Configurations
ui:
  theme: "light"
"""

INTENDED_DB_JSON = {
    "database": {
        "host": "db.production.local",
        "port": 5432,
        "encryption": {
            "enabled": True,
            "algorithm": "AES-256"
        }
    },
    "security": {
        "firewall": {
            "enabled": True,
            "allowed_ips": ["10.0.0.0/8", "192.168.1.0/24"]
        }
    },
    "caching": {
        "redis_host": "cache.production.local",
        "port": "6379"
    }
}

ACTUAL_DB_JSON = {
    "database": {
        "host": "db.staging.local",
        "port": 5432,
        "encryption": {
            "enabled": False
        }
    },
    "security": {
        "firewall": {
            "enabled": False,
            "allowed_ips": ["0.0.0.0/0"]
        }
    },
    "caching": {
        "redis_host": "cache.staging.local",
        "port": 6379
    }
}

def generate_sample_data(base_dir: str) -> tuple[str, str]:
    """Generates sample directories and files for demo config drift comparisons.
    
    Args:
        base_dir: Directory where 'demo_configs' should be created.
        
    Returns:
        A tuple of (intended_dir_path, actual_dir_path).
    """
    demo_dir = os.path.join(base_dir, "demo_configs")
    intended_dir = os.path.join(demo_dir, "intended")
    actual_dir = os.path.join(demo_dir, "actual")
    
    # Create folders if they don't exist
    os.makedirs(intended_dir, exist_ok=True)
    os.makedirs(actual_dir, exist_ok=True)
    
    # Write YAML sample files
    with open(os.path.join(intended_dir, "app.yaml"), "w", encoding="utf-8") as f:
        f.write(INTENDED_APP_YAML)
        
    with open(os.path.join(actual_dir, "app.yaml"), "w", encoding="utf-8") as f:
        f.write(ACTUAL_APP_YAML)
        
    # Write JSON sample files
    with open(os.path.join(intended_dir, "db.json"), "w", encoding="utf-8") as f:
        json.dump(INTENDED_DB_JSON, f, indent=2)
        
    with open(os.path.join(actual_dir, "db.json"), "w", encoding="utf-8") as f:
        json.dump(ACTUAL_DB_JSON, f, indent=2)
        
    logger.info(f"Sample data generated successfully at: {demo_dir}")
    return intended_dir, actual_dir

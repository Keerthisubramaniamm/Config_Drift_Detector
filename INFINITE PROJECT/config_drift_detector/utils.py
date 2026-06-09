import json
import logging
import os
from typing import Any, Dict, Optional, Tuple
import yaml

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("config_drift_detector.utils")

# Severity Keywords
SEVERITY_KEYWORDS = {
    "Critical": [
        "authentication", "authorization", "encryption", "security", 
        "firewall", "access_control", "ssl", "tls", "api_keys"
    ],
    "High": [
        "database", "replication", "backup", "load_balancer", 
        "network", "storage"
    ],
    "Medium": [
        "logging", "monitoring", "caching", "metrics"
    ],
    "Low": [
        "ui", "theme", "display", "dashboard"
    ]
}

def load_config_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Loads a JSON or YAML configuration file and returns it as a dictionary.
    
    Args:
        file_path: Absolute or relative path to the configuration file.
        
    Returns:
        A dictionary representation of the config, or None if loading failed.
    """
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return None
        
    _, ext = os.path.splitext(file_path.lower())
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            if ext == ".json":
                return json.load(f)
            elif ext in (".yaml", ".yml"):
                return yaml.safe_load(f)
            else:
                logger.error(f"Unsupported file format: {ext} for file: {file_path}")
                return None
    except Exception as e:
        logger.error(f"Error loading configuration file {file_path}: {str(e)}")
        return None

def clean_deepdiff_path(path_str: str) -> str:
    """Parses standard DeepDiff paths into a clean dotted path format.
    
    Example:
        "root['server']['ssl']" -> "server.ssl"
        "root['database']['ports'][0]" -> "database.ports.0"
        
    Args:
        path_str: DeepDiff path string.
        
    Returns:
        Dotted path string.
    """
    if not path_str or path_str == "root":
        return "root"
        
    # Remove leading 'root'
    if path_str.startswith("root"):
        path_str = path_str[4:]
        
    # Replace brackets and quotes
    # 'root[\'server\']' -> '.server'
    path_str = path_str.replace("['", ".").replace("']", "")
    path_str = path_str.replace("[", ".").replace("]", "")
    
    # Strip any leading dots
    if path_str.startswith("."):
        path_str = path_str[1:]
        
    return path_str

def classify_severity(config_path: str) -> str:
    """Classifies risk severity based on keywords present in the config path.
    
    Args:
        config_path: Dotted configuration path (e.g. 'server.ssl').
        
    Returns:
        Severity string ('Critical', 'High', 'Medium', 'Low').
    """
    path_lower = config_path.lower()
    
    # Check Critical keywords
    for kw in SEVERITY_KEYWORDS["Critical"]:
        if kw in path_lower:
            return "Critical"
            
    # Check High keywords
    for kw in SEVERITY_KEYWORDS["High"]:
        if kw in path_lower:
            return "High"
            
    # Check Medium keywords
    for kw in SEVERITY_KEYWORDS["Medium"]:
        if kw in path_lower:
            return "Medium"
            
    # Check Low keywords
    for kw in SEVERITY_KEYWORDS["Low"]:
        if kw in path_lower:
            return "Low"
            
    # Fallback to Medium if no keyword matches
    return "Medium"

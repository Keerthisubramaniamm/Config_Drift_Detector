import logging
import json
from typing import Any, Dict, List, Optional
from deepdiff import DeepDiff
from utils import clean_deepdiff_path, classify_severity, load_config_file

logger = logging.getLogger("config_drift_detector.drift_detector")

def get_value_by_path(config: Any, clean_path: str) -> Any:
    """Traverses a configuration object (dict or list) using a cleaned dotted path.
    
    Args:
        config: The root dict or list.
        clean_path: Dotted path, e.g. "server.ssl" or "database.ports.0".
        
    Returns:
        The resolved value, or None if path is invalid.
    """
    if not clean_path or clean_path == "root":
        return config
        
    parts = clean_path.split(".")
    current = config
    
    for part in parts:
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                return None
        elif isinstance(current, list):
            try:
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return None
            except ValueError:
                return None
        else:
            return None
            
    return current

def format_value(val: Any) -> str:
    """Formats a value of any type to a string representation for database storage.
    
    Args:
        val: The value to format.
        
    Returns:
        A string representation (JSON string for complex types).
    """
    if val is None:
        return "None"
    if isinstance(val, (dict, list)):
        try:
            return json.dumps(val, indent=2)
        except Exception:
            return str(val)
    if isinstance(val, bool):
        return str(val).lower() # standard True/False to true/false
    return str(val)

def detect_drift(intended_config: Dict[str, Any], actual_config: Dict[str, Any], file_name: str) -> List[Dict[str, Any]]:
    """Compares intended config against actual config and returns detected drifts.
    
    Args:
        intended_config: Dictionary representing the expected configuration.
        actual_config: Dictionary representing the deployed configuration.
        file_name: Name of the config file.
        
    Returns:
        A list of dictionaries containing detailed drift metrics:
        [
            {
                "file_name": str,
                "config_path": str,
                "intended_value": str,
                "actual_value": str,
                "drift_type": str,
                "severity": str
            },
            ...
        ]
    """
    logger.info(f"Running drift detection for file: {file_name}")
    drifts = []
    
    # We use DeepDiff to compare the configurations
    # ignore_order=True handles arrays where ordering might change but contents are equivalent
    ddiff = DeepDiff(intended_config, actual_config, ignore_order=True)
    
    # 1. Missing Keys (Removed from actual)
    if "dictionary_item_removed" in ddiff:
        for path_str in ddiff["dictionary_item_removed"]:
            clean_path = clean_deepdiff_path(path_str)
            raw_intended = get_value_by_path(intended_config, clean_path)
            
            drifts.append({
                "file_name": file_name,
                "config_path": clean_path,
                "intended_value": format_value(raw_intended),
                "actual_value": "Missing",
                "drift_type": "Missing Key",
                "severity": classify_severity(clean_path)
            })
            
    # 2. Added Keys (New in actual)
    if "dictionary_item_added" in ddiff:
        for path_str in ddiff["dictionary_item_added"]:
            clean_path = clean_deepdiff_path(path_str)
            raw_actual = get_value_by_path(actual_config, clean_path)
            
            drifts.append({
                "file_name": file_name,
                "config_path": clean_path,
                "intended_value": "Missing",
                "actual_value": format_value(raw_actual),
                "drift_type": "Added Key",
                "severity": classify_severity(clean_path)
            })
            
    # 3. Modified Values (Same key, different value)
    if "values_changed" in ddiff:
        for path_str, change_details in ddiff["values_changed"].items():
            clean_path = clean_deepdiff_path(path_str)
            intended_val = change_details.get("old_value")
            actual_val = change_details.get("new_value")
            
            drifts.append({
                "file_name": file_name,
                "config_path": clean_path,
                "intended_value": format_value(intended_val),
                "actual_value": format_value(actual_val),
                "drift_type": "Modified Value",
                "severity": classify_severity(clean_path)
            })
            
    # 4. Data Type Changes (Same key, different type)
    if "type_changes" in ddiff:
        for path_str, change_details in ddiff["type_changes"].items():
            clean_path = clean_deepdiff_path(path_str)
            intended_val = change_details.get("old_value")
            actual_val = change_details.get("new_value")
            old_type = change_details.get("old_type").__name__ if change_details.get("old_type") else "unknown"
            new_type = change_details.get("new_type").__name__ if change_details.get("new_type") else "unknown"
            
            drifts.append({
                "file_name": file_name,
                "config_path": clean_path,
                "intended_value": f"{format_value(intended_val)} ({old_type})",
                "actual_value": f"{format_value(actual_val)} ({new_type})",
                "drift_type": "Data Type Change",
                "severity": classify_severity(clean_path)
            })
            
    logger.info(f"Drift detection complete. Found {len(drifts)} drifts in {file_name}.")
    return drifts

def compare_config_folders(intended_dir: str, actual_dir: str) -> Dict[str, Any]:
    """Scans and compares all files within intended and actual folders.
    
    Matches files with same names (JSON, YAML).
    
    Args:
        intended_dir: Folder containing intended configs.
        actual_dir: Folder containing actual configs.
        
    Returns:
        A dict containing:
        - "files_checked": Total files evaluated.
        - "drifts": List of all detected drifts.
        - "errors": List of file loading/parsing errors.
    """
    import os
    
    results = {
        "files_checked": 0,
        "drifts": [],
        "errors": []
    }
    
    if not os.path.exists(intended_dir) or not os.path.exists(actual_dir):
        results["errors"].append("One or both folders do not exist.")
        return results
        
    intended_files = os.listdir(intended_dir)
    actual_files = os.listdir(actual_dir)
    
    # We match case-insensitively
    matched_files = []
    for f_int in intended_files:
        _, ext = os.path.splitext(f_int.lower())
        if ext not in (".json", ".yaml", ".yml"):
            continue
            
        for f_act in actual_files:
            if f_int.lower() == f_act.lower():
                matched_files.append((f_int, f_act))
                break
                
    if not matched_files:
        results["errors"].append("No matching configuration files found (JSON/YAML).")
        return results
        
    for f_int, f_act in matched_files:
        int_path = os.path.join(intended_dir, f_int)
        act_path = os.path.join(actual_dir, f_act)
        
        int_conf = load_config_file(int_path)
        act_conf = load_config_file(act_path)
        
        if int_conf is None or act_conf is None:
            results["errors"].append(f"Failed to load or parse '{f_int}'. Check syntax.")
            continue
            
        results["files_checked"] += 1
        file_drifts = detect_drift(int_conf, act_conf, f_int)
        results["drifts"].extend(file_drifts)
        
    return results

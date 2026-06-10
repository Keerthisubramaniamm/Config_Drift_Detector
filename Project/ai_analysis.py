import json
import logging
import os
from typing import Any, Dict, Optional
from groq import Groq

logger = logging.getLogger("config_drift_detector.ai_analysis")

def generate_mock_analysis(
    file_name: str,
    config_path: str,
    intended_value: str,
    actual_value: str,
    severity: str
) -> Dict[str, str]:
    """Generates a high-quality mockup of the AI analysis.
    
    Used when no Groq API key is configured in the environment.
    """
    path_lower = config_path.lower()
    
    # Custom templates based on config keywords
    if "ssl" in path_lower or "tls" in path_lower:
        return {
            "technical_impact": f"Plaintext transmission is active for {file_name} because SSL/TLS was switched from '{intended_value}' to '{actual_value}'. Traffic is not encrypted.",
            "business_impact": "Swapping from HTTPS/TLS to HTTP exposes user traffic, violates data privacy regulations (GDPR/HIPAA), and significantly degrades customer trust.",
            "security_impact": "Active session tokens, credentials, and API payloads are vulnerable to eavesdropping and Man-in-the-Middle (MITM) hijacking.",
            "risk_rating": "Critical",
            "recommendation": "1. Set the ssl/tls parameter to true.\n2. Ensure valid SSL/TLS certificates are bound to your ingress or server gateway.\n3. Enforce HTTP-to-HTTPS redirection rules."
        }
    elif "backup" in path_lower:
        return {
            "technical_impact": f"Automated configuration backups are disabled ('{actual_value}' instead of '{intended_value}'). Deployed environments lack state snapshotting.",
            "business_impact": "In the event of hardware or database failure, data recovery will be delayed or impossible, leading to prolonged operational downtime.",
            "security_impact": "Losing database snapshots compromises the availability pillar of the CIA triad, limiting recovery capabilities from ransomware attacks.",
            "risk_rating": "High",
            "recommendation": "1. Restore the 'database.backup' setting to true in your active configurations.\n2. Verify that backup cron schedules are running and writing to secure S3 buckets."
        }
    elif "replicas" in path_lower:
        return {
            "technical_impact": f"Cluster scaling counts dropped from {intended_value} to {actual_value}, reducing available containers to service client workloads.",
            "business_impact": "Decreased throughput capability will lead to application latency, server queue saturation, and potential page failures under normal peak traffic.",
            "security_impact": "Reduced redundancy leaves the cluster highly vulnerable to resource exhaustion and Denial of Service (DoS) attacks.",
            "risk_rating": "High",
            "recommendation": "1. Re-scale the server replica set to 3 using horizontal scaling parameters.\n2. Inspect autoscale triggers to confirm why replicas scaled down."
        }
    elif "firewall" in path_lower or "allowed_ips" in path_lower:
        return {
            "technical_impact": f"Firewall policies were opened to '{actual_value}' from the restrictive policy '{intended_value}'. All network interface constraints are dropped.",
            "business_impact": "Exposing internal administration ports or database endpoints directly to the public web will lead to compliance violations and data extraction risks.",
            "security_impact": "Attackers can perform network scans, exploit vulnerabilities on raw ports, and run brute-force attacks directly against backend services.",
            "risk_rating": "Critical",
            "recommendation": "1. Immediately revert 'allowed_ips' to the internal IP subnet range.\n2. Enable firewall checks to drop all traffic originating outside the trusted range."
        }
    elif "level" in path_lower:
        return {
            "technical_impact": f"Logging level altered from '{intended_value}' to '{actual_value}'. System logs will record verbose messages, flooding system disks.",
            "business_impact": "Verbose debug logs can degrade disk write throughput and inflate cloud storage costs due to excessive log creation.",
            "security_impact": "Log injection risks increase, and internal variables or secrets might accidentally be printed into public server outputs.",
            "risk_rating": "Medium",
            "recommendation": "1. Change the configuration 'logging.level' back to 'info' or 'warn' for production.\n2. Verify log rotation policies prevent disk space exhaustion."
        }
        
    # Generic template for other keys
    return {
        "technical_impact": f"The parameter '{config_path}' in configuration file '{file_name}' drifted from expected value '{intended_value}' to '{actual_value}'.",
        "business_impact": f"Uncoordinated changes to application properties can lead to inconsistent application states and drift from the engineering source of truth.",
        "security_impact": f"Drifts bypass infrastructure-as-code review boards, creating unverified security baselines in active production runtime.",
        "risk_rating": severity,
        "recommendation": f"1. Audit the change to see if it was manual or automatic.\n2. Synchronize '{config_path}' back to '{intended_value}' or update the intended template if the change was approved."
    }

def analyze_drift_with_ai(
    file_name: str,
    config_path: str,
    intended_value: str,
    actual_value: str,
    severity: str,
    model_name: str = "llama-3.1-8b-instant"
) -> Dict[str, str]:
    """Analyzes a configuration drift using the Groq API.
    
    Loads the GROQ_API_KEY from environment variables. If missing or the request fails,
    it falls back to offline mock analysis.
    
    Args:
        file_name: The configuration filename.
        config_path: The dotted configuration key path.
        intended_value: Expected configuration value.
        actual_value: Deployed configuration value.
        severity: Preset keyword severity.
        model_name: LLM model identifier.
        
    Returns:
        A dictionary containing:
        - "technical_impact"
        - "business_impact"
        - "security_impact"
        - "risk_rating"
        - "recommendation"
    """
    api_key = ""

    if not api_key:
        logger.info("GROQ_API_KEY environment variable not configured. Using offline mock analysis.")
        return generate_mock_analysis(file_name, config_path, intended_value, actual_value, severity)
        
    prompt = f"""
    Analyze the following configuration drift in our environment:
    
    File: {file_name}
    Path: {config_path}
    Expected Value: {intended_value}
    Actual Value: {actual_value}
    Severity: {severity}
    
    Generate detailed and practical summaries for:
    1. Technical Impact (How this affects systems, capacity, and deployment health)
    2. Business Impact (How this affects end users, cost, SLAs, and brand compliance)
    3. Security Impact (Data protection, vulnerabilities, and cyber attack risks)
    4. Risk Rating (Categorize as 'Critical', 'High', 'Medium', or 'Low')
    5. Recommended Fix (A brief list of operations to correct the drift)
    
    Your response MUST be a valid JSON object. Do not include markdown code block syntax (like ```json). Return ONLY the raw JSON string with these exact keys:
    {{
        "technical_impact": "string",
        "business_impact": "string",
        "security_impact": "string",
        "risk_rating": "string",
        "recommendation": "string"
    }}
    """
    
    try:
        client = Groq(api_key=api_key)
        
        # Call the chat completion endpoint
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system", 
                    "content": "You are a DevOps engineer and Cybersecurity auditor. You provide highly technical, precise, and practical drift assessments in JSON format."
                },
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2
        )
        
        response_text = completion.choices[0].message.content.strip()
        result = json.loads(response_text)
        
        # Verify all keys are present
        required_keys = ["technical_impact", "business_impact", "security_impact", "risk_rating", "recommendation"]
        for key in required_keys:
            if key not in result:
                result[key] = f"Information not provided by AI. Path context: {config_path}"
                
        logger.info("AI Analysis completed successfully via Groq.")
        return result
        
    except Exception as e:
        logger.error(f"Groq API error: {str(e)}. Falling back to mock generator.")
        return generate_mock_analysis(file_name, config_path, intended_value, actual_value, severity)

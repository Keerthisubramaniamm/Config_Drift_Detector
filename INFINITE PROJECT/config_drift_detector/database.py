import sqlite3
import os
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("config_drift_detector.database")

def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Establishes and returns a connection to the SQLite database.
    
    Args:
        db_path: Path to the SQLite database file.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Returns dictionaries/rows instead of tuples
    return conn

def init_db(db_path: str) -> None:
    """Initializes the database schema if tables do not exist.
    
    Args:
        db_path: Path to the SQLite database file.
    """
    logger.info(f"Initializing database at: {db_path}")
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # Create comparison_history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comparison_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_name TEXT NOT NULL,
            config_path TEXT NOT NULL,
            drift_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            intended_value TEXT,
            actual_value TEXT
        )
    """)
    
    # Create ai_analysis table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comparison_id INTEGER NOT NULL,
            technical_impact TEXT,
            business_impact TEXT,
            security_impact TEXT,
            risk_rating TEXT,
            recommendation TEXT,
            fallback_used INTEGER DEFAULT 0,
            FOREIGN KEY (comparison_id) REFERENCES comparison_history(id) ON DELETE CASCADE
        )
    """)

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT,
            notify_enabled BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Schema Migration: Add fallback_used column if it doesn't exist
    cursor.execute("PRAGMA table_info(ai_analysis)")
    columns = [col[1] for col in cursor.fetchall()]
    if "fallback_used" not in columns:
        try:
            cursor.execute("ALTER TABLE ai_analysis ADD COLUMN fallback_used INTEGER DEFAULT 0")
            logger.info("Migrated SQLite database: Added fallback_used column to ai_analysis table.")
        except Exception as e:
            logger.error(f"Migration error adding fallback_used: {str(e)}")

    # Schema Migration: Add user_id to comparison_history if it doesn't exist
    cursor.execute("PRAGMA table_info(comparison_history)")
    comparison_columns = [col[1] for col in cursor.fetchall()]
    if "user_id" not in comparison_columns:
        try:
            cursor.execute("ALTER TABLE comparison_history ADD COLUMN user_id INTEGER DEFAULT NULL")
            logger.info("Migrated SQLite database: Added user_id column to comparison_history table.")
        except Exception as e:
            logger.error(f"Migration error adding user_id: {str(e)}")
            
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")

def save_drift_entry(
    db_path: str,
    timestamp: str,
    file_name: str,
    config_path: str,
    drift_type: str,
    severity: str,
    intended_value: str,
    actual_value: str,
    user_id: int = None
) -> int:
    """Saves a single drift entry into the comparison_history table.
    
    Args:
        db_path: Path to the database.
        timestamp: ISO-format timestamp of the scan.
        file_name: Config filename.
        config_path: Dotted key path.
        drift_type: Missing Key, Added Key, Modified Value, Type Change.
        severity: Critical, High, Medium, Low.
        intended_value: String representation of expected value.
        actual_value: String representation of actual value.
        
    Returns:
        The ID of the inserted row.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO comparison_history (
            timestamp, file_name, config_path, drift_type, severity, intended_value, actual_value, user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, file_name, config_path, drift_type, severity, intended_value, actual_value, user_id))
    
    inserted_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return inserted_id

def save_ai_analysis(
    db_path: str,
    comparison_id: int,
    technical_impact: str,
    business_impact: str,
    security_impact: str,
    risk_rating: str,
    recommendation: str,
    fallback_used: int = 0
) -> int:
    """Saves AI impact analysis results for a given drift item.
    
    Args:
        db_path: Path to the database.
        comparison_id: ID of the corresponding row in comparison_history.
        technical_impact: AI summary of technical risk.
        business_impact: AI summary of business risk.
        security_impact: AI summary of security risk.
        risk_rating: AI risk score (e.g. High, Medium, Low).
        recommendation: AI step-by-step fix guide.
        fallback_used: 1 if fallback analysis was used, 0 otherwise.
        
    Returns:
        The ID of the inserted row.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO ai_analysis (
            comparison_id, technical_impact, business_impact, security_impact, risk_rating, recommendation, fallback_used
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (comparison_id, technical_impact, business_impact, security_impact, risk_rating, recommendation, fallback_used))
    
    inserted_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return inserted_id

def get_scan_history_summary(db_path: str, user_id: int = None) -> List[Dict[str, Any]]:
    """Returns a list of scans grouped by timestamp.
    
    Summarizes total files checked, total drifts, and maximum severity.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    query = """
        SELECT 
            timestamp, 
            COUNT(DISTINCT file_name) as files_count, 
            COUNT(id) as total_drifts,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium_count,
            SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low_count
        FROM comparison_history
    """
    params = []
    if user_id is not None:
        query += " WHERE user_id = ?"
        params.append(user_id)
    query += " GROUP BY timestamp ORDER BY timestamp DESC"
    cursor.execute(query, params)
    
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_scan_history_by_file(db_path: str, user_id: int = None) -> List[Dict[str, Any]]:
    """Returns detailed scan history rows grouped by Timestamp and File Name.
    
    This matches the specific requested Scan History columns:
    Timestamp, File Name, Severity, Drift Count.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    query = """
        SELECT 
            timestamp,
            file_name,
            COUNT(id) as drift_count,
            CASE 
                WHEN SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) > 0 THEN 'Critical'
                WHEN SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) > 0 THEN 'High'
                WHEN SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) > 0 THEN 'Medium'
                ELSE 'Low'
            END as max_severity
        FROM comparison_history
    """
    params = []
    if user_id is not None:
        query += " WHERE user_id = ?"
        params.append(user_id)
    query += " GROUP BY timestamp, file_name ORDER BY timestamp DESC, file_name ASC"
    cursor.execute(query, params)
    
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_drill_down_drifts(db_path: str, timestamp: str, file_name: Optional[str] = None, user_id: int = None) -> List[Dict[str, Any]]:
    """Fetches all detailed drift entries for a given timestamp (and optional file).
    
    Joins with AI analysis reports if they exist.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    query = """
        SELECT 
            h.id as drift_id,
            h.timestamp,
            h.file_name,
            h.config_path,
            h.drift_type,
            h.severity,
            h.intended_value,
            h.actual_value,
            a.technical_impact,
            a.business_impact,
            a.security_impact,
            a.risk_rating,
            a.recommendation,
            a.fallback_used
        FROM comparison_history h
        LEFT JOIN ai_analysis a ON h.id = a.comparison_id
        WHERE h.timestamp = ?
    """
    
    params = [timestamp]
    if file_name:
        query += " AND h.file_name = ?"
        params.append(file_name)
    if user_id is not None:
        query += " AND h.user_id = ?"
        params.append(user_id)
        
    query += " ORDER BY h.severity DESC, h.config_path ASC"
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def search_drifts(
    db_path: str,
    file_name: Optional[str] = None,
    severity: Optional[str] = None,
    drift_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user_id: int = None
) -> List[Dict[str, Any]]:
    """Queries SQLite with dynamic search criteria.
    
    Allows filtering by File Name, Severity, Drift Type, and Date Range.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    query = """
        SELECT 
            h.id as drift_id,
            h.timestamp,
            h.file_name,
            h.config_path,
            h.drift_type,
            h.severity,
            h.intended_value,
            h.actual_value,
            a.technical_impact,
            a.business_impact,
            a.security_impact,
            a.risk_rating,
            a.recommendation,
            a.fallback_used
        FROM comparison_history h
        LEFT JOIN ai_analysis a ON h.id = a.comparison_id
        WHERE 1=1
    """
    params = []
    
    if file_name:
        query += " AND h.file_name LIKE ?"
        params.append(f"%{file_name}%")
        
    if severity and severity != "All":
        query += " AND h.severity = ?"
        params.append(severity)
        
    if drift_type and drift_type != "All":
        query += " AND h.drift_type = ?"
        params.append(drift_type)
        
    if start_date:
        query += " AND date(h.timestamp) >= date(?)"
        params.append(start_date)
        
    if end_date:
        query += " AND date(h.timestamp) <= date(?)"
        params.append(end_date)
    if user_id is not None:
        query += " AND h.user_id = ?"
        params.append(user_id)
        
    query += " ORDER BY h.timestamp DESC, h.severity DESC"
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_analytics_metrics(db_path: str, user_id: int = None) -> Dict[str, Any]:
    """Computes high-level KPI cards and charting aggregates for the Analytics dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # 1. Total Files Checked
    # To get total files checked overall, we sum the unique file count per distinct scan timestamp
    cursor.execute("""
        SELECT SUM(files_in_scan) as total_checked FROM (
            SELECT COUNT(DISTINCT file_name) as files_in_scan 
            FROM comparison_history 
            GROUP BY timestamp
        )
    """)
    total_files_checked = cursor.fetchone()[0] or 0
    
    # 2. Total Drifts
    if user_id is not None:
        cursor.execute("SELECT COUNT(*) FROM comparison_history WHERE user_id = ?", (user_id,))
    else:
        cursor.execute("SELECT COUNT(*) FROM comparison_history")
    total_drifts = cursor.fetchone()[0] or 0
    
    # 3. Critical & High Drifts
    if user_id is not None:
        cursor.execute("SELECT COUNT(*) FROM comparison_history WHERE severity = 'Critical' AND user_id = ?", (user_id,))
    else:
        cursor.execute("SELECT COUNT(*) FROM comparison_history WHERE severity = 'Critical'")
    critical_drifts = cursor.fetchone()[0] or 0
    
    if user_id is not None:
        cursor.execute("SELECT COUNT(*) FROM comparison_history WHERE severity = 'High' AND user_id = ?", (user_id,))
    else:
        cursor.execute("SELECT COUNT(*) FROM comparison_history WHERE severity = 'High'")
    high_drifts = cursor.fetchone()[0] or 0
    
    # 4. Last Scan Time
    if user_id is not None:
        cursor.execute("SELECT MAX(timestamp) FROM comparison_history WHERE user_id = ?", (user_id,))
    else:
        cursor.execute("SELECT MAX(timestamp) FROM comparison_history")
    last_scan_time = cursor.fetchone()[0] or "N/A"
    
    # 5. Severity Distribution
    if user_id is not None:
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM comparison_history 
            WHERE user_id = ?
            GROUP BY severity
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM comparison_history 
            GROUP BY severity
        """)
    severity_dist = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    # 6. Drift Type Distribution
    if user_id is not None:
        cursor.execute("""
            SELECT drift_type, COUNT(*) as count 
            FROM comparison_history 
            WHERE user_id = ?
            GROUP BY drift_type
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT drift_type, COUNT(*) as count 
            FROM comparison_history 
            GROUP BY drift_type
        """)
    drift_type_dist = {row['drift_type']: row['count'] for row in cursor.fetchall()}
    
    # 7. Drift Trends Over Time (Scans grouped by date/timestamp)
    if user_id is not None:
        cursor.execute("""
            SELECT timestamp, COUNT(*) as count 
            FROM comparison_history 
            WHERE user_id = ?
            GROUP BY timestamp 
            ORDER BY timestamp ASC
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT timestamp, COUNT(*) as count 
            FROM comparison_history 
            GROUP BY timestamp 
            ORDER BY timestamp ASC
        """)
    drift_trends = [(row['timestamp'], row['count']) for row in cursor.fetchall()]
    
    # 8. Top Affected Files
    if user_id is not None:
        cursor.execute("""
            SELECT file_name, COUNT(*) as count 
            FROM comparison_history 
            WHERE user_id = ?
            GROUP BY file_name 
            ORDER BY count DESC 
            LIMIT 5
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT file_name, COUNT(*) as count 
            FROM comparison_history 
            GROUP BY file_name 
            ORDER BY count DESC 
            LIMIT 5
        """)
    top_files = [(row['file_name'], row['count']) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_files_checked": total_files_checked,
        "total_drifts": total_drifts,
        "critical_drifts": critical_drifts,
        "high_drifts": high_drifts,
        "last_scan_time": last_scan_time,
        "severity_dist": severity_dist,
        "drift_type_dist": drift_type_dist,
        "drift_trends": drift_trends,
        "top_files": top_files
    }


def get_user_by_email(db_path: str, email: str) -> Optional[Dict[str, Any]]:
    """Returns a user record by email address."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(db_path: str, user_id: int) -> Optional[Dict[str, Any]]:
    """Returns a user record by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(
    db_path: str,
    name: str,
    email: str,
    password_hash: str,
    notify_enabled: int = 1
) -> int:
    """Creates a new user account."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password_hash, notify_enabled) VALUES (?, ?, ?, ?)",
        (name.strip(), email.strip().lower(), password_hash, int(notify_enabled))
    )
    inserted_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return inserted_id


def update_user_profile(db_path: str, user_id: int, name: str, notify_enabled: bool) -> bool:
    """Updates a user's display name and notification preference."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET name = ?, notify_enabled = ? WHERE id = ?",
        (name.strip(), int(bool(notify_enabled)), user_id)
    )
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def update_user_password(db_path: str, user_id: int, password_hash: str) -> bool:
    """Updates a user's password hash."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (password_hash, user_id)
    )
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def clear_all_history(db_path: str, user_id: int = None) -> None:
    """Deletes scan history and AI analysis records.

    If `user_id` is provided, only the requested user's records are removed.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute("SELECT id FROM comparison_history WHERE user_id = ?", (user_id,))
        comparison_ids = [row[0] for row in cursor.fetchall()]
        if comparison_ids:
            cursor.executemany("DELETE FROM ai_analysis WHERE comparison_id = ?", [(cid,) for cid in comparison_ids])
        cursor.execute("DELETE FROM comparison_history WHERE user_id = ?", (user_id,))
    else:
        cursor.execute("DELETE FROM ai_analysis")
        cursor.execute("DELETE FROM comparison_history")
    conn.commit()
    conn.close()

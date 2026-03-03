"""
CORTEX - Database connection and session management.
"""

import sqlite3
from config import DATABASE


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database and create tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        -- Module 6 Enforcement Fields
        is_locked INTEGER DEFAULT 0,
        lock_until TEXT,
        lock_level INTEGER DEFAULT 0
    );
    """)

    # LOGIN ATTEMPTS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        device_info TEXT,
        status TEXT CHECK(status IN ('SUCCESS', 'FAIL')),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # USER BASELINE TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_baseline (
        user_id INTEGER PRIMARY KEY,
        login_start_hour INTEGER,
        login_end_hour INTEGER,
        known_ips TEXT,
        known_devices TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # THREAT ANALYSIS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        risk_score INTEGER,
        severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH')),
        triggered_rules TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # RISK MEMORY TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_memory (
        user_id INTEGER PRIMARY KEY,
        cumulative_risk INTEGER DEFAULT 0,
        event_count INTEGER DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # ADAPTIVE STATE TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS adaptive_state (
        user_id INTEGER PRIMARY KEY,
        tightened_start_hour INTEGER,
        tightened_end_hour INTEGER,
        active_until TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # -------------------------------
    # Module 6 - IP Lockdown Table
    # -------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ip_lockdowns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        lock_until TEXT NOT NULL,
        severity INTEGER,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()


def get_session():
    """Get database session."""
    return get_db_connection()


def close_session(conn):
    """Close database session."""
    conn.close()
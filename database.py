import sqlite3
import json
from datetime import datetime, timezone

DATABASE_NAME = "aegisapi.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    # Assessments table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            endpoints_found INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            endpoints_json TEXT DEFAULT '[]',
            checks_json TEXT DEFAULT '[]'
        )
    """)

    # Safely add new columns to existing databases
    cursor.execute("PRAGMA table_info(assessments)")
    existing_columns = [
        column["name"] for column in cursor.fetchall()
    ]

    if "endpoints_json" not in existing_columns:
        cursor.execute("""
            ALTER TABLE assessments
            ADD COLUMN endpoints_json TEXT DEFAULT '[]'
        """)

    if "checks_json" not in existing_columns:
        cursor.execute("""
            ALTER TABLE assessments
            ADD COLUMN checks_json TEXT DEFAULT '[]'
        """)

    # Findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            category TEXT,
            endpoint TEXT,
            method TEXT,
            issue TEXT,
            severity TEXT,
            evidence TEXT,
            FOREIGN KEY (assessment_id)
                REFERENCES assessments (assessment_id)
        )
    """)

    connection.commit()
    connection.close()


def save_assessment(target_url, results):

    connection = get_connection()
    cursor = connection.cursor()

    summary = results.get("summary", {})

    # Store original endpoints and security checks as JSON
    endpoints_json = json.dumps(
        results.get("endpoints", [])
    )

    checks_json = json.dumps(
        results.get("checks", [])
    )

    cursor.execute("""
        INSERT INTO assessments (
            target_url, scan_date, endpoints_found,
            findings_count, high_count, medium_count,
            low_count, info_count,
            endpoints_json, checks_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target_url,
        datetime.now(timezone.utc).isoformat(),
        summary.get("endpoints_found", 0),
        summary.get("findings_count", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
        summary.get("info", 0),
        endpoints_json,
        checks_json
    ))

    assessment_id = cursor.lastrowid

    # Store individual findings
    for finding in results.get("findings", []):

        cursor.execute("""
            INSERT INTO findings (
                assessment_id, category, endpoint,
                method, issue, severity, evidence
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            assessment_id,
            finding.get("category", ""),
            finding.get("endpoint", ""),
            finding.get("method", ""),
            finding.get("issue", ""),
            finding.get("severity", ""),
            finding.get("evidence", "")
        ))

    connection.commit()
    connection.close()

    return assessment_id


if __name__ == "__main__":
    initialize_database()
    print("AegisAPI database initialized successfully!")
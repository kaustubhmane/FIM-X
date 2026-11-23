import sqlite3
import os
from datetime import datetime


DB_PATH = "data/fimx.db"


def initialize_database():

    os.makedirs("data", exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER,
            last_modified TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_alerts (
            file_path TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_file(file_path, file_hash, file_size, last_modified):

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO files
        (file_path, file_hash, file_size, last_modified)
        VALUES (?, ?, ?, ?)
    """, (
        file_path,
        file_hash,
        file_size,
        last_modified
    ))

    connection.commit()
    connection.close()


def get_file(file_path):

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM files WHERE file_path = ?",
        (file_path,)
    )

    result = cursor.fetchone()

    connection.close()

    return result


def get_all_files():

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT file_path, file_hash
        FROM files
    """)

    results = cursor.fetchall()

    connection.close()

    return results


def log_event(event_type, file_path, old_hash=None, new_hash=None):

    timestamp = datetime.now().isoformat(timespec="seconds")

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO events
        (timestamp, event_type, file_path, old_hash, new_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (
        timestamp,
        event_type,
        file_path,
        old_hash,
        new_hash
    ))

    connection.commit()
    connection.close()

    

def should_log_event(event_type, file_path, new_hash=None):

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    if event_type == "MODIFIED":
        cursor.execute("""
            SELECT 1
            FROM events
            WHERE event_type = ?
              AND file_path = ?
              AND new_hash = ?
            LIMIT 1
        """, (event_type, file_path, new_hash))

    else:
        cursor.execute("""
            SELECT 1
            FROM events
            WHERE event_type = ?
              AND file_path = ?
            LIMIT 1
        """, (event_type, file_path))

    already_logged = cursor.fetchone() is not None
    connection.close()

    return not already_logged



def set_active_alert(
    event_type,
    file_path,
    old_hash=None,
    new_hash=None
):
    import os
    from datetime import datetime

    file_path = os.path.normpath(file_path)

    if event_type not in ("NEW", "MODIFIED", "DELETED"):
        raise ValueError("Invalid alert type")

    if not isinstance(file_path, str) or not file_path:
        raise ValueError("Invalid file path")

    # Prevent SHA-256 hashes from being stored as file paths.
    if (
        len(file_path) == 64
        and all(c in "0123456789abcdefABCDEF" for c in file_path)
    ):
        raise ValueError("A hash was provided instead of a file path")

    now = datetime.now().isoformat(timespec="seconds")

    connection = sqlite3.connect(DB_PATH)

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT event_type, old_hash, new_hash
            FROM active_alerts
            WHERE file_path = ?
        """, (file_path,))

        previous = cursor.fetchone()

        if previous is None:
            cursor.execute("""
                INSERT INTO active_alerts
                (file_path, event_type, old_hash, new_hash,
                 first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                file_path, event_type, old_hash,
                new_hash, now, now
            ))

            connection.commit()
            log_event(event_type, file_path, old_hash, new_hash)
            return

        previous_type, previous_old_hash, previous_new_hash = previous

        if previous_type == event_type:
            changed = (
                event_type == "MODIFIED"
                and previous_new_hash != new_hash
            )

            cursor.execute("""
                UPDATE active_alerts
                SET last_seen = ?,
                    old_hash = ?,
                    new_hash = ?
                WHERE file_path = ?
            """, (now, old_hash, new_hash, file_path))

            connection.commit()

            if changed:
                log_event(event_type, file_path, old_hash, new_hash)

            return

        cursor.execute("""
            UPDATE active_alerts
            SET event_type = ?,
                old_hash = ?,
                new_hash = ?,
                first_seen = ?,
                last_seen = ?
            WHERE file_path = ?
        """, (
            event_type, old_hash, new_hash,
            now, now, file_path
        ))

        connection.commit()

        log_event(
            "RESOLVED",
            file_path,
            previous_type,
            event_type
        )
        log_event(event_type, file_path, old_hash, new_hash)

    finally:
        connection.close()



def resolve_alert(file_path, reason="File state resolved"):

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT event_type
        FROM active_alerts
        WHERE file_path = ?
    """, (file_path,))

    previous = cursor.fetchone()

    if previous is None:
        connection.close()
        return

    previous_type = previous[0]

    cursor.execute("""
        DELETE FROM active_alerts
        WHERE file_path = ?
    """, (file_path,))

    connection.commit()
    connection.close()

    log_event(
        "RESOLVED",
        file_path,
        previous_type,
        reason
    )

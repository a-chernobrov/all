import sqlite3
import json
import time
from datetime import datetime

DB_PATH = 'cve_data.db'
MAX_RETRIES = 5


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def create_database():
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            year INTEGER,
            cve_id TEXT UNIQUE,
            description TEXT,
            links TEXT,
            source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id
        ON vulnerabilities (cve_id)
    ''')
    c.execute('''
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_year
        ON vulnerabilities (year)
    ''')
    conn.commit()
    conn.close()


def save_vulnerability(year, cve_id, description, links, source=None):
    """
    Upsert — создаёт запись или обновляет существующую:
    - description обновляется, если новый непустой (берётся самый длинный)
    - links сливаются (без дубликатов)
    - source обновляется, если указан
    - updated_at всегда обновляется
    """
    for attempt in range(MAX_RETRIES):
        try:
            return _save_vulnerability(year, cve_id, description, links, source)
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e) and attempt < MAX_RETRIES - 1:
                wait = 0.5 * (attempt + 1)
                print(f"  БД заблокирована, повтор через {wait:.1f}с (попытка {attempt + 2}/{MAX_RETRIES})")
                time.sleep(wait)
                continue
            raise


def _save_vulnerability(year, cve_id, description, links, source=None):
    conn = get_connection()
    c = conn.cursor()

    links_json = json.dumps(list(set(links))) if links else '[]'

    c.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
    existing = c.fetchone()

    if existing:
        old_desc = existing['description'] or ''
        new_desc = description or ''
        best_desc = new_desc if len(new_desc) > len(old_desc) else old_desc

        old_links = json.loads(existing['links']) if existing['links'] else []
        merged_links = list(set(old_links + links))
        merged_links_json = json.dumps(merged_links)

        update_fields = [
            'description = ?',
            'links = ?',
            'updated_at = CURRENT_TIMESTAMP',
        ]
        update_params = [best_desc, merged_links_json]

        if source:
            update_fields.append('source = ?')
            update_params.append(source)

        update_params.append(cve_id)
        c.execute(
            f"UPDATE vulnerabilities SET {', '.join(update_fields)} WHERE cve_id = ?",
            update_params
        )
    else:
        c.execute(
            """INSERT INTO vulnerabilities (year, cve_id, description, links, source, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
            (year, cve_id, description or '', links_json, source)
        )

    conn.commit()
    conn.close()


def count_vulnerabilities(search=None, source=None):
    conn = get_connection()
    c = conn.cursor()
    conditions = []
    params = []

    if search:
        pattern = f'%{search}%'
        conditions.append("(cve_id LIKE ? OR description LIKE ?)")
        params += [pattern, pattern]

    if source:
        conditions.append("source = ?")
        params.append(source)

    if conditions:
        c.execute(f"SELECT COUNT(*) FROM vulnerabilities WHERE {' AND '.join(conditions)}", params)
    else:
        c.execute("SELECT COUNT(*) FROM vulnerabilities")
    count = c.fetchone()[0]
    conn.close()
    return count


def get_all_cve_data():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT cve_id, links FROM vulnerabilities")
    data = c.fetchall()
    conn.close()
    return data


def search_vulnerabilities(query, limit=20, offset=0, source=None):
    """
    Полнотекстовый поиск по CVE с фильтром по источнику.
    """
    conn = get_connection()
    c = conn.cursor()

    pattern = f'%{query}%'
    where_clause = "(cve_id LIKE ? OR description LIKE ?)"
    params = [pattern, pattern]

    if source:
        where_clause += " AND source = ?"
        params.append(source)

    order_clause = """
        ORDER BY
          CASE WHEN cve_id LIKE ? THEN 0 ELSE 1 END,
          updated_at DESC
    """
    params_order = params + [f'{query}%']

    c.execute(
        f"""SELECT cve_id, year, description, links, source, created_at, updated_at
            FROM vulnerabilities
            WHERE {where_clause}
            {order_clause}
            LIMIT ? OFFSET ?""",
        tuple(params_order + [limit, offset])
    )
    rows = c.fetchall()

    c.execute(
        f"SELECT COUNT(*) FROM vulnerabilities WHERE {where_clause}",
        tuple(params)
    )
    total = c.fetchone()[0]

    conn.close()

    results = []
    for row in rows:
        results.append({
            'cve_id': row['cve_id'],
            'year': row['year'],
            'description': row['description'],
            'links': json.loads(row['links']) if row['links'] else [],
            'source': row['source'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        })

    return results, total


def search_description(query, limit=20, offset=0, source=None):
    """
    Поиск только по описанию (без поиска по CVE ID).
    """
    conn = get_connection()
    c = conn.cursor()

    pattern = f'%{query}%'
    where_clause = "description LIKE ?"
    params = [pattern]

    if source:
        where_clause += " AND source = ?"
        params.append(source)

    c.execute(
        f"""SELECT cve_id, year, description, links, source, created_at, updated_at
            FROM vulnerabilities
            WHERE {where_clause}
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?""",
        tuple(params + [limit, offset])
    )
    rows = c.fetchall()

    c.execute(
        f"SELECT COUNT(*) FROM vulnerabilities WHERE {where_clause}",
        tuple(params)
    )
    total = c.fetchone()[0]
    conn.close()

    results = []
    for row in rows:
        results.append({
            'cve_id': row['cve_id'],
            'year': row['year'],
            'description': row['description'],
            'links': json.loads(row['links']) if row['links'] else [],
            'source': row['source'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        })

    return results, total


def get_distinct_sources():
    """Возвращает список всех источников в БД."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT DISTINCT source FROM vulnerabilities WHERE source IS NOT NULL AND source != '' ORDER BY source")
    sources = [row[0] for row in c.fetchall()]
    conn.close()
    return sources


if __name__ == '__main__':
    create_database()
    print("Database created successfully.")

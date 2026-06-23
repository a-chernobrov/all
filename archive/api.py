import json
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from database import create_database, save_vulnerability, search_vulnerabilities, search_description, get_distinct_sources

create_database()
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)


# ─── Tool Call API (для LLM) ─────────────────────────────────────────

@app.route('/api/cve/search', methods=['GET', 'POST'])
def search_cve():
    """
    Поиск CVE для tool call LLM.
    GET /api/cve/search?q=CVE-2024&limit=5
    POST /api/cve/search with JSON body {"query": "CVE-2024", "limit": 5}
    """
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
        query = body.get('query', '').strip()
        limit = min(int(body.get('limit', 20)), 100)
        offset = int(body.get('offset', 0))
        source = body.get('source') or None
    else:
        query = request.args.get('q', '').strip()
        limit = min(int(request.args.get('limit', 20)), 100)
        offset = int(request.args.get('offset', 0))
        source = request.args.get('source') or None

    if not query:
        return jsonify({
            'results': [],
            'total': 0,
            'query': '',
            'error': 'Параметр query (или q) обязателен'
        }), 400

    results, total = search_vulnerabilities(query, limit=limit, offset=offset, source=source)

    return jsonify({
        'results': results,
        'total': total,
        'query': query,
        'limit': limit,
        'offset': offset
    })


@app.route('/api/cve/search/description', methods=['GET', 'POST'])
def search_cve_description():
    """
    Поиск только по описанию (без учёта CVE ID).
    GET  /api/cve/search/description?q=rce&limit=5
    POST /api/cve/search/description {"query": "rce", "limit": 5}
    """
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
        query = body.get('query', '').strip()
        limit = min(int(body.get('limit', 20)), 100)
        offset = int(body.get('offset', 0))
        source = body.get('source') or None
    else:
        query = request.args.get('q', '').strip()
        limit = min(int(request.args.get('limit', 20)), 100)
        offset = int(request.args.get('offset', 0))
        source = request.args.get('source') or None

    if not query:
        return jsonify({'error': 'Параметр query (или q) обязателен'}), 400

    results, total = search_description(query, limit=limit, offset=offset, source=source)

    return jsonify({
        'results': results,
        'total': total,
        'query': query,
        'limit': limit,
        'offset': offset
    })


# ─── CRUD API ─────────────────────────────────────────────────────────

@app.route('/api/cve', methods=['GET', 'POST'])
def handle_cve():
    from database import get_connection

    conn = get_connection()
    c = conn.cursor()

    if request.method == 'POST':
        data = request.get_json()
        cve_id = data.get('cve_id')
        year = data.get('year')
        description = data.get('description')
        links = data.get('links', [])
        source = data.get('source')

        if not all([cve_id, year, description]):
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            save_vulnerability(year, cve_id, description, links, source=source)
            return jsonify({'message': 'CVE saved successfully'}), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # GET — список с пагинацией
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 100, type=int)
    search_query = request.args.get('search', '', type=str)
    source = request.args.get('source') or None
    offset = (page - 1) * limit

    conditions = []
    params = []

    if search_query:
        pattern = f'%{search_query}%'
        conditions.append("(cve_id LIKE ? OR description LIKE ?)")
        params += [pattern, pattern]

    if source:
        conditions.append("source = ?")
        params.append(source)

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    c.execute(f"SELECT COUNT(*) FROM vulnerabilities {where}", tuple(params))
    total = c.fetchone()[0]

    c.execute(
        f"""SELECT cve_id, year, description, links, source, created_at, updated_at
            FROM vulnerabilities
            {where}
            ORDER BY updated_at DESC, year DESC, cve_id DESC
            LIMIT ? OFFSET ?""",
        tuple(params) + (limit, offset)
    )
    rows = c.fetchall()
    results = []
    for row in rows:
        results.append({
            'cve_id': row['cve_id'],
            'year': row['year'],
            'description': row['description'],
            'links_count': len(json.loads(row['links'])) if row['links'] and row['links'] != 'null' else 0,
            'source': row['source'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
        })

    conn.close()
    return jsonify({
        'total_records': total,
        'page': page,
        'limit': limit,
        'data': results
    })


@app.route('/api/cve/total', methods=['GET'])
def get_total_cve():
    from database import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM vulnerabilities")
    total = c.fetchone()[0]
    conn.close()
    return jsonify({'total': total})


@app.route('/api/cve/sources', methods=['GET'])
def get_sources():
    """Возвращает список всех источников."""
    sources = get_distinct_sources()
    return jsonify({'sources': sources})


@app.route('/api/cve/<path:cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    from database import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT description, links, source, created_at, updated_at FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
    row = c.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'CVE not found'}), 404

    return jsonify({
        'cve_id': cve_id,
        'description': row['description'] or 'No description available.',
        'links': json.loads(row['links']) if row['links'] else [],
        'source': row['source'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    })


@app.route('/api/cve/na/total', methods=['GET'])
def get_total_na_cve():
    from database import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%'")
    total_na = c.fetchone()[0]
    conn.close()
    return jsonify({'total_na': total_na})


@app.route('/api/cve/na', methods=['GET'])
def get_na_cve():
    from database import get_connection
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 100, type=int)
    offset = (page - 1) * limit

    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%'")
    total_records = c.fetchone()[0]

    c.execute(
        """SELECT cve_id, year, description, links, source, created_at, updated_at
           FROM vulnerabilities
           WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%'
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?""",
        (limit, offset)
    )
    rows = c.fetchall()
    conn.close()

    results = [{
        'cve_id': row['cve_id'],
        'year': row['year'],
        'description': row['description'],
        'links': json.loads(row['links']) if row['links'] else [],
        'source': row['source'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    } for row in rows]

    return jsonify({
        'total_records': total_records,
        'page': page,
        'limit': limit,
        'data': results
    })


# ─── Статика ─────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)

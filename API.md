# CVE Exploit Database API

Базовый URL: `http://localhost:3000`

---

## Tool Call API (для LLM)

### `GET /api/cve/search`

Поиск CVE для интеграции с LLM.

**Query-параметры:**

| Параметр | Тип | По умолчанию | Описание |
|---|---|---|---|
| `q` | string | — | Поисковый запрос (CVE ID или описание) |
| `limit` | int | `20` | Кол-во результатов (макс. 100) |
| `offset` | int | `0` | Смещение для пагинации |
| `source` | string | — | Фильтр по источнику |

**Пример:**
```
GET /api/cve/search?q=CVE-2024-48990&limit=5
```

**Ответ:**
```json
{
  "results": [
    {
      "cve_id": "CVE-2024-48990",
      "year": 2024,
      "description": "Описание уязвимости",
      "links": ["https://github.com/...", "https://example.com/..."],
      "source": "telegram",
      "created_at": "2026-06-19 12:00:00",
      "updated_at": "2026-06-19 12:00:00"
    }
  ],
  "total": 1,
  "query": "CVE-2024-48990",
  "limit": 5,
  "offset": 0
}
```

---

### `POST /api/cve/search`

То же, что GET, но параметры передаются в теле запроса.

**Body (JSON):**

```json
{
  "query": "CVE-2024",
  "limit": 5,
  "offset": 0,
  "source": "exploit-db"
}
```

---

### `GET /api/cve/search/description`

Поиск **только по описанию** (без учёта CVE ID).

**Query-параметры:**

| Параметр | Тип | По умолчанию | Описание |
|---|---|---|---|
| `q` | string | — | Поисковый запрос (только по description) |
| `limit` | int | `20` | Кол-во результатов (макс. 100) |
| `offset` | int | `0` | Смещение для пагинации |
| `source` | string | — | Фильтр по источнику |

**Пример:**
```
GET /api/cve/search/description?q=remote%20code%20execution&limit=3
```

**Ответ:** тот же формат, что и `/api/cve/search`.

---

### `POST /api/cve/search/description`

То же, что GET, но в теле запроса.

```json
{
  "query": "remote code execution",
  "limit": 5,
  "source": "exploit-db"
}
```

---

## CRUD API

### `GET /api/cve`

Список всех CVE с пагинацией.

**Query-параметры:**

| Параметр | Тип | По умолчанию | Описание |
|---|---|---|---|
| `page` | int | `1` | Номер страницы |
| `limit` | int | `100` | Записей на странице |
| `search` | string | — | Поиск по CVE ID или описанию |
| `source` | string | — | Фильтр по источнику |

**Ответ:**
```json
{
  "total_records": 7400,
  "page": 1,
  "limit": 100,
  "data": [
    {
      "cve_id": "CVE-2024-48990",
      "year": 2024,
      "description": "...",
      "links_count": 3,
      "source": "telegram",
      "created_at": "...",
      "updated_at": "..."
    }
  ]
}
```

---

### `POST /api/cve`

Добавить новую CVE-запись.

**Body (JSON):**
```json
{
  "cve_id": "CVE-2024-12345",
  "year": 2024,
  "description": "Описание уязвимости",
  "links": ["https://github.com/..."],
  "source": "manual"
}
```

**Ответ:** `201 Created`
```json
{ "message": "CVE saved successfully" }
```

---

### `GET /api/cve/<cve_id>`

Детали конкретной CVE.

**Пример:**
```
GET /api/cve/CVE-2024-48990
```

**Ответ:**
```json
{
  "cve_id": "CVE-2024-48990",
  "description": "Описание",
  "links": ["https://github.com/..."],
  "source": "telegram",
  "created_at": "2026-06-19 12:00:00",
  "updated_at": "2026-06-19 12:00:00"
}
```

**Ошибка:** `404 Not Found`
```json
{ "error": "CVE not found" }
```

---

### `GET /api/cve/total`

Общее количество записей в БД.

**Ответ:**
```json
{ "total": 7400 }
```

---

### `GET /api/cve/sources`

Список всех уникальных источников (для фильтра).

**Ответ:**
```json
{
  "sources": [
    "exploit-db",
    "poc-in-github",
    "pocorexp-in-github",
    "telegram",
    "data-cve-poc"
  ]
}
```

---

### `GET /api/cve/na`

Список записей без корректного CVE ID (N/A).

**Query-параметры:**

| Параметр | Тип | По умолчанию |
|---|---|---|
| `page` | int | `1` |
| `limit` | int | `100` |

---

### `GET /api/cve/na/total`

Количество записей без CVE ID.

**Ответ:**
```json
{ "total_na": 42 }
```

---

## Структура объекта CVE

```json
{
  "cve_id":    "CVE-2024-48990",   // string — идентификатор
  "year":      2024,                // int — год
  "description": "Описание...",     // string — описание
  "links":     ["https://..."],     // [string] — массив ссылок
  "source":    "telegram",          // string — источник данных
  "created_at": "2026-06-19 12:00:00",  // string — дата создания
  "updated_at": "2026-06-19 12:00:00"   // string — дата обновления
}
```

**Возможные значения `source`:**
- `exploit-db` — Exploit-DB
- `telegram` — Telegram-канал poc_in_zip
- `poc-in-github` — PoC-in-GitHub
- `data-cve-poc` — data-cve-poc
- `pocorexp-in-github` — PocOrExp_in_Github
- `pocorexp-in-github-today` — PocOrExp Today.md

---

## Статика

| Маршрут | Описание |
|---|---|
| `GET /` | Главная страница (`index.html`) |
| `GET /<file>` | Любой статический файл из корня |

document.addEventListener('DOMContentLoaded', function () {
    const tableBody = document.querySelector('#cve-table tbody');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');
    const pageInfo = document.getElementById('page-info');
    const searchInput = document.getElementById('search-input');
    const sourceFilter = document.getElementById('source-filter');
    const addBtn = document.getElementById('add-button');
    const addModal = document.getElementById('add-modal');
    const addForm = document.getElementById('add-cve-form');
    const detailModal = document.getElementById('detail-modal');
    const emptyState = document.getElementById('empty-state');

    let currentPage = 1;
    let currentSearch = '';
    let currentSource = '';
    const limit = 100;

    // ─── Fetch ────────────────────────────────────────────────────

    async function fetchData(page, search, source) {
        const params = new URLSearchParams({ page, limit });
        if (search) params.set('search', search);
        if (source) params.set('source', source);

        try {
            const res = await fetch(`/api/cve?${params}`);
            const data = await res.json();
            renderTable(data.data);
            renderPagination(data.total_records, page);
            updateStats(data.total_records);
            return data;
        } catch (err) {
            console.error('Fetch error:', err);
        }
    }

    // ─── Load Sources ─────────────────────────────────────────────

    async function loadSources() {
        try {
            const res = await fetch('/api/cve/sources');
            const data = await res.json();
            data.sources.forEach(src => {
                const opt = document.createElement('option');
                opt.value = src;
                opt.textContent = src;
                sourceFilter.appendChild(opt);
            });
        } catch (err) {
            console.error('Load sources error:', err);
        }
    }

    function renderTable(rows) {
        tableBody.innerHTML = '';

        if (!rows || rows.length === 0) {
            emptyState.classList.add('visible');
            return;
        }
        emptyState.classList.remove('visible');

        rows.forEach(item => {
            const tr = document.createElement('tr');

            const source = item.source || 'unknown';
            const createdAt = item.created_at
                ? new Date(item.created_at).toLocaleDateString('ru-RU')
                : '—';

            tr.innerHTML = `
                <td><span class="year-badge">${item.year || '—'}</span></td>
                <td><a class="cve-link" data-id="${item.cve_id}">${item.cve_id}</a></td>
                <td><div class="desc-cell" title="${escapeHtml(item.description)}">${escapeHtml(item.description)}</div></td>
                <td><span class="links-badge">${item.links_count}</span></td>
                <td><span class="source-badge">${source}</span></td>
                <td>
                    <button class="details-btn" data-id="${item.cve_id}">
                        Открыть
                    </button>
                </td>
            `;

            // Клик по CVE-ссылке
            tr.querySelector('.cve-link').addEventListener('click', () => openDetail(item.cve_id));
            tr.querySelector('.details-btn').addEventListener('click', () => openDetail(item.cve_id));

            tableBody.appendChild(tr);
        });
    }

    function renderPagination(total, page) {
        const totalPages = Math.ceil(total / limit) || 1;
        pageInfo.textContent = `Страница ${page} из ${totalPages}`;
        prevBtn.disabled = page <= 1 || total === 0;
        nextBtn.disabled = page >= totalPages || total === 0;
    }

    // ─── Stats ────────────────────────────────────────────────────

    function updateStats(filteredTotal) {
        // Всегда обновляем основной счётчик числом из ответа API
        document.getElementById('total-cve').textContent = filteredTotal;

        // NA counter — отдельный запрос (глобальный)
        fetch('/api/cve/na/total')
            .then(r => r.json())
            .then(data => {
                document.getElementById('na-counter').textContent = data.total_na;
            })
            .catch(e => console.error('NA stats error:', e));
    }

    // ─── Detail Modal ─────────────────────────────────────────────

    async function openDetail(cveId) {
        try {
            const res = await fetch(`/api/cve/${encodeURIComponent(cveId)}`);
            if (!res.ok) throw new Error('Not found');
            const data = await res.json();

            document.getElementById('modal-cve-id').textContent = cveId;

            let linksHtml = '';
            if (data.links && data.links.length > 0) {
                linksHtml = '<ul class="detail-links">' + data.links.map(link => `
                    <li>
                        <a href="${escapeHtml(link)}" target="_blank" rel="noopener noreferrer">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                            </svg>
                            ${escapeHtml(link)}
                        </a>
                    </li>
                `).join('') + '</ul>';
            } else {
                linksHtml = '<p style="color:#8b949e;font-size:0.85rem;">Нет ссылок</p>';
            }

            const source = data.source || '—';
            const created = data.created_at ? new Date(data.created_at).toLocaleString('ru-RU') : '—';
            const updated = data.updated_at ? new Date(data.updated_at).toLocaleString('ru-RU') : '—';

            document.getElementById('modal-body').innerHTML = `
                <div class="detail-section">
                    <span class="detail-label">Описание</span>
                    <p class="detail-description">${escapeHtml(data.description || 'Нет описания')}</p>
                </div>
                <div class="detail-section">
                    <span class="detail-label">Ссылки</span>
                    ${linksHtml}
                </div>
                <div class="detail-section">
                    <span class="detail-label">Источник</span>
                    <span class="detail-source">${source}</span>
                </div>
                <div class="detail-section">
                    <div class="detail-meta">
                        <span>Создано: ${created}</span>
                        <span>Обновлено: ${updated}</span>
                    </div>
                </div>
            `;

            detailModal.classList.add('active');
        } catch (err) {
            console.error('Detail error:', err);
            alert('Не удалось загрузить детали CVE');
        }
    }

    // ─── Modal controls ───────────────────────────────────────────

    function closeAllModals() {
        document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active'));
    }

    document.querySelectorAll('.modal-close, .modal-backdrop').forEach(el => {
        el.addEventListener('click', closeAllModals);
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeAllModals();
    });

    // ─── Add CVE ──────────────────────────────────────────────────

    addBtn.addEventListener('click', () => addModal.classList.add('active'));

    addForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const payload = {
            cve_id: document.getElementById('cve-id-input').value.trim(),
            year: parseInt(document.getElementById('year-input').value),
            description: document.getElementById('description-input').value.trim(),
            links: document.getElementById('links-input').value.split(',').map(s => s.trim()).filter(Boolean),
        };

        try {
            const res = await fetch('/api/cve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            if (!res.ok) {
                const err = await res.json();
                alert('Ошибка: ' + (err.error || 'Неизвестная ошибка'));
                return;
            }

            addForm.reset();
            closeAllModals();
            currentPage = 1;
            await fetchData(currentPage, currentSearch, currentSource);
        } catch (err) {
            alert('Ошибка сети: ' + err.message);
        }
    });

    // ─── Search ───────────────────────────────────────────────────

    let searchTimer;
    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            currentSearch = searchInput.value.trim();
            currentPage = 1;
            fetchData(currentPage, currentSearch, currentSource);
        }, 300);
    });

    // ─── Source Filter ────────────────────────────────────────────

    sourceFilter.addEventListener('change', () => {
        currentSource = sourceFilter.value;
        currentPage = 1;
        fetchData(currentPage, currentSearch, currentSource);
    });

    // ─── Pagination ───────────────────────────────────────────────

    prevBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            fetchData(currentPage, currentSearch, currentSource);
        }
    });

    nextBtn.addEventListener('click', () => {
        currentPage++;
        fetchData(currentPage, currentSearch, currentSource);
    });

    // ─── Init ─────────────────────────────────────────────────────

    loadSources();
    fetchData(1, '', '');

    // ─── Helpers ──────────────────────────────────────────────────

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});

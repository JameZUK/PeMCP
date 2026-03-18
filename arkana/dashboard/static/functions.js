/* Arkana Dashboard — Function Explorer */
var _debounceTimer;
var _currentSort = 'address';
var _sortAsc = true;
var _openDetailPanels = {};  // addr -> {decompile: data, activeTab: 'xrefs'}
var _openDetailPanelKeys = []; // LRU order (oldest first)
var _OPEN_DETAIL_PANELS_MAX = 50;
var _analysisCache = {};     // addr -> fetched analysis data
var _analysisCacheKeys = []; // LRU order (oldest first)
var _ANALYSIS_CACHE_MAX = 50;

function _ensureDetailPanel(addr) {
    if (!_openDetailPanels[addr]) {
        _openDetailPanelKeys.push(addr);
        while (_openDetailPanelKeys.length > _OPEN_DETAIL_PANELS_MAX) {
            var evict = _openDetailPanelKeys.shift();
            delete _openDetailPanels[evict];
        }
        _openDetailPanels[addr] = {};
    }
    return _openDetailPanels[addr];
}

function debounceReload() {
    clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(reloadFunctions, 300);
}
function sortBy(col) {
    if (_currentSort === col) {
        _sortAsc = !_sortAsc;
    } else {
        _currentSort = col;
        _sortAsc = true;
    }
    document.querySelectorAll('#func-table th.sortable').forEach(function(th) {
        var arrow = th.querySelector('.sort-arrow');
        if (th.dataset.sort === col) {
            th.classList.add('active');
            arrow.innerHTML = _sortAsc ? '&#9650;' : '&#9660;';
        } else {
            th.classList.remove('active');
            arrow.innerHTML = '';
        }
    });
    reloadFunctions();
}
function reloadFunctions() {
    var triage = document.getElementById('filter-triage').value;
    var search = document.getElementById('filter-search').value;
    var url = '/dashboard/api/functions?triage=' + encodeURIComponent(triage) +
              '&search=' + encodeURIComponent(search) +
              '&sort=' + encodeURIComponent(_currentSort) +
              '&asc=' + (_sortAsc ? '1' : '0');
    fetchJSON(url).then(function(data) {
        var tbody = document.getElementById('func-tbody');
        // Preserve scroll position across DOM rebuild
        var tableWrap = tbody.closest('.table-wrap');
        var savedScrollTop = tableWrap ? tableWrap.scrollTop : 0;
        var savedPageScroll = window.scrollY;

        document.getElementById('func-count').textContent = data.length;
        if (!data.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-msg">No matching functions.</td></tr>';
            return;
        }
        var html = '';
        data.forEach(function(f) {
            var noteClass = f.has_note ? ' has-note' : '';
            var exploredClass = f.is_decompiled ? ' explored' : '';
            var renamedClass = f.is_renamed ? ' renamed' : '';
            var noteIndicator = f.has_note ? ' <span class="note-indicator" title="Has notes">*</span>' : '';
            var statusTags = '';
            if (f.is_renamed) statusTags += '<span class="badge badge-renamed" title="Renamed">REN</span> ';
            if (f.is_decompiled) statusTags += '<span class="badge badge-explored" title="Decompiled">DEC</span> ';
            var triageClass = (['unreviewed','suspicious','clean','flagged'].indexOf(f.triage_status) !== -1) ? f.triage_status : 'unreviewed';
            html += '<tr class="triage-' + triageClass + noteClass + exploredClass + renamedClass + '" data-addr="' + escapeHtml(f.address) + '">';
            html += '<td class="mono">' + escapeHtml(f.address) + '</td>';
            html += '<td>' + statusTags + escapeHtml(f.name) + noteIndicator + '</td>';
            html += '<td>' + escapeHtml(String(f.size)) + '</td>';
            html += '<td>' + escapeHtml(String(f.complexity)) + '</td>';
            html += '<td>' + escapeHtml(String(f.score)) + '</td>';
            html += '<td><span class="badge badge-' + triageClass + '">' + triageClass.toUpperCase() + '</span></td>';
            html += '<td class="triage-btns">';
            var safeAddr = escapeHtml(f.address);
            html += '<a class="btn-triage btn-graph" href="/dashboard/callgraph?focus=' + encodeURIComponent(f.address) + '" title="View in call graph">GRAPH</a>';
            html += '<button class="btn-triage btn-analysis" data-addr="' + safeAddr + '" title="Cross-references &amp; analysis">XREF</button>';
            html += '<button class="btn-triage btn-decompile' + (f.is_decompiled ? ' active' : '') + '" data-addr="' + safeAddr + '" title="Decompile">DEC</button>';
            html += '<button class="btn-triage btn-asm" data-addr="' + safeAddr + '" title="Disassembly">ASM</button>';
            html += '<button class="btn-triage btn-vars" data-addr="' + safeAddr + '" title="Variables">VARS</button>';
            html += '<button class="btn-triage btn-sim" data-addr="' + safeAddr + '" title="Similar functions">SIM</button>';
            html += '<button class="btn-triage btn-flag' + (f.triage_status === 'flagged' ? ' active' : '') + '" data-addr="' + safeAddr + '" data-status="flagged">FLAG</button>';
            html += '<button class="btn-triage btn-suspicious' + (f.triage_status === 'suspicious' ? ' active' : '') + '" data-addr="' + safeAddr + '" data-status="suspicious">SUS</button>';
            html += '<button class="btn-triage btn-clean' + (f.triage_status === 'clean' ? ' active' : '') + '" data-addr="' + safeAddr + '" data-status="clean">CLN</button>';
            html += '</td></tr>';
            if (f.has_note && f.notes) {
                html += '<tr class="note-row">';
                html += '<td colspan="7"><div class="func-notes">';
                f.notes.forEach(function(n) {
                    html += '<div class="func-note-text">' + escapeHtml(n) + '</div>';
                });
                html += '</div></td></tr>';
            }
        });
        tbody.innerHTML = html;
        _restoreDetailPanels();

        // Restore scroll position after DOM rebuild
        if (tableWrap) tableWrap.scrollTop = savedScrollTop;
        window.scrollTo(0, savedPageScroll);
    });
}
// escapeHtml is defined globally in dashboard.js
function setTriage(addr, status) {
    fetchJSON('/dashboard/api/triage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
        body: JSON.stringify({address: addr, status: status})
    }).then(function() { reloadFunctions(); })
    .catch(function() { showToast('Triage update failed', 'error'); });
}

// --- Live decompile updates ---
// Layer 1: Per-row SSE updates (decompile-update event from SSE → CustomEvent)
document.addEventListener('arkana-decompile-update', function(e) {
    var addrs = (e.detail && e.detail.addresses) || [];
    for (var i = 0; i < addrs.length; i++) {
        var addr = addrs[i];
        var row = document.querySelector('tr[data-addr="' + CSS.escape(addr) + '"]');
        if (!row) continue;
        // Add DEC badge if not present
        var nameCell = row.children[1];
        if (nameCell && !nameCell.querySelector('.badge-explored')) {
            var badge = document.createElement('span');
            badge.className = 'badge badge-explored';
            badge.title = 'Decompiled';
            badge.textContent = 'DEC';
            nameCell.insertBefore(badge, nameCell.firstChild);
            nameCell.insertBefore(document.createTextNode(' '), badge.nextSibling);
        }
        // Mark row as explored
        if (!row.classList.contains('explored')) row.classList.add('explored');
        // Update DEC button
        var decBtn = row.querySelector('.btn-decompile');
        if (decBtn) decBtn.classList.add('active');
        // Flash animation
        row.classList.add('decompile-flash');
        row.addEventListener('animationend', function() {
            this.classList.remove('decompile-flash');
        }, {once: true});
    }
});

// Layer 2: Table reload when explored count changes (via state-update SSE)
var _exploredReloadTimer;
document.addEventListener('arkana-explored-changed', function(e) {
    // Skip auto-reload when detail panels are open — the user is reading
    // decompiled code/xrefs/asm. Destroying the DOM causes scroll reset and
    // flash. The user can manually reload via filter/sort changes.
    if (Object.keys(_openDetailPanels).length > 0) return;
    // Debounce: reload at most every 3 seconds
    clearTimeout(_exploredReloadTimer);
    _exploredReloadTimer = setTimeout(function() {
        if (typeof reloadFunctions === 'function') reloadFunctions();
    }, 500);
});

// Layer 3: Polling fallback removed — SSE + htmx partial polling already cover
// change detection.  The previous 5s setInterval was redundant and wasted
// bandwidth (triple-polling alongside SSE every 2s and htmx every 3s).

// Bind all event listeners on DOMContentLoaded
document.addEventListener('DOMContentLoaded', function() {
    var validSorts = ['address', 'name', 'size', 'complexity', 'score', 'triage'];
    document.querySelectorAll('#func-table th.sortable').forEach(function(th) {
        th.addEventListener('click', function() {
            var col = th.dataset.sort;
            if (validSorts.indexOf(col) !== -1) sortBy(col);
        });
    });

    var triageSelect = document.getElementById('filter-triage');
    if (triageSelect) triageSelect.addEventListener('change', reloadFunctions);

    var searchInput = document.getElementById('filter-search');
    if (searchInput) searchInput.addEventListener('keyup', function() {
        debounceReload();
        if (_currentView === 'tree') loadTreeView();
    });

    var codeSearchInput = document.getElementById('code-search');
    if (codeSearchInput) codeSearchInput.addEventListener('keyup', function(e) {
        if (e.key === 'Enter') searchDecompiledCode();
    });

    var tbody = document.getElementById('func-tbody');
    if (tbody) {
        tbody.addEventListener('click', function(e) {
            // Detail tab clicks
            var tabBtn = e.target.closest('.detail-tab');
            if (tabBtn) {
                switchDetailTab(tabBtn);
                return;
            }
            // Clickable xref entries
            var xrefEntry = e.target.closest('.xref-clickable');
            if (xrefEntry) {
                navigateToFunction(xrefEntry.dataset.addr);
                return;
            }
            var btn = e.target.closest('.btn-triage');
            if (!btn) return;
            if (btn.classList.contains('btn-decompile')) {
                toggleDecompile(btn);
            } else if (btn.classList.contains('btn-analysis')) {
                toggleAnalysisPanel(btn);
            } else if (btn.classList.contains('btn-asm')) {
                toggleDetailTab(btn, 'asm');
            } else if (btn.classList.contains('btn-vars')) {
                toggleDetailTab(btn, 'vars');
            } else if (btn.classList.contains('btn-sim')) {
                toggleDetailTab(btn, 'sim');
            } else {
                // Toggle: if already active, reset to unreviewed
                var status = btn.classList.contains('active') ? 'unreviewed' : btn.dataset.status;
                setTriage(btn.dataset.addr, status);
            }
        });
    }

    // Deep-link: ?highlight=0xADDR scrolls to and flashes the target row
    var hlParam = new URLSearchParams(window.location.search).get('highlight');
    if (hlParam) {
        window.history.replaceState({}, '', window.location.pathname);
        setTimeout(function() { navigateToFunction(hlParam); }, 300);
    }
});

// --- Analysis Panel (XREF button) ---
function toggleAnalysisPanel(btn) {
    var addr = btn.dataset.addr;
    var row = btn.closest('tr');
    var detailRow = _findDetailRow(row);
    if (detailRow) {
        var activeTab = detailRow.querySelector('.detail-tab.active');
        if (activeTab && activeTab.dataset.tab === 'xrefs') {
            // Already on xrefs tab — toggle off
            detailRow.remove();
            delete _openDetailPanels[addr];
            return;
        }
        // Switch to xrefs tab
        var xrefsTab = detailRow.querySelector('.detail-tab[data-tab="xrefs"]');
        if (xrefsTab) switchDetailTab(xrefsTab);
        return;
    }
    _ensureDetailPanel(addr);
    _openDetailPanels[addr].activeTab = 'xrefs';
    insertDetailPanel(row, addr, 'xrefs');
}

// --- Decompile (DEC button) ---
function toggleDecompile(btn) {
    var addr = btn.dataset.addr;
    var row = btn.closest('tr');
    var detailRow = _findDetailRow(row);
    if (detailRow) {
        var activeTab = detailRow.querySelector('.detail-tab.active');
        if (activeTab && activeTab.dataset.tab === 'code') {
            // Already on code tab — toggle off
            detailRow.remove();
            delete _openDetailPanels[addr];
            return;
        }
        // Switch to code tab (trigger decompile if needed)
        var codeTab = detailRow.querySelector('.detail-tab[data-tab="code"]');
        if (codeTab) switchDetailTab(codeTab);
        return;
    }
    // Already have cached decompile data?
    if (_openDetailPanels[addr] && _openDetailPanels[addr].decompile) {
        _openDetailPanels[addr].activeTab = 'code';
        insertDetailPanel(row, addr, 'code');
        return;
    }
    btn.textContent = '...';
    fetchJSON('/dashboard/api/decompile?address=' + encodeURIComponent(addr))
        .then(function(data) {
            if (data.cached) {
                _ensureDetailPanel(addr);
                _openDetailPanels[addr].decompile = data;
                _openDetailPanels[addr].activeTab = 'code';
                insertDetailPanel(row, addr, 'code');
                btn.textContent = 'DEC';
                btn.classList.add('active');
            } else {
                // Trigger decompilation
                btn.textContent = '<<<';
                fetchJSON('/dashboard/api/decompile', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
                    body: JSON.stringify({address: addr})
                })
                .then(function(result) {
                    btn.textContent = 'DEC';
                    if (result.cached || result.lines) {
                        _ensureDetailPanel(addr);
                        _openDetailPanels[addr].decompile = result;
                        _openDetailPanels[addr].activeTab = 'code';
                        insertDetailPanel(row, addr, 'code');
                        btn.classList.add('active');
                    } else {
                        btn.textContent = 'ERR';
                        setTimeout(function() { btn.textContent = 'DEC'; }, 2000);
                        if (result.error) showToast(result.error, 'error');
                    }
                }).catch(function() {
                    btn.textContent = 'DEC';
                    showToast('Decompilation request failed', 'error');
                });
            }
        }).catch(function() {
            btn.textContent = 'DEC';
            showToast('Failed to check decompile cache', 'error');
        });
}

// Find the detail panel row after a function row (skipping note rows)
function _findDetailRow(funcRow) {
    var nextRow = funcRow.nextElementSibling;
    while (nextRow && nextRow.classList.contains('note-row')) {
        nextRow = nextRow.nextElementSibling;
    }
    if (nextRow && nextRow.classList.contains('decompile-row')) return nextRow;
    return null;
}

// Insert a detail panel with tabs below a function row
function insertDetailPanel(afterRow, addr, startTab) {
    var insertAfter = afterRow;
    while (insertAfter.nextElementSibling && insertAfter.nextElementSibling.classList.contains('note-row')) {
        insertAfter = insertAfter.nextElementSibling;
    }
    var tr = document.createElement('tr');
    tr.className = 'decompile-row';
    tr.dataset.addr = addr;
    var td = document.createElement('td');
    td.setAttribute('colspan', '7');
    var panel = document.createElement('div');
    panel.className = 'decompile-panel';

    // Tab bar
    var tabBar = document.createElement('div');
    tabBar.className = 'detail-tab-bar';
    var tabs = ['XREFS', 'STRINGS', 'CODE', 'ASM', 'VARS', 'SIM'];
    for (var i = 0; i < tabs.length; i++) {
        var tabBtn = document.createElement('button');
        var tabKey = tabs[i].toLowerCase();
        tabBtn.className = 'detail-tab' + (tabKey === startTab ? ' active' : '');
        tabBtn.textContent = tabs[i];
        tabBtn.dataset.tab = tabKey;
        tabBtn.dataset.addr = addr;
        tabBar.appendChild(tabBtn);
    }

    // Header
    var header = document.createElement('div');
    header.className = 'decompile-panel-header';
    var panelData = _openDetailPanels[addr] || {};
    var decData = panelData.decompile;
    var funcName = (decData && decData.function_name) || addr;
    var lineInfo = decData ? ' &middot; ' + escapeHtml(String(decData.line_count || 0)) + ' lines' : '';
    header.innerHTML = '<span class="decompile-func-name">' + escapeHtml(funcName) +
        '</span> <span class="dim">(' + escapeHtml(addr) + lineInfo + ')</span>';

    // Tab content area
    var tabContent = document.createElement('div');
    tabContent.className = 'detail-tab-content';
    tabContent.id = 'tab-content-' + addr;

    _renderTabContent(tabContent, startTab, addr);

    panel.appendChild(tabBar);
    panel.appendChild(header);
    panel.appendChild(tabContent);
    td.appendChild(panel);
    tr.appendChild(td);
    insertAfter.parentNode.insertBefore(tr, insertAfter.nextSibling);
}

function _renderTabContent(container, tab, addr) {
    if (tab === 'code') {
        var panelData = _openDetailPanels[addr] || {};
        var decData = panelData.decompile;
        if (decData) {
            var pre = document.createElement('pre');
            pre.className = 'decompile-code';
            pre.textContent = (decData.lines || []).join('\n');
            container.innerHTML = '';
            container.appendChild(pre);
        } else {
            container.innerHTML = '<div class="dim p-10">Not yet decompiled. Click <b>DEC</b> to decompile this function.</div>';
        }
    } else if (tab === 'xrefs') {
        container.innerHTML = '<div class="dim p-10">Loading analysis...</div>';
        fetchAnalysis(addr, function(data) {
            if (data) {
                renderXrefsTab(container, data);
            } else {
                container.innerHTML = '<div class="dim p-10">Failed to load cross-references.</div>';
            }
        });
    } else if (tab === 'strings') {
        container.innerHTML = '<div class="dim p-10">Loading strings...</div>';
        fetchJSON('/dashboard/api/function-strings?address=' + encodeURIComponent(addr))
            .then(function(data) { renderStringsTab(container, data); })
            .catch(function() { container.innerHTML = '<div class="dim p-10">Failed to load strings.</div>'; });
    } else if (tab === 'asm') {
        renderAsmTab(container, addr);
    } else if (tab === 'vars') {
        renderVarsTab(container, addr);
    } else if (tab === 'sim') {
        renderSimTab(container, addr);
    }
}

function switchDetailTab(tabBtn) {
    var tab = tabBtn.dataset.tab;
    var addr = tabBtn.dataset.addr;
    var bar = tabBtn.parentNode;
    var content = document.getElementById('tab-content-' + addr);
    if (!content) return;

    // Update active tab
    var siblings = bar.querySelectorAll('.detail-tab');
    for (var i = 0; i < siblings.length; i++) siblings[i].classList.remove('active');
    tabBtn.classList.add('active');

    if (_openDetailPanels[addr]) _openDetailPanels[addr].activeTab = tab;
    _renderTabContent(content, tab, addr);
}

// --- Analysis data fetching ---
function fetchAnalysis(addr, callback) {
    if (_analysisCache[addr]) {
        callback(_analysisCache[addr]);
        return;
    }
    fetchJSON('/dashboard/api/function-analysis?address=' + encodeURIComponent(addr))
        .then(function(data) {
            // LRU eviction
            var idx = _analysisCacheKeys.indexOf(addr);
            if (idx !== -1) _analysisCacheKeys.splice(idx, 1);
            _analysisCacheKeys.push(addr);
            _analysisCache[addr] = data;
            while (_analysisCacheKeys.length > _ANALYSIS_CACHE_MAX) {
                var evict = _analysisCacheKeys.shift();
                delete _analysisCache[evict];
            }
            callback(data);
        })
        .catch(function() { callback(null); });
}

// --- Tab renderers ---
function renderXrefsTab(container, data) {
    var html = '<div class="p-10">';

    // Suspicious APIs section
    var suspicious = data.suspicious_apis || [];
    if (suspicious.length) {
        html += '<div class="suspicious-section">';
        html += '<div class="suspicious-section-header">SUSPICIOUS APIs (' + suspicious.length + ')</div>';
        for (var i = 0; i < suspicious.length; i++) {
            var api = suspicious[i];
            var riskClass = api.risk === 'CRITICAL' ? 'badge-danger' : api.risk === 'HIGH' ? 'badge-warning' : 'badge-dim';
            html += '<div class="suspicious-api-row">';
            html += '<span class="badge ' + riskClass + '">' + escapeHtml(api.risk) + '</span> ';
            html += '<span>' + escapeHtml(api.name) + '</span>';
            html += ' <span class="suspicious-api-category">' + escapeHtml(api.category || '') + '</span>';
            html += '</div>';
        }
        html += '</div>';
    }

    // Callers
    var callers = data.callers || [];
    html += '<div class="xref-section-header">CALLERS (' + callers.length + ')</div>';
    if (callers.length) {
        for (var i = 0; i < callers.length; i++) {
            var c = callers[i];
            var dotClass = 'xref-triage-dot dot-' + (c.triage || 'unreviewed');
            html += '<div class="xref-clickable xref-entry" data-addr="' + escapeHtml(c.address) + '" title="Go to ' + escapeHtml(c.address) + '">';
            html += '<span class="' + dotClass + '"></span> ';
            html += '<span class="mono dim">' + escapeHtml(c.address) + '</span> ';
            html += '<span>' + escapeHtml(c.name) + '</span>';
            if (c.complexity) html += ' <span class="dim fs-10">C:' + escapeHtml(String(c.complexity)) + '</span>';
            html += '</div>';
        }
    } else {
        html += '<div class="dim fs-12">No callers found</div>';
    }

    // Callees
    var callees = data.callees || [];
    html += '<div class="xref-section-header-mt">CALLEES (' + callees.length + ')</div>';
    if (callees.length) {
        for (var i = 0; i < callees.length; i++) {
            var c = callees[i];
            var dotClass = 'xref-triage-dot dot-' + (c.triage || 'unreviewed');
            html += '<div class="xref-clickable xref-entry" data-addr="' + escapeHtml(c.address) + '" title="Go to ' + escapeHtml(c.address) + '">';
            html += '<span class="' + dotClass + '"></span> ';
            html += '<span class="mono dim">' + escapeHtml(c.address) + '</span> ';
            html += '<span>' + escapeHtml(c.name) + '</span>';
            if (c.suspicious) {
                var riskClass = c.suspicious.risk === 'CRITICAL' ? 'badge-danger' : c.suspicious.risk === 'HIGH' ? 'badge-warning' : 'badge-dim';
                html += ' <span class="badge ' + riskClass + ' fs-9">' + escapeHtml(c.suspicious.risk) + '</span>';
            }
            if (c.complexity) html += ' <span class="dim fs-10">C:' + escapeHtml(String(c.complexity)) + '</span>';
            html += '</div>';
        }
    } else {
        html += '<div class="dim fs-12">No callees found</div>';
    }

    // Complexity
    if (data.complexity) {
        html += '<div class="xref-complexity">';
        html += 'BLOCKS: ' + escapeHtml(String(data.complexity.blocks || 0)) + ' / EDGES: ' + escapeHtml(String(data.complexity.edges || 0));
        html += '</div>';
    }

    html += '</div>';
    container.innerHTML = html;
}

function renderStringsTab(container, data) {
    var strings = data.strings || [];
    if (!strings.length) {
        container.innerHTML = '<div class="dim p-10">No strings associated with this function.</div>';
        return;
    }
    var html = '<table class="data-table data-table-sm"><thead><tr><th>TYPE</th><th>ADDRESS</th><th>STRING</th></tr></thead><tbody>';
    var typeBadge = {'STATIC':'badge-str-static','STACK':'badge-str-stack','TIGHT':'badge-str-tight'};
    for (var i = 0; i < strings.length; i++) {
        var s = strings[i];
        var bc = typeBadge[s.type] || 'badge-dim';
        var truncated = s.string.length > 120 ? s.string.substring(0, 120) + '...' : s.string;
        html += '<tr><td><span class="badge ' + bc + '">' + escapeHtml(s.type) + '</span></td>';
        html += '<td class="mono dim">' + escapeHtml(s.address || '') + '</td>';
        html += '<td class="str-content">' + escapeHtml(truncated) + '</td></tr>';
    }
    html += '</tbody></table>';
    container.innerHTML = html;
}

// --- Generic detail tab toggle for new tabs (ASM, VARS, SIM) ---
function toggleDetailTab(btn, tabName) {
    var addr = btn.dataset.addr;
    var row = btn.closest('tr');
    var detailRow = _findDetailRow(row);
    if (detailRow) {
        var activeTab = detailRow.querySelector('.detail-tab.active');
        if (activeTab && activeTab.dataset.tab === tabName) {
            detailRow.remove();
            delete _openDetailPanels[addr];
            return;
        }
        var tab = detailRow.querySelector('.detail-tab[data-tab="' + tabName + '"]');
        if (tab) switchDetailTab(tab);
        return;
    }
    _ensureDetailPanel(addr);
    _openDetailPanels[addr].activeTab = tabName;
    insertDetailPanel(row, addr, tabName);
}

// --- ASM tab renderer ---
function renderAsmTab(container, addr) {
    container.innerHTML = '<div class="dim p-10">Loading disassembly...</div>';
    fetchJSON('/dashboard/api/disassembly?address=' + encodeURIComponent(addr) + '&count=200')
        .then(function(data) {
            var insns = data.instructions || [];
            if (!insns.length) {
                container.innerHTML = '<div class="dim p-10">No disassembly available.' +
                    (data.error ? ' ' + escapeHtml(data.error) : '') + '</div>';
                return;
            }
            var html = '<table class="data-table data-table-sm asm-table"><thead><tr><th>ADDR</th><th>BYTES</th><th>MNEMONIC</th><th>OPERANDS</th></tr></thead><tbody>';
            insns.forEach(function(insn) {
                html += '<tr>';
                html += '<td class="mono asm-addr">' + escapeHtml(insn.address) + '</td>';
                html += '<td class="mono dim asm-bytes">' + escapeHtml(insn.bytes) + '</td>';
                html += '<td class="asm-mnemonic">' + escapeHtml(insn.mnemonic) + '</td>';
                html += '<td class="asm-operands">' + escapeHtml(insn.op_str) + '</td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;
        })
        .catch(function() {
            container.innerHTML = '<div class="dim p-10">Failed to load disassembly.</div>';
        });
}

// --- VARS tab renderer ---
function renderVarsTab(container, addr) {
    container.innerHTML = '<div class="dim p-10">Loading variables...</div>';
    fetchJSON('/dashboard/api/function-variables?address=' + encodeURIComponent(addr))
        .then(function(data) {
            var params = data.parameters || [];
            var locals = data.locals || [];
            if (!params.length && !locals.length) {
                container.innerHTML = '<div class="dim p-10">No variable information available.' +
                    (data.error ? ' ' + escapeHtml(data.error) : '') + '</div>';
                return;
            }
            var html = '<div class="p-10">';
            if (data.calling_convention) {
                html += '<div class="dim">Calling convention: ' + escapeHtml(data.calling_convention) + '</div>';
            }
            if (params.length) {
                html += '<div class="xref-section-header">PARAMETERS (' + params.length + ')</div>';
                html += '<table class="data-table data-table-sm"><thead><tr><th>NAME</th><th>SIZE</th><th>CATEGORY</th></tr></thead><tbody>';
                params.forEach(function(v) {
                    html += '<tr><td class="mono">' + escapeHtml(v.name) + '</td>';
                    html += '<td>' + escapeHtml(String(v.size || 0)) + '</td>';
                    html += '<td class="dim">' + escapeHtml(v.category || '') + '</td></tr>';
                });
                html += '</tbody></table>';
            }
            if (locals.length) {
                html += '<div class="xref-section-header-mt">LOCAL VARIABLES (' + locals.length + ')</div>';
                html += '<table class="data-table data-table-sm"><thead><tr><th>NAME</th><th>SIZE</th><th>CATEGORY</th></tr></thead><tbody>';
                locals.forEach(function(v) {
                    html += '<tr><td class="mono">' + escapeHtml(v.name) + '</td>';
                    html += '<td>' + escapeHtml(String(v.size || 0)) + '</td>';
                    html += '<td class="dim">' + escapeHtml(v.category || '') + '</td></tr>';
                });
                html += '</tbody></table>';
            }
            html += '</div>';
            container.innerHTML = html;
        })
        .catch(function() {
            container.innerHTML = '<div class="dim p-10">Failed to load variables.</div>';
        });
}

// --- SIM tab renderer ---
function renderSimTab(container, addr) {
    container.innerHTML = '<div class="dim p-10">Loading similarity data...</div>';
    fetchJSON('/dashboard/api/function-similarity?address=' + encodeURIComponent(addr))
        .then(function(data) {
            var matches = data.matches || [];
            if (!matches.length) {
                container.innerHTML = '<div class="dim p-10">No similar functions found.' +
                    (!data.available ? ' Function scoring data not available.' : '') + '</div>';
                return;
            }
            var html = '<table class="data-table data-table-sm"><thead><tr><th>ADDRESS</th><th>NAME</th><th>SCORE</th><th>SIMILARITY</th></tr></thead><tbody>';
            matches.forEach(function(m) {
                html += '<tr class="xref-clickable" data-addr="' + escapeHtml(m.address) + '">';
                html += '<td class="mono">' + escapeHtml(m.address) + '</td>';
                html += '<td>' + escapeHtml(m.name) + '</td>';
                html += '<td>' + escapeHtml(String(m.score)) + '</td>';
                html += '<td><span class="badge badge-dim">' + escapeHtml(String(m.similarity)) + '%</span></td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
            container.innerHTML = html;
        })
        .catch(function() {
            container.innerHTML = '<div class="dim p-10">Failed to load similarity data.</div>';
        });
}

// --- Navigation ---
function navigateToFunction(addr) {
    var tbody = document.getElementById('func-tbody');
    if (!tbody) return;
    // Find the row with this address
    var targetRow = tbody.querySelector('tr[data-addr="' + CSS.escape(addr) + '"]');
    if (targetRow) {
        targetRow.scrollIntoView({behavior: 'smooth', block: 'center'});
        targetRow.classList.add('highlight-flash');
        setTimeout(function() { targetRow.classList.remove('highlight-flash'); }, 2000);
        return;
    }
    // Not in current view — clear filters and search for it
    var searchInput = document.getElementById('filter-search');
    var triageSelect = document.getElementById('filter-triage');
    if (triageSelect) triageSelect.value = 'all';
    if (searchInput) {
        searchInput.value = addr;
        reloadFunctions();
        setTimeout(function() {
            var row = tbody.querySelector('tr[data-addr="' + CSS.escape(addr) + '"]');
            if (row) {
                row.scrollIntoView({behavior: 'smooth', block: 'center'});
                row.classList.add('highlight-flash');
                setTimeout(function() { row.classList.remove('highlight-flash'); }, 2000);
            }
        }, 600);
    }
}

// --- Restore panels after reload ---
function _restoreDetailPanels() {
    var addrs = Object.keys(_openDetailPanels);
    if (!addrs.length) return;
    var tbody = document.getElementById('func-tbody');
    if (!tbody) return;
    addrs.forEach(function(addr) {
        var row = tbody.querySelector('tr[data-addr="' + CSS.escape(addr) + '"]');
        if (row) {
            var panelData = _openDetailPanels[addr];
            var tab = (panelData && panelData.activeTab) || 'xrefs';
            insertDetailPanel(row, addr, tab);
        }
    });
}

// === Full-Text Decompiled Search ===
var _codeSearchDebounce;
function searchDecompiledCode() {
    var q = document.getElementById('code-search').value.trim();
    if (!q) return;
    var resultsPanel = document.getElementById('code-search-results');
    var body = document.getElementById('code-search-body');
    var countBadge = document.getElementById('code-search-count');
    resultsPanel.classList.remove('d-none');
    body.innerHTML = '<div class="dim p-10">Searching...</div>';
    fetchJSON('/dashboard/api/search-code?q=' + encodeURIComponent(q) + '&limit=100')
        .then(function(data) {
            if (data.error) {
                body.innerHTML = '<div class="dim p-10">' + escapeHtml(data.error) + '</div>';
                countBadge.textContent = '0';
                return;
            }
            var matches = data.results || [];
            countBadge.textContent = String(data.total_matches || 0);
            if (!matches.length) {
                body.innerHTML = '<div class="dim p-10">No matches found. ' +
                    escapeHtml(String(data.searched_functions || 0)) + ' functions searched (' +
                    escapeHtml(String(data.total_cached || 0)) + ' cached).</div>';
                return;
            }
            var html = '<div class="code-search-stats p-6-12 dim fs-11">Found ' +
                escapeHtml(String(data.total_matches)) + ' matches across ' +
                escapeHtml(String(data.searched_functions)) + ' functions (' +
                escapeHtml(String(data.total_cached)) + ' cached)</div>';
            var qRe = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
            for (var i = 0; i < matches.length; i++) {
                var m = matches[i];
                html += '<div class="code-search-result-item">';
                html += '<div class="code-search-result-header">';
                html += '<a class="code-search-func-link" href="#" data-nav-addr="' +
                    escapeHtml(m.address) + '">' + escapeHtml(m.function_name) + '</a>';
                html += ' <span class="dim mono fs-10">' + escapeHtml(m.address) + ':' + escapeHtml(String(m.line_number)) + '</span>';
                html += '</div>';
                if (m.context_before) {
                    html += '<div class="code-match-context dim">' + escapeHtml(m.context_before) + '</div>';
                }
                // Highlight: split raw text on matches, escape each part separately
                var parts = m.line_text.split(qRe);
                var highlightedLine = '';
                for (var p = 0; p < parts.length; p++) {
                    highlightedLine += (p % 2 === 1)
                        ? '<mark class="code-match-highlight">' + escapeHtml(parts[p]) + '</mark>'
                        : escapeHtml(parts[p]);
                }
                html += '<div class="code-match-line">' + highlightedLine + '</div>';
                if (m.context_after) {
                    html += '<div class="code-match-context dim">' + escapeHtml(m.context_after) + '</div>';
                }
                html += '</div>';
            }
            body.innerHTML = html;
        })
        .catch(function() {
            body.innerHTML = '<div class="dim p-10">Search request failed.</div>';
            countBadge.textContent = '0';
        });
}
function clearCodeSearch() {
    document.getElementById('code-search-results').classList.add('d-none');
    document.getElementById('code-search').value = '';
}

// === Symbol Tree View ===
var _currentView = 'table';
var _cachedFunctions = null;

function toggleView(mode) {
    _currentView = mode;
    var tableWrap = document.querySelector('.table-wrap');
    var tree = document.getElementById('symbol-tree');
    document.querySelectorAll('.view-toggle-btn').forEach(function(btn) {
        btn.classList.toggle('active', btn.dataset.view === mode);
    });
    if (mode === 'tree') {
        if (tableWrap) tableWrap.classList.add('d-none');
        tree.classList.remove('d-none');
        loadTreeView();
    } else {
        if (tableWrap) tableWrap.classList.remove('d-none');
        tree.classList.add('d-none');
        _cachedFunctions = null;
    }
}

function loadTreeView() {
    var triage = document.getElementById('filter-triage').value;
    var search = document.getElementById('filter-search').value;
    var url = '/dashboard/api/functions?triage=' + encodeURIComponent(triage) +
              '&search=' + encodeURIComponent(search) +
              '&sort=' + encodeURIComponent(_currentSort) +
              '&asc=' + (_sortAsc ? '1' : '0');
    fetchJSON(url).then(function(data) {
        _cachedFunctions = data;
        renderSymbolTree(data);
    });
}

function renderSymbolTree(functions) {
    var tree = document.getElementById('symbol-tree');
    if (!functions || !functions.length) {
        tree.innerHTML = '<div class="dim p-10">No functions to display.</div>';
        return;
    }
    // Categorize
    var groups = {
        flagged: {label: 'FLAGGED', items: [], cls: 'tree-group-flagged'},
        suspicious: {label: 'SUSPICIOUS', items: [], cls: 'tree-group-suspicious'},
        decompiled: {label: 'DECOMPILED', items: [], cls: 'tree-group-decompiled'},
        renamed: {label: 'RENAMED', items: [], cls: 'tree-group-renamed'},
        other: {label: 'OTHER', items: [], cls: 'tree-group-other'},
        library: {label: 'LIBRARY / PLT', items: [], cls: 'tree-group-library'},
    };
    var libPrefixes = ['__libc_', '_Jv_', '__cxa_', '__gmon_', '_ITM_', '__stack_chk', 'sub_', '__x86.'];
    for (var i = 0; i < functions.length; i++) {
        var f = functions[i];
        var isLib = f.is_simprocedure || f.is_plt;
        if (!isLib) {
            for (var p = 0; p < libPrefixes.length; p++) {
                if (f.name.indexOf(libPrefixes[p]) === 0) { isLib = true; break; }
            }
        }
        if (isLib) {
            groups.library.items.push(f);
        } else if (f.triage_status === 'flagged') {
            groups.flagged.items.push(f);
        } else if (f.triage_status === 'suspicious') {
            groups.suspicious.items.push(f);
        } else if (f.is_decompiled) {
            groups.decompiled.items.push(f);
        } else if (f.is_renamed) {
            groups.renamed.items.push(f);
        } else {
            groups.other.items.push(f);
        }
    }
    var order = ['flagged', 'suspicious', 'decompiled', 'renamed', 'other', 'library'];
    var html = '<div class="tree-controls p-6-12"><button class="btn btn-triage" data-tree-action="expand-all">EXPAND ALL</button> <button class="btn btn-triage" data-tree-action="collapse-all">COLLAPSE ALL</button></div>';
    for (var g = 0; g < order.length; g++) {
        var key = order[g];
        var group = groups[key];
        if (!group.items.length) continue;
        html += '<div class="tree-group ' + group.cls + '">';
        html += '<div class="tree-group-header" data-tree-action="toggle">';
        html += '<span class="tree-expand-icon">&#9660;</span> ';
        html += escapeHtml(group.label) + ' <span class="badge badge-dim">' + group.items.length + '</span>';
        html += '</div>';
        html += '<div class="tree-items">';
        for (var j = 0; j < group.items.length; j++) {
            var fn = group.items[j];
            var triageClass = 'dot-' + (fn.triage_status || 'unreviewed');
            html += '<div class="tree-item xref-clickable" data-addr="' + escapeHtml(fn.address) + '" data-tree-action="nav-func">';
            html += '<span class="xref-triage-dot ' + triageClass + '"></span> ';
            html += '<span class="tree-item-addr mono dim">' + escapeHtml(fn.address) + '</span> ';
            html += '<span class="tree-item-name">' + escapeHtml(fn.name) + '</span>';
            if (fn.size) html += ' <span class="dim fs-10">S:' + escapeHtml(String(fn.size)) + '</span>';
            if (fn.complexity) html += ' <span class="dim fs-10">C:' + escapeHtml(String(fn.complexity)) + '</span>';
            if (fn.score) html += ' <span class="dim fs-10">E:' + escapeHtml(String(fn.score)) + '</span>';
            html += '</div>';
        }
        html += '</div></div>';
    }
    tree.innerHTML = html;
}

function toggleAllTreeGroups(expand) {
    document.querySelectorAll('.tree-group').forEach(function(g) {
        if (expand) g.classList.remove('collapsed');
        else g.classList.add('collapsed');
    });
}

// --- CSP-safe event listeners for Batch 4 buttons ---
(function() {
    // Code search button
    var searchBtn = document.getElementById('code-search-btn');
    if (searchBtn) searchBtn.addEventListener('click', searchDecompiledCode);

    // Code search clear
    var clearBtn = document.getElementById('code-search-clear-btn');
    if (clearBtn) clearBtn.addEventListener('click', clearCodeSearch);

    // Code search enter key
    var codeInput = document.getElementById('code-search');
    if (codeInput) codeInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') searchDecompiledCode();
    });

    // View toggle buttons
    var tableBtn = document.getElementById('view-table-btn');
    var treeBtn = document.getElementById('view-tree-btn');
    if (tableBtn) tableBtn.addEventListener('click', function() { toggleView('table'); });
    if (treeBtn) treeBtn.addEventListener('click', function() { toggleView('tree'); });

    // Delegated click handler for code search result links
    var searchBody = document.getElementById('code-search-body');
    if (searchBody) searchBody.addEventListener('click', function(e) {
        var link = e.target.closest('[data-nav-addr]');
        if (link) {
            e.preventDefault();
            navigateToFunction(link.getAttribute('data-nav-addr'));
        }
    });

    // Delegated click handler for symbol tree actions
    var treeEl = document.getElementById('symbol-tree');
    if (treeEl) treeEl.addEventListener('click', function(e) {
        var el = e.target.closest('[data-tree-action]');
        if (!el) return;
        var action = el.getAttribute('data-tree-action');
        if (action === 'expand-all') toggleAllTreeGroups(true);
        else if (action === 'collapse-all') toggleAllTreeGroups(false);
        else if (action === 'toggle') el.parentNode.classList.toggle('collapsed');
        else if (action === 'nav-func') {
            var addr = el.getAttribute('data-addr');
            if (addr) { toggleView('table'); setTimeout(function() { navigateToFunction(addr); }, 100); }
        }
    });
})();

// showToast is defined in dashboard.js (loaded on all pages via base.html)

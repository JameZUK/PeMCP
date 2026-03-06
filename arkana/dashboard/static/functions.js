/* Arkana Dashboard — Function Explorer */
var _debounceTimer;
var _currentSort = 'address';
var _sortAsc = true;
var _openDetailPanels = {};  // addr -> {decompile: data, activeTab: 'xrefs'}
var _analysisCache = {};     // addr -> fetched analysis data

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
    fetch(url).then(function(r) { return r.json(); }).then(function(data) {
        var tbody = document.getElementById('func-tbody');
        document.getElementById('func-count').textContent = data.length;
        if (!data.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-msg">No matching functions.</td></tr>';
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
            html += '<tr class="triage-' + f.triage_status + noteClass + exploredClass + renamedClass + '" data-addr="' + escapeHtml(f.address) + '">';
            html += '<td class="mono">' + f.address + '</td>';
            html += '<td>' + statusTags + escapeHtml(f.name) + noteIndicator + '</td>';
            html += '<td>' + f.size + '</td>';
            html += '<td>' + f.complexity + '</td>';
            html += '<td><span class="badge badge-' + f.triage_status + '">' + f.triage_status.toUpperCase() + '</span></td>';
            html += '<td class="triage-btns">';
            var safeAddr = escapeHtml(f.address);
            html += '<button class="btn-triage btn-analysis" data-addr="' + safeAddr + '" title="Cross-references &amp; analysis">XREF</button>';
            html += '<button class="btn-triage btn-decompile' + (f.is_decompiled ? ' active' : '') + '" data-addr="' + safeAddr + '" title="Decompile">DEC</button>';
            html += '<button class="btn-triage btn-flag' + (f.triage_status === 'flagged' ? ' active' : '') + '" data-addr="' + safeAddr + '" data-status="flagged">FLAG</button>';
            html += '<button class="btn-triage btn-suspicious' + (f.triage_status === 'suspicious' ? ' active' : '') + '" data-addr="' + safeAddr + '" data-status="suspicious">SUS</button>';
            html += '<button class="btn-triage btn-clean' + (f.triage_status === 'clean' ? ' active' : '') + '" data-addr="' + safeAddr + '" data-status="clean">CLN</button>';
            html += '</td></tr>';
            if (f.has_note && f.notes) {
                html += '<tr class="note-row">';
                html += '<td colspan="6"><div class="func-notes">';
                f.notes.forEach(function(n) {
                    html += '<div class="func-note-text">' + escapeHtml(n) + '</div>';
                });
                html += '</div></td></tr>';
            }
        });
        tbody.innerHTML = html;
        _restoreDetailPanels();
    });
}
function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}
function setTriage(addr, status) {
    fetch('/dashboard/api/triage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({address: addr, status: status})
    }).then(function() { reloadFunctions(); });
}

// Bind all event listeners on DOMContentLoaded
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('#func-table th.sortable').forEach(function(th) {
        th.addEventListener('click', function() {
            sortBy(th.dataset.sort);
        });
    });

    var triageSelect = document.getElementById('filter-triage');
    if (triageSelect) triageSelect.addEventListener('change', reloadFunctions);

    var searchInput = document.getElementById('filter-search');
    if (searchInput) searchInput.addEventListener('keyup', debounceReload);

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
            } else {
                // Toggle: if already active, reset to unreviewed
                var status = btn.classList.contains('active') ? 'unreviewed' : btn.dataset.status;
                setTriage(btn.dataset.addr, status);
            }
        });
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
    _openDetailPanels[addr] = _openDetailPanels[addr] || {};
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
    fetch('/dashboard/api/decompile?address=' + encodeURIComponent(addr))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.cached) {
                _openDetailPanels[addr] = _openDetailPanels[addr] || {};
                _openDetailPanels[addr].decompile = data;
                _openDetailPanels[addr].activeTab = 'code';
                insertDetailPanel(row, addr, 'code');
                btn.textContent = 'DEC';
                btn.classList.add('active');
            } else {
                // Trigger decompilation
                btn.textContent = '<<<';
                fetch('/dashboard/api/decompile', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({address: addr})
                }).then(function(r) { return r.json(); })
                .then(function(result) {
                    btn.textContent = 'DEC';
                    if (result.cached || result.lines) {
                        _openDetailPanels[addr] = _openDetailPanels[addr] || {};
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
    td.setAttribute('colspan', '6');
    var panel = document.createElement('div');
    panel.className = 'decompile-panel';

    // Tab bar
    var tabBar = document.createElement('div');
    tabBar.className = 'detail-tab-bar';
    var tabs = ['XREFS', 'STRINGS', 'CODE'];
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
    var lineInfo = decData ? ' &middot; ' + (decData.line_count || 0) + ' lines' : '';
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
            container.innerHTML = '<div class="dim" style="padding:10px;">Not yet decompiled. Click <b>DEC</b> to decompile this function.</div>';
        }
    } else if (tab === 'xrefs') {
        container.innerHTML = '<div class="dim" style="padding:10px;">Loading analysis...</div>';
        fetchAnalysis(addr, function(data) {
            if (data) {
                renderXrefsTab(container, data);
            } else {
                container.innerHTML = '<div class="dim" style="padding:10px;">Failed to load cross-references.</div>';
            }
        });
    } else if (tab === 'strings') {
        container.innerHTML = '<div class="dim" style="padding:10px;">Loading strings...</div>';
        fetch('/dashboard/api/function-strings?address=' + encodeURIComponent(addr))
            .then(function(r) { return r.json(); })
            .then(function(data) { renderStringsTab(container, data); })
            .catch(function() { container.innerHTML = '<div class="dim" style="padding:10px;">Failed to load strings.</div>'; });
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
    fetch('/dashboard/api/function-analysis?address=' + encodeURIComponent(addr))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            _analysisCache[addr] = data;
            callback(data);
        })
        .catch(function() { callback(null); });
}

// --- Tab renderers ---
function renderXrefsTab(container, data) {
    var html = '<div style="padding:10px;">';

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
    html += '<div style="font-size:10px;letter-spacing:2px;color:var(--primary-dim);margin-bottom:6px;">CALLERS (' + callers.length + ')</div>';
    if (callers.length) {
        for (var i = 0; i < callers.length; i++) {
            var c = callers[i];
            var dotClass = 'xref-triage-dot dot-' + (c.triage || 'unreviewed');
            html += '<div class="xref-clickable xref-entry" data-addr="' + escapeHtml(c.address) + '" title="Go to ' + escapeHtml(c.address) + '">';
            html += '<span class="' + dotClass + '"></span> ';
            html += '<span class="mono dim">' + escapeHtml(c.address) + '</span> ';
            html += '<span>' + escapeHtml(c.name) + '</span>';
            if (c.complexity) html += ' <span class="dim" style="font-size:10px;">C:' + c.complexity + '</span>';
            html += '</div>';
        }
    } else {
        html += '<div class="dim" style="font-size:12px;">No callers found</div>';
    }

    // Callees
    var callees = data.callees || [];
    html += '<div style="font-size:10px;letter-spacing:2px;color:var(--primary-dim);margin:10px 0 6px;">CALLEES (' + callees.length + ')</div>';
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
                html += ' <span class="badge ' + riskClass + '" style="font-size:9px;">' + escapeHtml(c.suspicious.risk) + '</span>';
            }
            if (c.complexity) html += ' <span class="dim" style="font-size:10px;">C:' + c.complexity + '</span>';
            html += '</div>';
        }
    } else {
        html += '<div class="dim" style="font-size:12px;">No callees found</div>';
    }

    // Complexity
    if (data.complexity) {
        html += '<div style="margin-top:10px; font-size:10px; letter-spacing:1px; color:var(--primary-dim);">';
        html += 'BLOCKS: ' + (data.complexity.blocks || 0) + ' / EDGES: ' + (data.complexity.edges || 0);
        html += '</div>';
    }

    html += '</div>';
    container.innerHTML = html;
}

function renderStringsTab(container, data) {
    var strings = data.strings || [];
    if (!strings.length) {
        container.innerHTML = '<div class="dim" style="padding:10px;">No strings associated with this function.</div>';
        return;
    }
    var html = '<table class="data-table" style="font-size:12px;"><thead><tr><th>TYPE</th><th>ADDRESS</th><th>STRING</th></tr></thead><tbody>';
    var typeBadge = {'STATIC':'badge-str-static','STACK':'badge-str-stack','TIGHT':'badge-str-tight'};
    for (var i = 0; i < strings.length; i++) {
        var s = strings[i];
        var bc = typeBadge[s.type] || 'badge-dim';
        var truncated = s.string.length > 120 ? s.string.substring(0, 120) + '...' : s.string;
        html += '<tr><td><span class="badge ' + bc + '">' + s.type + '</span></td>';
        html += '<td class="mono dim">' + escapeHtml(s.address || '') + '</td>';
        html += '<td class="str-content">' + escapeHtml(truncated) + '</td></tr>';
    }
    html += '</tbody></table>';
    container.innerHTML = html;
}

// --- Navigation ---
function navigateToFunction(addr) {
    var tbody = document.getElementById('func-tbody');
    if (!tbody) return;
    // Find the row with this address
    var targetRow = tbody.querySelector('tr[data-addr="' + addr + '"]');
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
            var row = tbody.querySelector('tr[data-addr="' + addr + '"]');
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
        var row = tbody.querySelector('tr[data-addr="' + addr + '"]');
        if (row) {
            var panelData = _openDetailPanels[addr];
            var tab = (panelData && panelData.activeTab) || 'xrefs';
            insertDetailPanel(row, addr, tab);
        }
    });
}

function showToast(msg, type) {
    var container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    var toast = document.createElement('div');
    toast.className = 'toast toast-' + (type || 'info');
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(function() { toast.remove(); }, 4000);
}

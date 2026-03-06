/* Arkana Dashboard — Function Explorer */
var _debounceTimer;
var _currentSort = 'address';
var _sortAsc = true;
var _openDecompilePanels = {};  // addr -> cached data (survives reloads)

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
            html += '<tr class="triage-' + f.triage_status + noteClass + exploredClass + renamedClass + '">';
            html += '<td class="mono">' + f.address + '</td>';
            html += '<td>' + statusTags + escapeHtml(f.name) + noteIndicator + '</td>';
            html += '<td>' + f.size + '</td>';
            html += '<td>' + f.complexity + '</td>';
            html += '<td><span class="badge badge-' + f.triage_status + '">' + f.triage_status.toUpperCase() + '</span></td>';
            html += '<td class="triage-btns">';
            var safeAddr = escapeHtml(f.address);
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
        // Restore open decompile panels
        _restoreDecompilePanels();
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
    // Sort column headers
    document.querySelectorAll('#func-table th.sortable').forEach(function(th) {
        th.addEventListener('click', function() {
            sortBy(th.dataset.sort);
        });
    });

    // Filter controls
    var triageSelect = document.getElementById('filter-triage');
    if (triageSelect) triageSelect.addEventListener('change', reloadFunctions);

    var searchInput = document.getElementById('filter-search');
    if (searchInput) searchInput.addEventListener('keyup', debounceReload);

    // Triage buttons — use event delegation on the tbody
    var tbody = document.getElementById('func-tbody');
    if (tbody) {
        tbody.addEventListener('click', function(e) {
            var btn = e.target.closest('.btn-triage');
            if (!btn) return;
            if (btn.classList.contains('btn-decompile')) {
                toggleDecompile(btn);
            } else {
                // Toggle: if already active, reset to unreviewed
                var status = btn.classList.contains('active') ? 'unreviewed' : btn.dataset.status;
                setTriage(btn.dataset.addr, status);
            }
        });
    }
});

// --- Decompile ---
function toggleDecompile(btn) {
    var addr = btn.dataset.addr;
    var row = btn.closest('tr');
    // Check if panel already exists below this row
    var nextRow = row.nextElementSibling;
    while (nextRow && nextRow.classList.contains('note-row')) {
        nextRow = nextRow.nextElementSibling;
    }
    if (nextRow && nextRow.classList.contains('decompile-row')) {
        // Toggle: remove from tracking and hide
        nextRow.remove();
        delete _openDecompilePanels[addr];
        return;
    }
    // Already have cached data from a previous open? Re-insert immediately.
    if (_openDecompilePanels[addr]) {
        insertDecompilePanel(row, addr, _openDecompilePanels[addr]);
        return;
    }
    // Try server cache first
    btn.textContent = '...';
    fetch('/dashboard/api/decompile?address=' + encodeURIComponent(addr))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.cached) {
                _openDecompilePanels[addr] = data;
                insertDecompilePanel(row, addr, data);
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
                        _openDecompilePanels[addr] = result;
                        insertDecompilePanel(row, addr, result);
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

function insertDecompilePanel(afterRow, addr, data) {
    // Find the correct insertion point (after note rows)
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
    var header = document.createElement('div');
    header.className = 'decompile-panel-header';
    header.innerHTML = '<span class="decompile-func-name">' + escapeHtml(data.function_name || addr) +
        '</span> <span class="dim">(' + escapeHtml(data.address || addr) + ' &middot; ' +
        (data.line_count || 0) + ' lines)</span>';
    var pre = document.createElement('pre');
    pre.className = 'decompile-code';
    pre.textContent = (data.lines || []).join('\n');
    panel.appendChild(header);
    panel.appendChild(pre);
    td.appendChild(panel);
    tr.appendChild(td);
    insertAfter.parentNode.insertBefore(tr, insertAfter.nextSibling);
}

function _restoreDecompilePanels() {
    var addrs = Object.keys(_openDecompilePanels);
    if (!addrs.length) return;
    var tbody = document.getElementById('func-tbody');
    if (!tbody) return;
    addrs.forEach(function(addr) {
        // Find the function row with this address
        var rows = tbody.querySelectorAll('tr');
        for (var i = 0; i < rows.length; i++) {
            var btn = rows[i].querySelector('.btn-decompile[data-addr="' + addr + '"]');
            if (btn) {
                insertDecompilePanel(rows[i], addr, _openDecompilePanels[addr]);
                break;
            }
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

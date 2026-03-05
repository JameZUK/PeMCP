/* Arkana Dashboard — Function Explorer */
var _debounceTimer;
var _currentSort = 'address';
var _sortAsc = true;

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
            if (btn) {
                setTriage(btn.dataset.addr, btn.dataset.status);
            }
        });
    }
});

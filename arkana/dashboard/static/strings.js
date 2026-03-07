/* Arkana Dashboard — Strings Page */
var _strSort = 'score';
var _strSortAsc = false;
var _strOffset = 0;
var _strLimit = 100;
var _strDebounce;

function strEscapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function reloadStrings() {
    var type = document.getElementById('str-filter-type').value;
    var cat = document.getElementById('str-filter-cat').value;
    var score = document.getElementById('str-filter-score').value;
    var search = document.getElementById('str-filter-search').value;
    var url = '/dashboard/api/strings?type=' + encodeURIComponent(type) +
        '&category=' + encodeURIComponent(cat) +
        '&min_score=' + encodeURIComponent(score || '0') +
        '&search=' + encodeURIComponent(search) +
        '&sort=' + encodeURIComponent(_strSort) +
        '&asc=' + (_strSortAsc ? '1' : '0') +
        '&offset=' + _strOffset +
        '&limit=' + _strLimit;
    fetch(url).then(function(r) { return r.json(); }).then(function(data) {
        renderStringTable(data);
        renderStats(data);
        renderPagination(data);
    }).catch(function() {
        document.getElementById('str-tbody').innerHTML =
            '<tr><td colspan="7" class="empty-msg">Failed to load strings.</td></tr>';
    });
}

function renderStringTable(data) {
    var tbody = document.getElementById('str-tbody');
    var strings = data.strings || [];
    if (!strings.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-msg">No matching strings.</td></tr>';
        return;
    }
    var html = '';
    var typeBadge = {
        'ASCII': 'badge-str-ascii',
        'STATIC': 'badge-str-static',
        'STACK': 'badge-str-stack',
        'DECODED': 'badge-str-decoded',
        'TIGHT': 'badge-str-tight'
    };
    for (var i = 0; i < strings.length; i++) {
        var s = strings[i];
        var badgeClass = typeBadge[s.type] || 'badge-dim';
        var catBadge = s.category ? '<span class="badge badge-dim">' + strEscapeHtml(s.category) + '</span>' : '';
        var score = (typeof s.sifter_score === 'number') ? s.sifter_score : 0;
        var truncated = s.string.length > 200 ? s.string.substring(0, 200) + '...' : s.string;
        html += '<tr>';
        html += '<td class="mono">' + strEscapeHtml(s.address || '') + '</td>';
        html += '<td><span class="string-score">' + score + '</span></td>';
        html += '<td><span class="badge ' + badgeClass + '">' + s.type + '</span></td>';
        html += '<td class="str-content" title="' + strEscapeHtml(s.string) + '">' + strEscapeHtml(truncated) + '</td>';
        html += '<td>' + catBadge + '</td>';
        html += '<td>';
        if (s.func_addr) {
            html += '<a href="/dashboard/functions?highlight=' + encodeURIComponent(s.func_addr) + '" class="func-link">&rarr; ' + strEscapeHtml(s.func_name || s.func_addr) + '</a>';
        }
        html += '</td>';
        html += '<td><button class="btn-copy btn-triage" data-str="' + i + '" title="Copy to clipboard">CPY</button></td>';
        html += '</tr>';
    }
    tbody.innerHTML = html;
    // Store strings for copy
    tbody._strings = strings;
}

function renderStats(data) {
    var statTotal = document.getElementById('stat-total');
    if (statTotal) statTotal.textContent = data.total_unfiltered || 0;

    var statTypes = document.getElementById('stat-types');
    if (statTypes && data.type_counts) {
        var html = '';
        var types = Object.keys(data.type_counts);
        for (var i = 0; i < types.length; i++) {
            html += '<div class="stat-row"><span class="stat-label">' + types[i] + '</span><span>' + data.type_counts[types[i]] + '</span></div>';
        }
        statTypes.innerHTML = html;
    }

    var statCats = document.getElementById('stat-cats');
    if (statCats && data.category_counts) {
        var html = '';
        var cats = Object.keys(data.category_counts);
        for (var i = 0; i < cats.length; i++) {
            html += '<div class="stat-row"><span class="stat-label">' + cats[i] + '</span><span>' + data.category_counts[cats[i]] + '</span></div>';
        }
        statCats.innerHTML = html || '<div class="dim p-6-0 fs-12">No categories</div>';
    }

    var strTotal = document.getElementById('str-total');
    if (strTotal) strTotal.textContent = data.total + ' of ' + data.total_unfiltered + ' strings';
}

function renderPagination(data) {
    var prev = document.getElementById('str-prev');
    var next = document.getElementById('str-next');
    var info = document.getElementById('str-page-info');
    var start = data.offset + 1;
    var end = Math.min(data.offset + data.limit, data.total);
    if (data.total === 0) {
        info.textContent = '0 strings';
    } else {
        info.textContent = start + '-' + end + ' of ' + data.total;
    }
    prev.disabled = data.offset <= 0;
    next.disabled = (data.offset + data.limit) >= data.total;
}

function copyString(str) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(str).then(function() {
            showToast('Copied to clipboard', 'success');
        });
    }
}

function strSortBy(col) {
    if (_strSort === col) {
        _strSortAsc = !_strSortAsc;
    } else {
        _strSort = col;
        _strSortAsc = col === 'type' || col === 'address';
    }
    _strOffset = 0;
    document.querySelectorAll('#str-table th.sortable').forEach(function(th) {
        var arrow = th.querySelector('.sort-arrow');
        if (th.dataset.sort === col) {
            th.classList.add('active');
            arrow.innerHTML = _strSortAsc ? '&#9650;' : '&#9660;';
        } else {
            th.classList.remove('active');
            arrow.innerHTML = '';
        }
    });
    reloadStrings();
}

function strDebounceReload() {
    clearTimeout(_strDebounce);
    _strDebounce = setTimeout(function() {
        _strOffset = 0;
        reloadStrings();
    }, 300);
}

document.addEventListener('DOMContentLoaded', function() {
    // Sort headers
    document.querySelectorAll('#str-table th.sortable').forEach(function(th) {
        th.addEventListener('click', function() {
            strSortBy(th.dataset.sort);
        });
    });

    // Default sort arrow
    var defaultTh = document.querySelector('#str-table th[data-sort="score"]');
    if (defaultTh) {
        defaultTh.classList.add('active');
        defaultTh.querySelector('.sort-arrow').innerHTML = '&#9660;';
    }

    // Filter controls
    var typeSelect = document.getElementById('str-filter-type');
    if (typeSelect) typeSelect.addEventListener('change', function() { _strOffset = 0; reloadStrings(); });

    var catInput = document.getElementById('str-filter-cat');
    if (catInput) catInput.addEventListener('keyup', strDebounceReload);

    var scoreInput = document.getElementById('str-filter-score');
    if (scoreInput) scoreInput.addEventListener('keyup', strDebounceReload);

    var searchInput = document.getElementById('str-filter-search');
    if (searchInput) searchInput.addEventListener('keyup', strDebounceReload);

    // Pagination
    document.getElementById('str-prev').addEventListener('click', function() {
        _strOffset = Math.max(0, _strOffset - _strLimit);
        reloadStrings();
    });
    document.getElementById('str-next').addEventListener('click', function() {
        _strOffset += _strLimit;
        reloadStrings();
    });

    // Copy delegation
    var tbody = document.getElementById('str-tbody');
    if (tbody) {
        tbody.addEventListener('click', function(e) {
            var btn = e.target.closest('.btn-copy');
            if (!btn) return;
            var idx = parseInt(btn.dataset.str, 10);
            if (tbody._strings && tbody._strings[idx]) {
                copyString(tbody._strings[idx].string);
            }
        });
    }

    // FLOSS panel toggle
    var flossToggle = document.getElementById('floss-panel-toggle');
    if (flossToggle) {
        flossToggle.addEventListener('click', function() {
            var body = document.getElementById('floss-panel-body');
            var hint = document.getElementById('floss-collapse-hint');
            if (body.style.display === 'none') {
                body.style.display = '';
                hint.textContent = '[collapse]';
            } else {
                body.style.display = 'none';
                hint.textContent = '[expand]';
            }
        });
    }

    // Initial load
    reloadStrings();
    loadFlossPanel();
});

var _flossRefreshTimer = null;

function loadFlossPanel() {
    fetch('/dashboard/api/floss-summary').then(function(r) { return r.json(); }).then(function(data) {
        renderFlossPanel(data);
    }).catch(function() {});
}

function renderFlossPanel(data) {
    var panel = document.getElementById('floss-panel');
    if (!data || !data.available) {
        panel.style.display = 'none';
        return;
    }
    panel.style.display = '';

    // Status badge
    var badge = document.getElementById('floss-status-badge');
    var status = (data.status || 'unknown').toUpperCase();
    badge.textContent = status;
    badge.className = 'badge';
    if (status === 'COMPLETE' || status === 'COMPLETED') {
        badge.classList.add('badge-completed');
    } else if (status === 'RUNNING' || status === 'IN_PROGRESS') {
        badge.classList.add('badge-running');
    } else if (status === 'FAILED' || status === 'ERROR') {
        badge.classList.add('badge-failed');
    } else {
        badge.classList.add('badge-dim');
    }

    // Type counts
    var countsEl = document.getElementById('floss-type-counts');
    var tc = data.type_counts || {};
    var typeColors = {
        'STATIC': 'badge-str-static',
        'STACK': 'badge-str-stack',
        'DECODED': 'badge-str-decoded',
        'TIGHT': 'badge-str-tight'
    };
    var html = '';
    var types = ['STATIC', 'STACK', 'DECODED', 'TIGHT'];
    for (var i = 0; i < types.length; i++) {
        var t = types[i];
        var c = tc[t] || 0;
        html += '<div class="floss-type-row">';
        html += '<span class="badge ' + (typeColors[t] || 'badge-dim') + '">' + t + '</span>';
        html += '<span class="floss-type-count">' + c + '</span>';
        html += '</div>';
    }
    html += '<div class="floss-type-row floss-type-total">';
    html += '<span class="dim">TOTAL</span>';
    html += '<span>' + (data.total_floss_strings || 0) + '</span>';
    html += '</div>';
    countsEl.innerHTML = html;

    // Top decoded
    var decodedSection = document.getElementById('floss-top-decoded');
    var decodedList = document.getElementById('floss-decoded-list');
    if (data.top_decoded && data.top_decoded.length > 0) {
        decodedSection.style.display = '';
        decodedList.innerHTML = data.top_decoded.map(function(s) {
            return '<div class="floss-string-item">' + strEscapeHtml(s) + '</div>';
        }).join('');
    } else {
        decodedSection.style.display = 'none';
    }

    // Top stack
    var stackSection = document.getElementById('floss-top-stack');
    var stackList = document.getElementById('floss-stack-list');
    if (data.top_stack && data.top_stack.length > 0) {
        stackSection.style.display = '';
        stackList.innerHTML = data.top_stack.map(function(s) {
            return '<div class="floss-string-item">' + strEscapeHtml(s) + '</div>';
        }).join('');
    } else {
        stackSection.style.display = 'none';
    }

    // Metadata
    var metaEl = document.getElementById('floss-meta');
    var metaParts = [];
    if (data.floss_version) metaParts.push('FLOSS ' + strEscapeHtml(data.floss_version));
    var cfg = data.analysis_config || {};
    if (cfg.min_length) metaParts.push('min_length=' + cfg.min_length);
    if (cfg.timeout) metaParts.push('timeout=' + cfg.timeout);
    if (metaParts.length) {
        metaEl.style.display = '';
        metaEl.innerHTML = metaParts.join(' &middot; ');
    } else {
        metaEl.style.display = 'none';
    }

    // Auto-refresh while not complete
    if (_flossRefreshTimer) clearInterval(_flossRefreshTimer);
    if (status !== 'COMPLETE' && status !== 'COMPLETED' && status !== 'FAILED' && status !== 'ERROR') {
        _flossRefreshTimer = setInterval(loadFlossPanel, 5000);
    }
}

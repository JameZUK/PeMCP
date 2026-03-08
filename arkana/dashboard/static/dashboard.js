/* Arkana Dashboard — htmx config + SSE handler + toast notifications */

// Global HTML escape helper — used by functions.js, strings.js, and this file
function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

// CSRF token helper — reads from <meta name="csrf-token">
function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Apply data-width attributes as inline styles (for CSP-compliant dynamic widths)
function applyDataWidths(root) {
    (root || document).querySelectorAll('[data-width]').forEach(function(el) {
        var w = parseFloat(el.dataset.width);
        if (!isNaN(w)) el.style.width = w + '%';
    });
}
document.addEventListener('DOMContentLoaded', function() { applyDataWidths(); });
document.addEventListener('htmx:afterSwap', function(e) { applyDataWidths(e.detail.target); });

// Strip ?token= from URL after login (if present)
(function() {
    var params = new URLSearchParams(window.location.search);
    if (params.has('token') && window.location.pathname !== '/dashboard/login') {
        params.delete('token');
        var newUrl = window.location.pathname;
        var remaining = params.toString();
        if (remaining) newUrl += '?' + remaining;
        window.history.replaceState({}, '', newUrl);
    }
})();

// Toast notification system
function showToast(message, type) {
    var container = document.getElementById('toast-container');
    if (!container) return;
    var toast = document.createElement('div');
    toast.className = 'toast toast-' + (type || 'success');
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(function() {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        setTimeout(function() { toast.remove(); }, 300);
    }, 5000);
}

// SSE connection for live updates (all pages)
(function() {
    var evtSource = null;
    var lastActiveTool = null;
    var lastTaskRunning = 0;
    var lastExploredFuncs = -1;
    var reconnectDelay = 2000;
    var maxReconnectDelay = 30000;
    var disconnected = false;

    function setDisconnected(state) {
        disconnected = state;
        var indicator = document.getElementById('sse-disconnect');
        if (!indicator) {
            // Create the indicator in the nav bar
            var nav = document.querySelector('.top-nav');
            if (nav) {
                indicator = document.createElement('span');
                indicator.id = 'sse-disconnect';
                indicator.className = 'sse-disconnect';
                indicator.textContent = 'DISCONNECTED';
                indicator.style.display = 'none';
                nav.appendChild(indicator);
            }
        }
        if (indicator) {
            indicator.style.display = state ? 'inline-block' : 'none';
        }
    }

    function refreshPageElements() {
        if (!window.htmx) return;
        // Refresh whichever htmx-polled elements exist on the current page
        var targets = ['#overview-stats', '#task-list', '#timeline-entries'];
        for (var i = 0; i < targets.length; i++) {
            var el = document.querySelector(targets[i]);
            if (el) htmx.trigger(el, 'htmx:load');
        }
    }

    function handleStateUpdate(data) {
        // Update nav filename indicator
        var fnEl = document.getElementById('nav-filename');
        if (fnEl) {
            fnEl.textContent = data.filename || '';
        }

        // Toast: tool completed
        var currentTool = data.active_tool || null;
        if (lastActiveTool && !currentTool) {
            showToast(lastActiveTool + ' completed', 'success');
        }
        lastActiveTool = currentTool;

        // Toast: background task completed/failed
        var tasks = data.background_tasks || [];
        var running = 0;
        for (var i = 0; i < tasks.length; i++) {
            if (tasks[i].status === 'running') running++;
        }
        if (running < lastTaskRunning && lastTaskRunning > 0) {
            showToast('Background task finished', 'info');
        }
        lastTaskRunning = running;

        // Track explored (decompiled) function count — trigger reload when it changes
        var exploredFuncs = data.explored_functions || 0;
        if (lastExploredFuncs >= 0 && exploredFuncs !== lastExploredFuncs) {
            document.dispatchEvent(new CustomEvent('arkana-explored-changed', {
                detail: {count: exploredFuncs, prev: lastExploredFuncs}
            }));
        }
        lastExploredFuncs = exploredFuncs;

        refreshPageElements();
    }

    function connectSSE() {
        if (evtSource) evtSource.close();
        evtSource = new EventSource('/dashboard/api/events');

        evtSource.addEventListener('state-update', function(e) {
            // Reset backoff on successful message
            reconnectDelay = 2000;
            setDisconnected(false);
            try {
                var data = JSON.parse(e.data);
                handleStateUpdate(data);
            } catch (err) {
                refreshPageElements();
            }
        });

        evtSource.addEventListener('file-changed', function(e) {
            reconnectDelay = 2000;
            setDisconnected(false);
            showToast('New file loaded — refreshing...', 'info');
            setTimeout(function() {
                window.location.reload();
            }, 500);
        });

        evtSource.addEventListener('decompile-update', function(e) {
            reconnectDelay = 2000;
            setDisconnected(false);
            try {
                var data = JSON.parse(e.data);
                document.dispatchEvent(new CustomEvent('arkana-decompile-update', {detail: data}));
            } catch (err) {}
        });

        evtSource.onopen = function() {
            reconnectDelay = 2000;
            setDisconnected(false);
        };

        evtSource.onerror = function() {
            if (evtSource) evtSource.close();
            setDisconnected(true);
            // Exponential backoff: 2s, 4s, 8s, 16s, max 30s
            setTimeout(connectSSE, reconnectDelay);
            reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay);
        };
    }
    // Delay SSE connection until page is fully loaded
    if (document.readyState === 'complete') {
        connectSSE();
    } else {
        window.addEventListener('load', connectSSE);
    }

    // Cleanly close SSE before page unload to prevent Firefox
    // "interrupted while the page was loading" warnings
    window.addEventListener('beforeunload', function() {
        if (evtSource) {
            evtSource.close();
            evtSource = null;
        }
    });
})();

// Global search (keyboard shortcut: "/")
(function() {
    var searchInput = document.getElementById('global-search-input');
    var dropdown = document.getElementById('search-dropdown');
    if (!searchInput || !dropdown) return;
    var debounceTimer;

    function doSearch() {
        var q = searchInput.value.trim();
        if (q.length < 2) {
            dropdown.classList.add('hidden');
            return;
        }
        fetch('/dashboard/api/search?q=' + encodeURIComponent(q))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                renderDropdown(data, q);
            })
            .catch(function() {
                dropdown.innerHTML = '<div class="search-empty">Search failed</div>';
                dropdown.classList.remove('hidden');
            });
    }

    function renderDropdown(data, q) {
        var html = '';
        var groups = [
            {key: 'functions', label: 'FUNCTIONS', render: function(item) {
                return '<a class="search-result" href="/dashboard/functions?search=' + encodeURIComponent(item.name) + '">' +
                    '<span class="mono dim">' + escapeHtml(item.address) + '</span> ' + escapeHtml(item.name) + '</a>';
            }},
            {key: 'strings', label: 'STRINGS', render: function(item) {
                return '<a class="search-result" href="/dashboard/strings?search=' + encodeURIComponent(q) + '">' +
                    '<span class="badge badge-dim fs-9">' + escapeHtml(item.type) + '</span> ' + escapeHtml(item.string) + '</a>';
            }},
            {key: 'imports', label: 'IMPORTS', render: function(item) {
                return '<a class="search-result" href="/dashboard/imports">' +
                    '<span class="dim">' + escapeHtml(item.dll) + '</span> ' + escapeHtml(item.function) + '</a>';
            }},
            {key: 'notes', label: 'NOTES', render: function(item) {
                return '<a class="search-result" href="/dashboard/notes">' +
                    '<span class="badge badge-dim fs-9">' + escapeHtml(item.category) + '</span> ' + escapeHtml(item.content) + '</a>';
            }}
        ];

        var hasResults = false;
        for (var i = 0; i < groups.length; i++) {
            var g = groups[i];
            var items = data[g.key] || [];
            if (!items.length) continue;
            hasResults = true;
            html += '<div class="search-group-title">' + g.label + '</div>';
            for (var j = 0; j < items.length; j++) {
                html += g.render(items[j]);
            }
        }

        if (!hasResults) {
            html = '<div class="search-empty">No results for "' + escapeHtml(q) + '"</div>';
        }
        dropdown.innerHTML = html;
        dropdown.classList.remove('hidden');
    }

    searchInput.addEventListener('keyup', function(e) {
        if (e.key === 'Escape') {
            dropdown.classList.add('hidden');
            searchInput.blur();
            return;
        }
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(doSearch, 300);
    });

    searchInput.addEventListener('focus', function() {
        if (searchInput.value.trim().length >= 2) doSearch();
    });

    // Close on click outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('#nav-search')) {
            dropdown.classList.add('hidden');
        }
    });

    // "/" keyboard shortcut
    document.addEventListener('keydown', function(e) {
        if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
            var tag = (e.target.tagName || '').toLowerCase();
            if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
            e.preventDefault();
            searchInput.focus();
        }
    });

    // Pre-fill from URL search param
    var urlParams = new URLSearchParams(window.location.search);
    var searchParam = urlParams.get('search');
    if (searchParam) {
        // Set the page-specific filter if it exists
        var pageFilter = document.getElementById('filter-search') || document.getElementById('str-filter-search');
        if (pageFilter && !pageFilter.value) {
            pageFilter.value = searchParam;
            // Trigger reload for the page
            if (typeof reloadFunctions === 'function') reloadFunctions();
            if (typeof reloadStrings === 'function') reloadStrings();
        }
    }
})();

// --- Navigation History (client-side) ---
(function() {
    var _NAV_HISTORY_KEY = 'arkana_nav_history';
    var _NAV_MAX = 50;
    var _navPos = -1;

    function getNavHistory() {
        try {
            return JSON.parse(sessionStorage.getItem(_NAV_HISTORY_KEY) || '[]');
        } catch (e) {
            return [];
        }
    }

    function saveNavHistory(hist) {
        try {
            sessionStorage.setItem(_NAV_HISTORY_KEY, JSON.stringify(hist));
        } catch (e) { /* storage full */ }
    }

    function pushNavHistory(url, label) {
        var hist = getNavHistory();
        // Get current position
        var posKey = 'arkana_nav_pos';
        _navPos = parseInt(sessionStorage.getItem(posKey) || '-1', 10);
        // Truncate forward history
        if (_navPos >= 0 && _navPos < hist.length - 1) {
            hist = hist.slice(0, _navPos + 1);
        }
        // Avoid duplicate consecutive entries
        if (hist.length > 0 && hist[hist.length - 1].url === url) return;
        hist.push({url: url, label: label, timestamp: Date.now()});
        if (hist.length > _NAV_MAX) hist = hist.slice(hist.length - _NAV_MAX);
        _navPos = hist.length - 1;
        saveNavHistory(hist);
        sessionStorage.setItem(posKey, String(_navPos));
    }

    function goBack() {
        var hist = getNavHistory();
        var posKey = 'arkana_nav_pos';
        _navPos = parseInt(sessionStorage.getItem(posKey) || '-1', 10);
        if (_navPos > 0) {
            _navPos--;
            sessionStorage.setItem(posKey, String(_navPos));
            window.location.href = hist[_navPos].url;
        }
    }

    function goForward() {
        var hist = getNavHistory();
        var posKey = 'arkana_nav_pos';
        _navPos = parseInt(sessionStorage.getItem(posKey) || '-1', 10);
        if (_navPos < hist.length - 1) {
            _navPos++;
            sessionStorage.setItem(posKey, String(_navPos));
            window.location.href = hist[_navPos].url;
        }
    }

    // Track page navigation
    var pagePath = window.location.pathname;
    var pageLabel = document.title.replace('Arkana — ', '').replace('Arkana Dashboard', 'OVERVIEW');
    pushNavHistory(pagePath + window.location.search, pageLabel);

    // Keyboard shortcuts: Alt+Left/Right for history
    document.addEventListener('keydown', function(e) {
        if (e.altKey && e.key === 'ArrowLeft') { e.preventDefault(); goBack(); }
        if (e.altKey && e.key === 'ArrowRight') { e.preventDefault(); goForward(); }
    });

    // Expose globally for nav buttons
    window.navGoBack = goBack;
    window.navGoForward = goForward;
})();

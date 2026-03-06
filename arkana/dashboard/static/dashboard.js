/* Arkana Dashboard — htmx config + SSE handler + toast notifications */

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
    connectSSE();
})();

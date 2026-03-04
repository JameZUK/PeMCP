/* Arkana Dashboard — htmx config + SSE handler */

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

// SSE connection for live updates (overview page only)
(function() {
    var statsEl = document.getElementById('overview-stats');
    if (!statsEl) return; // Only on overview page

    var evtSource = null;
    function connectSSE() {
        if (evtSource) evtSource.close();
        evtSource = new EventSource('/dashboard/api/events');
        evtSource.addEventListener('state-update', function(e) {
            // The htmx polling handles UI updates; SSE is a fallback
            // for faster reaction. Trigger htmx refresh.
            if (window.htmx) {
                htmx.trigger('#overview-stats', 'htmx:load');
            }
        });
        evtSource.onerror = function() {
            // Reconnect after 5s on error
            if (evtSource) evtSource.close();
            setTimeout(connectSSE, 5000);
        };
    }
    connectSSE();
})();

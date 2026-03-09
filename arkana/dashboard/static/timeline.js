/* Arkana Dashboard — Timeline expand/collapse + filtering */
var _expandedEntries = Object.create(null);

function toggleTimelineDetail(entry) {
    var detail = entry.querySelector('.timeline-detail');
    var arrow = entry.querySelector('.timeline-expand');
    if (!detail) return;
    var isHidden = detail.classList.contains('hidden');
    detail.classList.toggle('hidden');
    if (arrow) {
        arrow.innerHTML = isHidden ? '&#9660;' : '&#9654;';
    }
    entry.classList.toggle('expanded', isHidden);

    var id = entry.getAttribute('data-entry-id');
    if (id) {
        if (isHidden) { _expandedEntries[id] = true; }
        else { delete _expandedEntries[id]; }
    }
}

function _restoreExpanded() {
    var entries = document.querySelectorAll('.timeline-entry[data-entry-id]');
    entries.forEach(function(entry) {
        var id = entry.getAttribute('data-entry-id');
        if (_expandedEntries[id]) {
            var detail = entry.querySelector('.timeline-detail');
            var arrow = entry.querySelector('.timeline-expand');
            if (detail) {
                detail.classList.remove('hidden');
                entry.classList.add('expanded');
                if (arrow) { arrow.innerHTML = '&#9660;'; }
            }
        }
    });
}

// Event delegation for expandable timeline entries
document.addEventListener('click', function(e) {
    var entry = e.target.closest('.timeline-entry.expandable');
    if (entry) {
        toggleTimelineDetail(entry);
    }
});

document.body.addEventListener('htmx:afterSwap', function(evt) {
    if (evt.detail.target && evt.detail.target.id === 'timeline-entries') {
        _restoreExpanded();
        _applyTimelineFilters();
    }
});

// --- Filtering ---
(function () {
    "use strict";

    var searchInput = document.getElementById("timeline-search");
    var typeFilter = document.getElementById("timeline-type-filter");
    var countBadge = document.getElementById("timeline-count");
    var debounceTimer = null;

    function applyFilters() {
        var container = document.querySelector("#timeline-entries .timeline");
        if (!container) return;

        var query = searchInput ? searchInput.value.trim().toLowerCase() : "";
        var typeVal = typeFilter ? typeFilter.value : "";
        var entries = container.querySelectorAll(".timeline-entry");
        var visible = 0;

        entries.forEach(function (entry) {
            var show = true;

            // Type filter
            if (typeVal) {
                var hasClass = entry.classList.contains("type-" + typeVal);
                if (!hasClass) show = false;
            }

            // Text search
            if (show && query) {
                var name = (entry.querySelector(".timeline-name") || {}).textContent || "";
                var summary = (entry.querySelector(".timeline-summary") || {}).textContent || "";
                var text = (name + " " + summary).toLowerCase();
                if (text.indexOf(query) === -1) show = false;
            }

            entry.style.display = show ? "" : "none";
            if (show) visible++;
        });

        if (countBadge) countBadge.textContent = String(visible);
    }

    // Expose for htmx:afterSwap
    window._applyTimelineFilters = applyFilters;

    if (searchInput) {
        searchInput.addEventListener("input", function () {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(applyFilters, 150);
        });
    }

    if (typeFilter) {
        typeFilter.addEventListener("change", applyFilters);
    }
})();

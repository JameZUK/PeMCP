/* Arkana Dashboard — Timeline expand/collapse */
var _expandedEntries = {};

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
    }
});

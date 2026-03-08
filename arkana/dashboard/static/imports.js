/* Arkana Dashboard — Imports page filter */

function filterImports() {
    var q = document.getElementById('import-search').value.toLowerCase();
    var groups = document.querySelectorAll('.import-dll-group');
    for (var i = 0; i < groups.length; i++) {
        var dll = (groups[i].getAttribute('data-dll') || '').toLowerCase();
        var rows = groups[i].querySelectorAll('.import-func-row');
        var groupVisible = false;
        if (!q || dll.indexOf(q) !== -1) {
            groupVisible = true;
            for (var j = 0; j < rows.length; j++) rows[j].style.display = '';
        } else {
            for (var j = 0; j < rows.length; j++) {
                var fn = (rows[j].getAttribute('data-func') || '').toLowerCase();
                if (fn.indexOf(q) !== -1) {
                    rows[j].style.display = '';
                    groupVisible = true;
                } else {
                    rows[j].style.display = 'none';
                }
            }
        }
        groups[i].style.display = groupVisible ? '' : 'none';
        if (groupVisible && q) {
            var details = groups[i].querySelector('details');
            if (details) details.open = true;
        }
    }
}

// Bind filter input via addEventListener (CSP-compliant, no inline handler)
document.addEventListener('DOMContentLoaded', function() {
    var input = document.getElementById('import-search');
    if (input) {
        input.addEventListener('input', filterImports);
    }
});

/* Arkana Dashboard — Call Graph (Cytoscape.js) */
var cy = null;
function initCytoscape(elements) {
    cy = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
            {selector: 'node', style: {
                'background-color': '#001a00',
                'border-color': '#00ff41',
                'border-width': 2,
                'label': 'data(label)',
                'color': '#00ff41',
                'font-family': 'Courier New, monospace',
                'font-size': '10px',
                'text-valign': 'bottom',
                'text-margin-y': 4,
                'width': 'mapData(complexity, 0, 50, 20, 60)',
                'height': 'mapData(complexity, 0, 50, 20, 60)',
            }},
            {selector: 'node[triage="clean"]', style: {'border-color': '#00ff41', 'background-color': '#003300'}},
            {selector: 'node[triage="flagged"]', style: {'border-color': '#ff4141', 'background-color': '#330000'}},
            {selector: 'node[triage="suspicious"]', style: {'border-color': '#ffaa00', 'background-color': '#332200'}},
            {selector: 'node[triage="unreviewed"]', style: {'border-color': '#009922', 'background-color': '#001200'}},
            {selector: 'node[explored="yes"]', style: {'border-width': 3, 'color': '#66ffaa'}},
            {selector: 'node[renamed="yes"]', style: {'border-width': 3, 'border-color': '#44ddff', 'color': '#44ddff'}},
            {selector: 'edge', style: {
                'width': 1,
                'line-color': '#009922',
                'target-arrow-color': '#009922',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'opacity': 0.7,
            }},
            {selector: ':selected', style: {
                'border-color': '#ccffcc',
                'border-width': 3,
            }},
        ],
        layout: {name: 'breadthfirst', directed: true, spacingFactor: 1.2},
        minZoom: 0.1,
        maxZoom: 5,
        wheelSensitivity: 0.5,
    });

    cy.on('tap', 'node', function(evt) {
        var data = evt.target.data();
        var info = document.getElementById('node-info');
        var details = document.getElementById('node-details');
        // Build node details using safe DOM construction (no innerHTML with user data)
        details.textContent = '';
        function addRow(label, value) {
            var row = document.createElement('div');
            row.className = 'detail-row';
            var lbl = document.createElement('span');
            lbl.className = 'detail-label';
            lbl.textContent = label;
            row.appendChild(lbl);
            row.appendChild(document.createTextNode(' ' + value));
            details.appendChild(row);
        }
        addRow('ADDRESS:', data.id);
        addRow('NAME:', data.label);
        addRow('COMPLEXITY:', data.complexity);
        // Triage badge (safe — triage values are from a fixed set)
        var triageRow = document.createElement('div');
        triageRow.className = 'detail-row';
        var triageLbl = document.createElement('span');
        triageLbl.className = 'detail-label';
        triageLbl.textContent = 'TRIAGE:';
        triageRow.appendChild(triageLbl);
        triageRow.appendChild(document.createTextNode(' '));
        var triageBadge = document.createElement('span');
        triageBadge.className = 'badge badge-' + (['clean','flagged','suspicious','unreviewed'].indexOf(data.triage) >= 0 ? data.triage : 'unreviewed');
        triageBadge.textContent = (data.triage || 'unreviewed').toUpperCase();
        triageRow.appendChild(triageBadge);
        details.appendChild(triageRow);
        // Status badges
        if (data.renamed === 'yes' || data.explored === 'yes') {
            var statusRow = document.createElement('div');
            statusRow.className = 'detail-row';
            var statusLbl = document.createElement('span');
            statusLbl.className = 'detail-label';
            statusLbl.textContent = 'STATUS:';
            statusRow.appendChild(statusLbl);
            if (data.renamed === 'yes') { var rb = document.createElement('span'); rb.className = 'badge badge-renamed'; rb.textContent = 'RENAMED'; statusRow.appendChild(document.createTextNode(' ')); statusRow.appendChild(rb); }
            if (data.explored === 'yes') { var eb = document.createElement('span'); eb.className = 'badge badge-explored'; eb.textContent = 'EXPLORED'; statusRow.appendChild(document.createTextNode(' ')); statusRow.appendChild(eb); }
            details.appendChild(statusRow);
        }
        info.classList.remove('hidden');
    });
}
function loadGraph() {
    fetch('/dashboard/api/callgraph').then(function(r) { return r.json(); }).then(function(data) {
        var elements = data.nodes.concat(data.edges);
        if (cy) cy.destroy();
        if (!elements.length) {
            document.getElementById('cy').innerHTML = '<div class="empty-msg">No call graph data. Load a binary and wait for angr CFG analysis.</div>';
            return;
        }
        initCytoscape(elements);
    });
}
function changeLayout() {
    if (!cy) return;
    var name = document.getElementById('layout-select').value;
    cy.layout({name: name, directed: true, spacingFactor: 1.2, animate: true}).run();
}
function fitGraph() {
    if (cy) cy.fit();
}
document.addEventListener('DOMContentLoaded', function() {
    loadGraph();

    var layoutSelect = document.getElementById('layout-select');
    if (layoutSelect) layoutSelect.addEventListener('change', changeLayout);

    var btnFit = document.getElementById('btn-fit');
    if (btnFit) btnFit.addEventListener('click', fitGraph);

    var btnReload = document.getElementById('btn-reload');
    if (btnReload) btnReload.addEventListener('click', loadGraph);
});

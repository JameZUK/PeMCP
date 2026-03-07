/* Arkana Dashboard — Call Graph (IDA Pro Style) — 12-Feature Upgrade */

/* ========== GLOBAL STATE ========== */

var cy = null;
var _selectedNode = null;
var _contextMenuNode = null;
var _focusedMode = false;
var _marchingAntsRAF = null;
var _marchingAntsOffset = 0;
var _minimapDebounce = null;
var _searchDebounce = null;

/* ========== UTILITIES ========== */

function getLayoutConfig(name) {
    if (name === 'dagre') {
        return {
            name: 'dagre',
            rankDir: 'TB',
            nodeSep: 30,
            rankSep: 50,
            ranker: 'network-simplex',
            animate: false,
        };
    }
    if (name === 'breadthfirst') {
        return {name: 'breadthfirst', directed: true, spacingFactor: 1.2, animate: true};
    }
    if (name === 'cose') {
        return {name: 'cose', animate: true, nodeOverlap: 20, idealEdgeLength: 80};
    }
    if (name === 'circle') {
        return {name: 'circle', animate: true};
    }
    return {name: name, animate: true};
}

function getTaxiDirection(layoutName) {
    return layoutName === 'dagre' || layoutName === 'breadthfirst' ? 'downward' : 'auto';
}

function getExportFilename(ext) {
    var d = new Date();
    var date = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    return 'arkana_callgraph_' + date + '.' + ext;
}

/* ========== CORE INIT ========== */

function initCytoscape(elements) {
    var layoutName = document.getElementById('layout-select').value;
    var layoutCfg = getLayoutConfig(layoutName);

    /* Detect if dagre extension is actually available */
    if (layoutName === 'dagre') {
        try {
            /* cytoscape-dagre registers via cytoscape('layout', 'dagre', impl).
               If it didn't register, fall back to breadthfirst. */
            if (typeof cytoscapeDagre === 'undefined' && typeof window.cytoscapeDagre === 'undefined') {
                console.warn('[callgraph] dagre extension not detected, falling back to breadthfirst');
                layoutName = 'breadthfirst';
                layoutCfg = getLayoutConfig(layoutName);
            }
        } catch (e) {
            console.warn('[callgraph] dagre check failed, falling back to breadthfirst', e);
            layoutName = 'breadthfirst';
            layoutCfg = getLayoutConfig(layoutName);
        }
    }

    cy = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
            /* IDA-style rectangular box nodes — F10: height mapped by complexity */
            {selector: 'node', style: {
                'shape': 'round-rectangle',
                'width': 'label',
                'height': 'mapData(complexity, 0, 50, 28, 50)',
                'padding': '12px',
                'background-color': '#001a00',
                'border-color': '#009922',
                'border-width': 2,
                'label': 'data(label)',
                'color': '#00ff41',
                'font-family': 'Courier New, monospace',
                'font-size': '11px',
                'text-valign': 'center',
                'text-halign': 'center',
                'text-wrap': 'ellipsis',
                'text-max-width': '140px',
                'min-zoomed-font-size': 6,
            }},
            /* Triage coloring */
            {selector: 'node[triage="clean"]', style: {
                'border-color': '#00ff41', 'background-color': '#003300',
            }},
            {selector: 'node[triage="flagged"]', style: {
                'border-color': '#ff4141', 'background-color': '#330000', 'color': '#ff6666',
            }},
            {selector: 'node[triage="suspicious"]', style: {
                'border-color': '#ffaa00', 'background-color': '#332200', 'color': '#ffcc44',
            }},
            {selector: 'node[triage="unreviewed"]', style: {
                'border-color': '#009922', 'background-color': '#001200',
            }},
            /* Explored / renamed highlights */
            {selector: 'node[explored="yes"]', style: {
                'border-width': 3, 'color': '#66ffaa',
            }},
            {selector: 'node[renamed="yes"]', style: {
                'border-width': 3, 'border-color': '#44ddff', 'color': '#44ddff',
            }},
            /* Score-based border thickness — higher score = thicker border */
            {selector: 'node[score > 0]', style: {
                'border-width': 'mapData(score, 0, 100, 2, 5)',
            }},
            /* Orthogonal taxi-routed edges */
            {selector: 'edge', style: {
                'width': 1.5,
                'line-color': '#009922',
                'target-arrow-color': '#009922',
                'target-arrow-shape': 'triangle',
                'arrow-scale': 0.8,
                'curve-style': 'taxi',
                'taxi-direction': getTaxiDirection(layoutName),
                'taxi-turn': '20px',
                'opacity': 0.6,
            }},
            /* Selection */
            {selector: ':selected', style: {
                'border-color': '#ccffcc',
                'border-width': 3,
            }},
            /* Neighborhood highlighting */
            {selector: 'node.highlighted', style: {
                'border-width': 3,
                'border-color': '#ccffcc',
                'background-color': '#003300',
                'color': '#ccffcc',
                'z-index': 10,
            }},
            {selector: 'node.highlighted[triage="flagged"]', style: {
                'border-color': '#ff6666', 'background-color': '#440000', 'color': '#ff8888',
            }},
            {selector: 'node.highlighted[triage="suspicious"]', style: {
                'border-color': '#ffcc44', 'background-color': '#443300', 'color': '#ffdd66',
            }},
            /* F9: Marching ants on highlighted edges */
            {selector: 'edge.highlighted', style: {
                'opacity': 1,
                'line-color': '#00ff41',
                'target-arrow-color': '#00ff41',
                'width': 2,
                'z-index': 10,
                'line-style': 'dashed',
                'line-dash-pattern': [8, 4],
                'line-dash-offset': 0,
            }},
            {selector: '.dimmed', style: {
                'opacity': 0.15,
            }},
            /* F3: Hidden nodes in focus mode */
            {selector: '.hidden-node', style: {
                'display': 'none',
            }},
        ],
        layout: layoutCfg,
        minZoom: 0.05,
        maxZoom: 5,
        wheelSensitivity: 0.3,
        boxSelectionEnabled: true,
    });

    /* Click node → highlight neighborhood */
    cy.on('tap', 'node', function(evt) {
        var node = evt.target;
        console.log('[callgraph] node tapped:', node.id(), node.data('label'));
        _selectedNode = node;
        highlightNeighborhood(node);
        showNodeDetails(node);
    });

    /* Click background → clear */
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            _selectedNode = null;
            clearHighlight();
            hideSidebar();
            hideContextMenu();
        }
    });

    /* F1: Right-click context menu */
    cy.on('cxttap', 'node', function(evt) {
        evt.originalEvent.preventDefault();
        _contextMenuNode = evt.target;
        showContextMenu(evt.renderedPosition, evt.originalEvent);
    });

    cy.on('cxttap', function(evt) {
        if (evt.target === cy) hideContextMenu();
    });

    /* F3: Double-tap for subgraph focus */
    cy.on('dbltap', 'node', function(evt) {
        focusSubgraph(evt.target, 2);
    });

    /* F11: Tooltip on hover */
    cy.on('mouseover', 'node', function(evt) {
        var d = evt.target.data();
        var lines = [
            d.id,
            d.label,
            'Size: ' + (d.size || '—'),
            'In: ' + (d.in_deg !== undefined ? d.in_deg : '—') + ' / Out: ' + (d.out_deg !== undefined ? d.out_deg : '—'),
        ];
        showTooltip(evt.renderedPosition, lines.join('\n'));
    });

    cy.on('mouseout', 'node', function() { hideTooltip(); });

    cy.on('mouseover', 'edge', function(evt) {
        var d = evt.target.data();
        var srcNode = cy.getElementById(d.source);
        var tgtNode = cy.getElementById(d.target);
        var srcLabel = srcNode.length ? srcNode.data('label') : d.source;
        var tgtLabel = tgtNode.length ? tgtNode.data('label') : d.target;
        showTooltip(evt.renderedPosition, srcLabel + ' \u2192 ' + tgtLabel);
    });

    cy.on('mouseout', 'edge', function() { hideTooltip(); });

    /* F5: Minimap updates */
    cy.on('viewport', function() { updateMinimapViewport(); });
    cy.on('layoutstop add remove', function() { scheduleMinimapRender(); });

    /* Dismiss context menu on zoom/pan */
    cy.on('zoom pan', function() { hideContextMenu(); });

    /* Initial minimap render */
    scheduleMinimapRender();
}

/* ========== HIGHLIGHT / CLEAR (F9: marching ants) ========== */

function highlightNeighborhood(node) {
    cy.elements().removeClass('highlighted dimmed');
    var neighborhood = node.closedNeighborhood();
    cy.elements().not(neighborhood).addClass('dimmed');
    neighborhood.addClass('highlighted');
    startMarchingAnts();
}

function clearHighlight() {
    if (!cy) return;
    cy.elements().removeClass('highlighted dimmed');
    stopMarchingAnts();
}

function startMarchingAnts() {
    stopMarchingAnts();
    _marchingAntsOffset = 0;
    function step() {
        _marchingAntsOffset += 0.5;
        if (_marchingAntsOffset > 12) _marchingAntsOffset = 0;
        cy.edges('.highlighted').style('line-dash-offset', _marchingAntsOffset);
        _marchingAntsRAF = requestAnimationFrame(step);
    }
    _marchingAntsRAF = requestAnimationFrame(step);
}

function stopMarchingAnts() {
    if (_marchingAntsRAF) {
        cancelAnimationFrame(_marchingAntsRAF);
        _marchingAntsRAF = null;
    }
}

/* ========== NODE DETAILS SIDEBAR (F4: tabbed analysis panel) ========== */

var _sidebarCache = {};  /* keyed by address: {analysis: ..., decompile: ...} */
var _activeTab = 'info';
var _sidebarNodeAddr = null;

function showNodeDetails(node) {
    try {
        var addr = node.id();
        /* Clear cache when switching to a different node */
        if (_sidebarNodeAddr !== addr) {
            _sidebarCache[addr] = _sidebarCache[addr] || {};
            _sidebarNodeAddr = addr;
        }
        _activeTab = 'info';
        _updateTabBar('info');
        renderInfoTab(node);
        var sidebar = document.getElementById('node-info');
        sidebar.classList.remove('hidden');
        console.log('[callgraph] sidebar shown for', addr);
    } catch (err) {
        console.error('[callgraph] showNodeDetails error:', err);
    }
}

function _updateTabBar(active) {
    var tabs = document.querySelectorAll('.sidebar-tab');
    for (var i = 0; i < tabs.length; i++) {
        if (tabs[i].getAttribute('data-tab') === active) {
            tabs[i].classList.add('active');
        } else {
            tabs[i].classList.remove('active');
        }
    }
}

function switchSidebarTab(tabName) {
    if (!_selectedNode || !_sidebarNodeAddr) return;
    _activeTab = tabName;
    _updateTabBar(tabName);
    var node = _selectedNode;
    var addr = node.id();

    switch (tabName) {
        case 'info':
            renderInfoTab(node);
            break;
        case 'xrefs':
            _fetchAnalysis(addr, function(data) { renderXrefsTab(data, node); });
            break;
        case 'strings':
            _fetchAnalysis(addr, function(data) { renderStringsTab(data); });
            break;
        case 'code':
            renderCodeTab(addr);
            break;
    }
}

function _fetchAnalysis(addr, callback) {
    var details = document.getElementById('node-details');
    var cached = _sidebarCache[addr] && _sidebarCache[addr].analysis;
    if (cached) { callback(cached); return; }
    details.textContent = '';
    var loading = document.createElement('div');
    loading.className = 'detail-row dim';
    loading.textContent = 'Loading...';
    details.appendChild(loading);
    fetch('/dashboard/api/function-analysis?address=' + encodeURIComponent(addr))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!_sidebarCache[addr]) _sidebarCache[addr] = {};
            _sidebarCache[addr].analysis = data;
            /* Only render if still on same node/tab */
            if (_sidebarNodeAddr === addr) callback(data);
        })
        .catch(function() {
            details.textContent = '';
            var err = document.createElement('div');
            err.className = 'detail-row dim';
            err.textContent = 'Failed to load analysis data';
            details.appendChild(err);
        });
}

/* --- INFO TAB --- */
function renderInfoTab(node) {
    var data = node.data();
    var details = document.getElementById('node-details');
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
    addRow('SCORE:', data.score !== undefined ? data.score : 0);
    addRow('CALLERS:', data.in_deg !== undefined ? data.in_deg : '\u2014');
    addRow('CALLEES:', data.out_deg !== undefined ? data.out_deg : '\u2014');
    if (data.size !== undefined && data.size > 0) {
        addRow('SIZE:', data.size + ' bytes');
    }

    /* Triage badge */
    var triageRow = document.createElement('div');
    triageRow.className = 'detail-row';
    var triageLbl = document.createElement('span');
    triageLbl.className = 'detail-label';
    triageLbl.textContent = 'TRIAGE:';
    triageRow.appendChild(triageLbl);
    triageRow.appendChild(document.createTextNode(' '));
    var triageBadge = document.createElement('span');
    var validTriage = ['clean', 'flagged', 'suspicious', 'unreviewed'];
    triageBadge.className = 'badge badge-' + (validTriage.indexOf(data.triage) >= 0 ? data.triage : 'unreviewed');
    triageBadge.textContent = (data.triage || 'unreviewed').toUpperCase();
    triageRow.appendChild(triageBadge);
    details.appendChild(triageRow);

    /* Status badges */
    if (data.renamed === 'yes' || data.explored === 'yes') {
        var statusRow = document.createElement('div');
        statusRow.className = 'detail-row';
        var statusLbl = document.createElement('span');
        statusLbl.className = 'detail-label';
        statusLbl.textContent = 'STATUS:';
        statusRow.appendChild(statusLbl);
        if (data.renamed === 'yes') {
            var rb = document.createElement('span');
            rb.className = 'badge badge-renamed';
            rb.textContent = 'RENAMED';
            statusRow.appendChild(document.createTextNode(' '));
            statusRow.appendChild(rb);
        }
        if (data.explored === 'yes') {
            var eb = document.createElement('span');
            eb.className = 'badge badge-explored';
            eb.textContent = 'EXPLORED';
            statusRow.appendChild(document.createTextNode(' '));
            statusRow.appendChild(eb);
        }
        details.appendChild(statusRow);
    }

    /* Caller/callee counts from graph data */
    var incomers = node.incomers('node');
    var outgoers = node.outgoers('node');

    if (incomers.length > 0) {
        var callersTitle = document.createElement('div');
        callersTitle.className = 'detail-row';
        callersTitle.innerHTML = '<span class="detail-label">CALLERS (' + incomers.length + '):</span>';
        details.appendChild(callersTitle);
        incomers.forEach(function(n) {
            var xrow = document.createElement('div');
            xrow.className = 'sidebar-xref-row';
            xrow.textContent = n.data('label') || n.id();
            xrow.title = n.id();
            xrow.addEventListener('click', function() {
                navigateToNode(n);
            });
            details.appendChild(xrow);
        });
    }

    if (outgoers.length > 0) {
        var calleesTitle = document.createElement('div');
        calleesTitle.className = 'detail-row';
        calleesTitle.innerHTML = '<span class="detail-label">CALLEES (' + outgoers.length + '):</span>';
        details.appendChild(calleesTitle);
        outgoers.forEach(function(n) {
            var xrow = document.createElement('div');
            xrow.className = 'sidebar-xref-row';
            xrow.textContent = n.data('label') || n.id();
            xrow.title = n.id();
            xrow.addEventListener('click', function() {
                navigateToNode(n);
            });
            details.appendChild(xrow);
        });
    }
}

/* --- XREFS TAB --- */
function renderXrefsTab(data, node) {
    var details = document.getElementById('node-details');
    details.textContent = '';

    /* Suspicious APIs section */
    if (data.suspicious_apis && data.suspicious_apis.length > 0) {
        var section = document.createElement('div');
        section.className = 'suspicious-section';
        var header = document.createElement('div');
        header.className = 'suspicious-section-header';
        header.textContent = 'SUSPICIOUS APIs (' + data.suspicious_apis.length + ')';
        section.appendChild(header);
        data.suspicious_apis.forEach(function(api) {
            var row = document.createElement('div');
            row.className = 'suspicious-api-row';
            var badge = document.createElement('span');
            badge.className = 'badge';
            if (api.risk === 'CRITICAL') badge.className += ' badge-severity-high';
            else if (api.risk === 'HIGH') badge.className += ' badge-severity-medium';
            else badge.className += ' badge-severity-low';
            badge.textContent = api.risk;
            row.appendChild(badge);
            var nameSpan = document.createElement('span');
            nameSpan.textContent = api.name;
            row.appendChild(nameSpan);
            var catSpan = document.createElement('span');
            catSpan.className = 'suspicious-api-category';
            catSpan.textContent = api.category;
            row.appendChild(catSpan);
            section.appendChild(row);
        });
        details.appendChild(section);
    }

    /* Callers */
    if (data.callers && data.callers.length > 0) {
        var callersTitle = document.createElement('div');
        callersTitle.className = 'detail-row';
        callersTitle.innerHTML = '<span class="detail-label">CALLERS (' + data.callers.length + '):</span>';
        details.appendChild(callersTitle);
        data.callers.forEach(function(c) {
            _appendXrefRow(details, c);
        });
    }

    /* Callees */
    if (data.callees && data.callees.length > 0) {
        var calleesTitle = document.createElement('div');
        calleesTitle.className = 'detail-row';
        calleesTitle.innerHTML = '<span class="detail-label">CALLEES (' + data.callees.length + '):</span>';
        details.appendChild(calleesTitle);
        data.callees.forEach(function(c) {
            _appendXrefRow(details, c);
        });
    }

    /* Complexity */
    if (data.complexity) {
        var compRow = document.createElement('div');
        compRow.className = 'detail-row';
        compRow.innerHTML = '<span class="detail-label">BLOCKS:</span> ' + data.complexity.blocks +
            ' &nbsp; <span class="detail-label">EDGES:</span> ' + data.complexity.edges;
        details.appendChild(compRow);
    }

    if (!data.callers.length && !data.callees.length && !data.suspicious_apis.length) {
        var empty = document.createElement('div');
        empty.className = 'detail-row dim';
        empty.textContent = 'No cross-references found';
        details.appendChild(empty);
    }
}

function _appendXrefRow(container, entry) {
    var row = document.createElement('div');
    row.className = 'sidebar-xref-row';
    row.style.display = 'flex';
    row.style.alignItems = 'center';
    row.style.gap = '6px';
    /* Triage dot */
    var dot = document.createElement('span');
    dot.className = 'xref-triage-dot dot-' + (entry.triage || 'unreviewed');
    row.appendChild(dot);
    /* Name */
    var nameSpan = document.createElement('span');
    nameSpan.textContent = entry.name || entry.address;
    nameSpan.style.flex = '1';
    nameSpan.style.overflow = 'hidden';
    nameSpan.style.textOverflow = 'ellipsis';
    nameSpan.style.whiteSpace = 'nowrap';
    row.appendChild(nameSpan);
    /* Score indicator */
    if (entry.score) {
        var scoreSpan = document.createElement('span');
        scoreSpan.className = 'dim';
        scoreSpan.style.fontSize = '9px';
        scoreSpan.textContent = 'S:' + entry.score;
        row.appendChild(scoreSpan);
    }
    /* Suspicious badge if present */
    if (entry.suspicious) {
        var sBadge = document.createElement('span');
        sBadge.className = 'badge';
        if (entry.suspicious.risk === 'CRITICAL') sBadge.className += ' badge-severity-high';
        else if (entry.suspicious.risk === 'HIGH') sBadge.className += ' badge-severity-medium';
        else sBadge.className += ' badge-severity-low';
        sBadge.textContent = entry.suspicious.risk;
        sBadge.style.fontSize = '9px';
        row.appendChild(sBadge);
    }
    row.title = entry.address;
    /* Click to navigate */
    row.addEventListener('click', function() {
        if (!cy) return;
        var n = cy.getElementById(entry.address);
        if (n.length) {
            navigateToNode(n);
        }
    });
    container.appendChild(row);
}

/* --- STRINGS TAB --- */
function renderStringsTab(data) {
    var details = document.getElementById('node-details');
    details.textContent = '';

    var strings = data.strings || [];
    if (strings.length === 0) {
        var empty = document.createElement('div');
        empty.className = 'detail-row dim';
        empty.textContent = 'No strings referenced';
        details.appendChild(empty);
        return;
    }

    strings.forEach(function(s) {
        var row = document.createElement('div');
        row.className = 'detail-row';
        row.style.display = 'flex';
        row.style.alignItems = 'center';
        row.style.gap = '6px';
        row.style.fontSize = '12px';
        /* Type badge */
        var badge = document.createElement('span');
        var typeLower = (s.type || 'ascii').toLowerCase();
        badge.className = 'badge badge-str-' + typeLower;
        badge.textContent = (s.type || 'ASCII');
        badge.style.fontSize = '9px';
        badge.style.flexShrink = '0';
        row.appendChild(badge);
        /* Address */
        if (s.address) {
            var addr = document.createElement('span');
            addr.className = 'dim';
            addr.textContent = s.address;
            addr.style.fontSize = '10px';
            addr.style.flexShrink = '0';
            row.appendChild(addr);
        }
        /* String content */
        var content = document.createElement('span');
        var str = s.string || '';
        content.textContent = str.length > 120 ? str.substring(0, 120) + '...' : str;
        content.style.overflow = 'hidden';
        content.style.textOverflow = 'ellipsis';
        content.style.whiteSpace = 'nowrap';
        content.title = str;
        row.appendChild(content);
        details.appendChild(row);
    });
}

/* --- CODE TAB --- */
function renderCodeTab(addr) {
    var details = document.getElementById('node-details');
    details.textContent = '';

    /* Check cache */
    var cached = _sidebarCache[addr] && _sidebarCache[addr].decompile;
    if (cached) {
        _renderCodeContent(details, cached);
        return;
    }

    var loading = document.createElement('div');
    loading.className = 'detail-row dim';
    loading.textContent = 'Decompiling...';
    details.appendChild(loading);

    fetch('/dashboard/api/decompile', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
        body: JSON.stringify({address: addr}),
    })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!_sidebarCache[addr]) _sidebarCache[addr] = {};
            _sidebarCache[addr].decompile = data;
            if (_sidebarNodeAddr === addr && _activeTab === 'code') {
                details.textContent = '';
                _renderCodeContent(details, data);
            }
        })
        .catch(function() {
            if (_sidebarNodeAddr === addr && _activeTab === 'code') {
                details.textContent = '';
                var err = document.createElement('div');
                err.className = 'detail-row dim';
                err.textContent = 'Decompilation request failed';
                details.appendChild(err);
            }
        });
}

function _renderCodeContent(container, data) {
    if (data.error) {
        var err = document.createElement('div');
        err.className = 'detail-row dim';
        err.textContent = data.error;
        container.appendChild(err);
        return;
    }
    var code = Array.isArray(data.lines) ? data.lines.join('\n') : '(no output)';
    var pre = document.createElement('pre');
    pre.className = 'sidebar-code';
    pre.textContent = code;
    container.appendChild(pre);
}

/* --- Navigate to node helper --- */
function navigateToNode(n) {
    _selectedNode = n;
    highlightNeighborhood(n);
    showNodeDetails(n);
    cy.animate({center: {eles: n}, duration: 300});
}

function hideSidebar() {
    document.getElementById('node-info').classList.add('hidden');
}

/* ========== GRAPH LOAD / LAYOUT / FIT ========== */

function loadGraph() {
    fetch('/dashboard/api/callgraph').then(function(r) { return r.json(); }).then(function(data) {
        var elements = data.nodes.concat(data.edges);
        if (cy) {
            stopMarchingAnts();
            cy.destroy();
            cy = null;
        }
        _selectedNode = null;
        _focusedMode = false;
        updateShowAllButton();

        if (!elements.length) {
            /* Remove any previous empty message */
            var prev = document.getElementById('cy-empty-msg');
            if (prev) prev.remove();
            /* Add empty message without destroying overlay children (menu, tooltip, minimap, legend) */
            var emptyDiv = document.createElement('div');
            emptyDiv.id = 'cy-empty-msg';
            emptyDiv.className = 'empty-msg';
            emptyDiv.style.position = 'absolute';
            emptyDiv.style.top = '50%';
            emptyDiv.style.left = '50%';
            emptyDiv.style.transform = 'translate(-50%, -50%)';
            emptyDiv.textContent = 'No call graph data. Load a binary and wait for angr CFG analysis.';
            document.getElementById('cy').appendChild(emptyDiv);
            document.getElementById('graph-stats').textContent = '';
            return;
        }
        /* Remove empty message if present */
        var oldEmpty = document.getElementById('cy-empty-msg');
        if (oldEmpty) oldEmpty.remove();
        try {
            initCytoscape(elements);
        } catch (err) {
            console.error('[callgraph] initCytoscape failed:', err);
            /* Retry with a safe layout */
            try {
                document.getElementById('layout-select').value = 'cose';
                initCytoscape(elements);
                console.info('[callgraph] retried with cose layout — success');
            } catch (err2) {
                console.error('[callgraph] cose fallback also failed:', err2);
                var errDiv = document.createElement('div');
                errDiv.className = 'empty-msg';
                errDiv.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--danger);';
                errDiv.textContent = 'Graph init error: ' + err.message;
                document.getElementById('cy').appendChild(errDiv);
                return;
            }
        }
        var statsEl = document.getElementById('graph-stats');
        if (statsEl) {
            statsEl.textContent = data.nodes.length + ' NODES / ' + data.edges.length + ' EDGES';
        }
    }).catch(function(err) {
        console.error('[callgraph] loadGraph fetch error:', err);
        var cyEl = document.getElementById('cy');
        var errDiv = document.createElement('div');
        errDiv.id = 'cy-empty-msg';
        errDiv.className = 'empty-msg';
        errDiv.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);color:var(--danger);';
        errDiv.textContent = 'Failed to load graph: ' + err.message;
        cyEl.appendChild(errDiv);
    });
}

function changeLayout() {
    if (!cy) return;
    var name = document.getElementById('layout-select').value;
    var dir = getTaxiDirection(name);
    cy.style().selector('edge').style('taxi-direction', dir).update();
    cy.layout(getLayoutConfig(name)).run();
}

function fitGraph() {
    if (cy) cy.fit();
}

/* ========== F1: CONTEXT MENU ========== */

function showContextMenu(pos, origEvt) {
    var menu = document.getElementById('cy-context-menu');
    if (!menu) return;
    var container = document.getElementById('cy');
    var rect = container.getBoundingClientRect();

    /* Position within the cy container */
    var x = origEvt.clientX - rect.left;
    var y = origEvt.clientY - rect.top;

    /* Clamp to stay inside container */
    menu.style.display = 'block';
    var menuW = menu.offsetWidth;
    var menuH = menu.offsetHeight;
    if (x + menuW > rect.width) x = rect.width - menuW - 4;
    if (y + menuH > rect.height) y = rect.height - menuH - 4;
    if (x < 0) x = 4;
    if (y < 0) y = 4;

    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
}

function hideContextMenu() {
    var menu = document.getElementById('cy-context-menu');
    if (menu) menu.style.display = 'none';
}

function contextMenuAction(action) {
    if (!_contextMenuNode) return;
    var node = _contextMenuNode;
    var addr = node.id();
    hideContextMenu();

    switch (action) {
        case 'decompile':
            doDecompile(addr);
            break;
        case 'flag':
            doTriage(node, 'flagged');
            break;
        case 'suspicious':
            doTriage(node, 'suspicious');
            break;
        case 'clean':
            doTriage(node, 'clean');
            break;
        case 'unreviewed':
            doTriage(node, 'unreviewed');
            break;
        case 'xrefs':
            doShowXrefs(addr);
            break;
        case 'center':
            cy.animate({center: {eles: node}, zoom: 1.5, duration: 400});
            break;
        case 'focus':
            focusSubgraph(node, 2);
            break;
        case 'bookmark':
            bookmarkCurrent();
            break;
    }
}

function doDecompile(addr) {
    fetch('/dashboard/api/decompile', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
        body: JSON.stringify({address: addr}),
    })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) {
                showToast(data.error, 'error');
            } else {
                var name = data.function_name || addr;
                var code = Array.isArray(data.lines) ? data.lines.join('\n') : '(no output)';
                showDecompilePanel(name, code);
            }
        })
        .catch(function() { showToast('Decompile request failed', 'error'); });
}

function showDecompilePanel(name, code) {
    var panel = document.getElementById('decompile-overlay');
    if (!panel) return;
    panel.querySelector('.decompile-func-name').textContent = name;
    panel.querySelector('.decompile-code').textContent = code;
    panel.classList.remove('hidden');
}

function hideDecompilePanel() {
    var panel = document.getElementById('decompile-overlay');
    if (panel) panel.classList.add('hidden');
}

function doTriage(node, status) {
    var addr = node.id();
    fetch('/dashboard/api/triage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
        body: JSON.stringify({address: addr, status: status}),
    })
        .then(function(r) {
            if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || r.statusText); });
            return r.json();
        })
        .then(function(data) {
            if (data.ok) {
                node.data('triage', status);
                showToast('Triage: ' + status.toUpperCase(), 'success');
                if (_selectedNode && _selectedNode.id() === addr) {
                    showNodeDetails(node);
                }
            } else {
                showToast('Triage failed: ' + (data.error || 'unknown'), 'error');
            }
        })
        .catch(function(err) { showToast('Triage: ' + (err.message || 'request failed'), 'error'); });
}

function doShowXrefs(addr) {
    fetch('/dashboard/api/function-xrefs?address=' + encodeURIComponent(addr))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) { showToast(data.error, 'error'); return; }
            var lines = ['XREFS for ' + addr + ':'];
            if (data.callers && data.callers.length) {
                var names = data.callers.map(function(c) { return c.name || c.address; });
                lines.push('Callers: ' + names.join(', '));
            }
            if (data.callees && data.callees.length) {
                var names2 = data.callees.map(function(c) { return c.name || c.address; });
                lines.push('Callees: ' + names2.join(', '));
            }
            if (lines.length === 1) lines.push('(none found)');
            showToast(lines.join('\n'), 'info');
        })
        .catch(function() { showToast('Xrefs request failed', 'error'); });
}

function showToast(msg, type) {
    var container = document.querySelector('.toast-container');
    if (!container) return;
    var t = document.createElement('div');
    t.className = 'toast toast-' + (type || 'info');
    t.textContent = msg;
    container.appendChild(t);
    setTimeout(function() {
        t.style.opacity = '0';
        setTimeout(function() { t.remove(); }, 300);
    }, 4000);
}

/* ========== F2: SEARCH / FILTER ========== */

function setupSearch() {
    var input = document.getElementById('graph-search');
    var countEl = document.getElementById('graph-search-count');
    var clearBtn = document.getElementById('graph-search-clear');
    if (!input) return;

    input.addEventListener('input', function() {
        clearTimeout(_searchDebounce);
        _searchDebounce = setTimeout(function() { doSearch(input.value); }, 300);
    });

    input.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            input.value = '';
            input.blur();
            doSearch('');
        }
    });

    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            input.value = '';
            input.blur();
            doSearch('');
        });
    }
}

function doSearch(query) {
    var countEl = document.getElementById('graph-search-count');
    if (!cy) {
        if (countEl) countEl.textContent = '';
        return;
    }
    if (!query.trim()) {
        cy.elements().removeClass('highlighted dimmed');
        stopMarchingAnts();
        if (countEl) countEl.textContent = '';
        return;
    }
    var q = query.toLowerCase();
    var matched = cy.nodes().filter(function(n) {
        var label = (n.data('label') || '').toLowerCase();
        var id = (n.id() || '').toLowerCase();
        return label.indexOf(q) >= 0 || id.indexOf(q) >= 0;
    });
    cy.elements().removeClass('highlighted dimmed');
    stopMarchingAnts();
    if (matched.length > 0) {
        cy.elements().not(matched).addClass('dimmed');
        matched.addClass('highlighted');
    }
    if (countEl) {
        countEl.textContent = matched.length + '/' + cy.nodes().length;
    }
}

/* ========== F7: KEYBOARD NAVIGATION ========== */

function setupKeyboard() {
    document.addEventListener('keydown', function(e) {
        /* Skip if typing in an input */
        var tag = (e.target.tagName || '').toLowerCase();
        if (tag === 'input' || tag === 'textarea' || tag === 'select') {
            if (e.key === 'Escape') {
                e.target.blur();
            }
            return;
        }
        if (!cy) return;

        switch (e.key) {
            case 'f':
            case 'F':
                e.preventDefault();
                fitGraph();
                break;
            case 'r':
            case 'R':
                e.preventDefault();
                loadGraph();
                break;
            case '/':
                e.preventDefault();
                var searchInput = document.getElementById('graph-search');
                if (searchInput) searchInput.focus();
                break;
            case 'd':
            case 'D':
                e.preventDefault();
                if (_selectedNode) doDecompile(_selectedNode.id());
                break;
            case 'Escape':
                clearHighlight();
                hideSidebar();
                hideContextMenu();
                hideDecompilePanel();
                if (_focusedMode) restoreFullGraph();
                var searchInput2 = document.getElementById('graph-search');
                if (searchInput2) { searchInput2.value = ''; doSearch(''); }
                break;
            case 'ArrowUp':
            case 'ArrowLeft':
                e.preventDefault();
                navigateConnected('callers');
                break;
            case 'ArrowDown':
            case 'ArrowRight':
                e.preventDefault();
                navigateConnected('callees');
                break;
        }
    });
}

function navigateConnected(direction) {
    if (!_selectedNode || !cy) return;
    var targets;
    if (direction === 'callers') {
        targets = _selectedNode.incomers('node');
    } else {
        targets = _selectedNode.outgoers('node');
    }
    if (targets.length === 0) return;
    var next = targets[0];
    _selectedNode = next;
    highlightNeighborhood(next);
    showNodeDetails(next);
    cy.animate({center: {eles: next}, duration: 300});
}

/* ========== F3: SUBGRAPH FOCUS ========== */

function focusSubgraph(node, hops) {
    if (!cy) return;
    /* Compute N-hop neighborhood */
    var neighborhood = node.closedNeighborhood();
    for (var i = 1; i < hops; i++) {
        neighborhood = neighborhood.closedNeighborhood();
    }
    /* Hide everything else */
    cy.elements().not(neighborhood).addClass('hidden-node');
    neighborhood.removeClass('hidden-node');
    _focusedMode = true;
    updateShowAllButton();

    /* Re-layout visible elements */
    var layoutName = document.getElementById('layout-select').value;
    cy.elements(':visible').layout(getLayoutConfig(layoutName)).run();

    /* Highlight the focal node */
    highlightNeighborhood(node);
    _selectedNode = node;
    showNodeDetails(node);
}

function restoreFullGraph() {
    if (!cy) return;
    cy.elements().removeClass('hidden-node');
    _focusedMode = false;
    updateShowAllButton();

    var layoutName = document.getElementById('layout-select').value;
    cy.layout(getLayoutConfig(layoutName)).run();
}

function updateShowAllButton() {
    var btn = document.getElementById('btn-show-all');
    if (!btn) return;
    btn.style.display = _focusedMode ? 'inline-block' : 'none';
}

/* ========== F11: TOOLTIP ========== */

function showTooltip(pos, text) {
    var tip = document.getElementById('cy-tooltip');
    if (!tip) return;
    tip.textContent = text;
    tip.style.display = 'block';

    var container = document.getElementById('cy');
    var rect = container.getBoundingClientRect();
    var x = pos.x + 12;
    var y = pos.y + 12;

    /* Keep inside container */
    if (x + tip.offsetWidth > rect.width) x = pos.x - tip.offsetWidth - 8;
    if (y + tip.offsetHeight > rect.height) y = pos.y - tip.offsetHeight - 8;

    tip.style.left = x + 'px';
    tip.style.top = y + 'px';
}

function hideTooltip() {
    var tip = document.getElementById('cy-tooltip');
    if (tip) tip.style.display = 'none';
}

/* ========== F5: MINIMAP ========== */

function scheduleMinimapRender() {
    clearTimeout(_minimapDebounce);
    _minimapDebounce = setTimeout(renderMinimap, 500);
}

function renderMinimap() {
    if (!cy) return;
    var img = document.getElementById('minimap-img');
    if (!img) return;
    try {
        var png = cy.png({full: true, maxWidth: 180, maxHeight: 120, bg: '#0a0a0a'});
        img.src = png;
        img.style.display = 'block';
    } catch (e) {
        /* ignore rendering errors on empty graphs */
    }
    updateMinimapViewport();
}

function updateMinimapViewport() {
    var vp = document.getElementById('minimap-viewport');
    var img = document.getElementById('minimap-img');
    if (!vp || !img || !cy) return;

    var ext = cy.extent();
    var bb = cy.elements().boundingBox();
    if (bb.w === 0 || bb.h === 0) return;

    var imgW = img.naturalWidth || 180;
    var imgH = img.naturalHeight || 120;
    var displayW = img.clientWidth || 180;
    var displayH = img.clientHeight || 120;
    var scaleX = displayW / bb.w;
    var scaleY = displayH / bb.h;

    var left = (ext.x1 - bb.x1) * scaleX;
    var top = (ext.y1 - bb.y1) * scaleY;
    var width = ext.w * scaleX;
    var height = ext.h * scaleY;

    vp.style.left = Math.max(0, left) + 'px';
    vp.style.top = Math.max(0, top) + 'px';
    vp.style.width = Math.min(displayW, Math.max(8, width)) + 'px';
    vp.style.height = Math.min(displayH, Math.max(8, height)) + 'px';
    vp.style.display = 'block';
}

function setupMinimap() {
    var minimap = document.getElementById('graph-minimap');
    if (!minimap) return;
    minimap.addEventListener('click', function(e) {
        if (!cy) return;
        var rect = minimap.getBoundingClientRect();
        var clickX = e.clientX - rect.left;
        var clickY = e.clientY - rect.top;

        var bb = cy.elements().boundingBox();
        if (bb.w === 0 || bb.h === 0) return;

        var displayW = minimap.clientWidth || 180;
        var displayH = minimap.clientHeight || 120;
        var modelX = bb.x1 + (clickX / displayW) * bb.w;
        var modelY = bb.y1 + (clickY / displayH) * bb.h;

        /* Pan so the clicked model position is at the viewport center */
        cy.pan({
            x: cy.width() / 2 - modelX * cy.zoom(),
            y: cy.height() / 2 - modelY * cy.zoom()
        });
    });
}

/* ========== F8: EXPORT PNG / SVG ========== */

function exportPNG() {
    if (!cy) return;
    try {
        var dataUrl = cy.png({full: true, bg: '#0a0a0a', scale: 2});
        var a = document.createElement('a');
        a.href = dataUrl;
        a.download = getExportFilename('png');
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        showToast('PNG exported', 'success');
    } catch (e) {
        showToast('PNG export failed', 'error');
    }
}

function exportSVG() {
    if (!cy) return;
    /* cy.svg() requires cytoscape-svg extension — fall back to high-res PNG */
    if (typeof cy.svg === 'function') {
        try {
            var svgContent = cy.svg({full: true});
            var blob = new Blob([svgContent], {type: 'image/svg+xml'});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = getExportFilename('svg');
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('SVG exported', 'success');
            return;
        } catch (e) { /* fall through to PNG fallback */ }
    }
    /* Fallback: export as high-res PNG */
    try {
        var dataUrl = cy.png({full: true, bg: '#0a0a0a', scale: 3});
        var a2 = document.createElement('a');
        a2.href = dataUrl;
        a2.download = getExportFilename('png');
        document.body.appendChild(a2);
        a2.click();
        document.body.removeChild(a2);
        showToast('SVG not available — exported hi-res PNG', 'info');
    } catch (e2) {
        showToast('Export failed', 'error');
    }
}

/* ========== F12: BOOKMARKS (localStorage) ========== */

var BOOKMARKS_KEY = 'arkana_callgraph_bookmarks';

function getBookmarks() {
    try {
        return JSON.parse(localStorage.getItem(BOOKMARKS_KEY)) || [];
    } catch (e) {
        return [];
    }
}

function saveBookmarks(list) {
    localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(list));
}

function bookmarkCurrent() {
    if (!cy) return;
    var highlighted = cy.nodes('.highlighted');
    if (highlighted.length === 0 && _selectedNode) {
        highlighted = _selectedNode.closedNeighborhood().nodes();
    }
    if (highlighted.length === 0) {
        showToast('Select nodes to bookmark', 'warning');
        return;
    }
    var name = prompt('Bookmark name:');
    if (!name) return;
    var ids = [];
    highlighted.forEach(function(n) { ids.push(n.id()); });
    var bookmarks = getBookmarks();
    bookmarks.push({name: name, ids: ids, created: Date.now()});
    saveBookmarks(bookmarks);
    refreshBookmarkDropdown();
    showToast('Bookmarked: ' + name, 'success');
}

function goToBookmark(index) {
    if (!cy) return;
    var bookmarks = getBookmarks();
    if (index < 0 || index >= bookmarks.length) return;
    var bm = bookmarks[index];
    var nodes = cy.collection();
    bm.ids.forEach(function(id) {
        var n = cy.getElementById(id);
        if (n.length) nodes = nodes.union(n);
    });
    if (nodes.length === 0) {
        showToast('No matching nodes found (different binary?)', 'warning');
        return;
    }
    cy.elements().removeClass('highlighted dimmed');
    stopMarchingAnts();
    cy.elements().not(nodes).addClass('dimmed');
    nodes.addClass('highlighted');
    startMarchingAnts();
    cy.animate({fit: {eles: nodes, padding: 40}, duration: 400});
}

function deleteBookmark(index) {
    var bookmarks = getBookmarks();
    if (index < 0 || index >= bookmarks.length) return;
    bookmarks.splice(index, 1);
    saveBookmarks(bookmarks);
    refreshBookmarkDropdown();
    showToast('Bookmark deleted', 'info');
}

function refreshBookmarkDropdown() {
    var container = document.getElementById('bookmark-list');
    if (!container) return;
    container.textContent = '';
    var bookmarks = getBookmarks();
    if (bookmarks.length === 0) {
        var empty = document.createElement('div');
        empty.className = 'bookmark-empty';
        empty.textContent = 'No bookmarks';
        container.appendChild(empty);
        return;
    }
    bookmarks.forEach(function(bm, i) {
        var row = document.createElement('div');
        row.className = 'bookmark-row';

        var nameSpan = document.createElement('span');
        nameSpan.className = 'bookmark-name';
        nameSpan.textContent = bm.name;
        nameSpan.title = bm.ids.length + ' nodes';
        row.appendChild(nameSpan);

        var goBtn = document.createElement('button');
        goBtn.className = 'btn bookmark-go';
        goBtn.textContent = 'GO';
        goBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            goToBookmark(i);
            toggleBookmarkDropdown(false);
        });
        row.appendChild(goBtn);

        var delBtn = document.createElement('button');
        delBtn.className = 'btn bookmark-del';
        delBtn.textContent = 'DEL';
        delBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            deleteBookmark(i);
        });
        row.appendChild(delBtn);

        container.appendChild(row);
    });
}

function toggleBookmarkDropdown(forceState) {
    var dd = document.getElementById('bookmark-dropdown');
    if (!dd) return;
    var show = forceState !== undefined ? forceState : dd.classList.contains('hidden');
    if (show) {
        refreshBookmarkDropdown();
        dd.classList.remove('hidden');
    } else {
        dd.classList.add('hidden');
    }
}

/* ========== F6: COLOR LEGEND ========== */

function buildLegend() {
    var legend = document.getElementById('graph-legend');
    if (!legend) return;
    var items = [
        {color: '#ff4141', border: null, label: 'FLAGGED'},
        {color: '#ffaa00', border: null, label: 'SUSPICIOUS'},
        {color: '#00ff41', border: null, label: 'CLEAN'},
        {color: '#009922', border: null, label: 'UNREVIEWED'},
        {color: null, border: '#44ddff', label: 'RENAMED'},
        {color: null, border: '#66ffaa', label: 'EXPLORED'},
    ];
    var body = legend.querySelector('.legend-body');
    if (!body) return;
    body.textContent = '';
    items.forEach(function(item) {
        var row = document.createElement('div');
        row.className = 'legend-item';
        var swatch = document.createElement('span');
        swatch.className = 'legend-swatch';
        if (item.color) {
            swatch.style.background = item.color;
        } else {
            swatch.style.background = '#001a00';
            swatch.style.border = '2px solid ' + item.border;
        }
        row.appendChild(swatch);
        var label = document.createElement('span');
        label.textContent = item.label;
        row.appendChild(label);
        body.appendChild(row);
    });
    /* Score note */
    var note = document.createElement('div');
    note.className = 'legend-item dim';
    note.style.fontSize = '9px';
    note.style.marginTop = '4px';
    note.textContent = 'BORDER THICKNESS = SCORE';
    body.appendChild(note);
}

function toggleLegend() {
    var legend = document.getElementById('graph-legend');
    if (!legend) return;
    legend.classList.toggle('hidden');
}

/* ========== DOMContentLoaded ========== */

document.addEventListener('DOMContentLoaded', function() {
    loadGraph();

    /* Layout controls */
    var layoutSelect = document.getElementById('layout-select');
    if (layoutSelect) layoutSelect.addEventListener('change', changeLayout);

    var btnFit = document.getElementById('btn-fit');
    if (btnFit) btnFit.addEventListener('click', fitGraph);

    var btnReload = document.getElementById('btn-reload');
    if (btnReload) btnReload.addEventListener('click', loadGraph);

    /* F3: Show all */
    var btnShowAll = document.getElementById('btn-show-all');
    if (btnShowAll) btnShowAll.addEventListener('click', restoreFullGraph);
    updateShowAllButton();

    /* F2: Search */
    setupSearch();

    /* F7: Keyboard */
    setupKeyboard();

    /* F1: Context menu — event delegation + dismiss on click-away */
    var ctxMenu = document.getElementById('cy-context-menu');
    if (ctxMenu) {
        ctxMenu.addEventListener('click', function(e) {
            var action = e.target.getAttribute('data-action');
            if (action) contextMenuAction(action);
        });
    }
    document.addEventListener('click', function(e) {
        if (ctxMenu && !ctxMenu.contains(e.target)) hideContextMenu();
    });
    document.addEventListener('scroll', hideContextMenu);

    /* F5: Minimap */
    setupMinimap();

    /* F8: Export */
    var btnPng = document.getElementById('btn-export-png');
    if (btnPng) btnPng.addEventListener('click', exportPNG);
    var btnSvg = document.getElementById('btn-export-svg');
    if (btnSvg) btnSvg.addEventListener('click', exportSVG);

    /* F12: Bookmarks */
    var btnBookmark = document.getElementById('btn-bookmark');
    if (btnBookmark) btnBookmark.addEventListener('click', function() { toggleBookmarkDropdown(); });
    refreshBookmarkDropdown();

    /* F6: Legend */
    buildLegend();
    var btnLegend = document.getElementById('legend-close');
    if (btnLegend) btnLegend.addEventListener('click', toggleLegend);

    /* Sidebar tab switching */
    var tabBar = document.querySelector('.sidebar-tab-bar');
    if (tabBar) {
        tabBar.addEventListener('click', function(e) {
            var tab = e.target.getAttribute('data-tab');
            if (tab) switchSidebarTab(tab);
        });
    }

    /* Decompile overlay close */
    var btnDecompClose = document.getElementById('decompile-overlay-close');
    if (btnDecompClose) btnDecompClose.addEventListener('click', hideDecompilePanel);
});

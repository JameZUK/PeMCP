/* Arkana Dashboard — Similarity View (BSim + BinDiff) */
(function () {
    "use strict";

    var _selectedFilePath = "";
    var _debounceTimer = null;
    var _expandedSha256 = "";
    var _diffFileListLoaded = false;
    var _dbListLoaded = false;

    // Cached data for client-side sorting
    var _triageResults = [];
    var _triageSort = "shared";
    var _triageSortAsc = false;
    var _matchCache = {};  // sha256 -> {matches: [], sort: "", asc: false}

    // File browser cache + sort
    var _fileListData = [];
    var _fileSort = "name";
    var _fileSortAsc = true;

    // DB binaries cache + sort
    var _dbBinaries = [];
    var _dbSort = "name";
    var _dbSortAsc = true;

    // ====================================================================
    //  Top-level tab switching
    // ====================================================================
    var _projectsForCompareLoaded = false;

    function switchTab(tab) {
        var tabs = document.querySelectorAll(".sim-tab");
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.toggle("active", tabs[i].getAttribute("data-tab") === tab);
        }
        document.getElementById("tab-similarity").classList.toggle("d-none", tab !== "similarity");
        document.getElementById("tab-diff").classList.toggle("d-none", tab !== "diff");
        document.getElementById("tab-projects").classList.toggle("d-none", tab !== "projects");
        document.getElementById("tab-database").classList.toggle("d-none", tab !== "database");

        // Lazy-load data for tabs on first visit
        if (tab === "diff" && !_diffFileListLoaded) {
            _diffFileListLoaded = true;
            loadFileList();
        }
        if (tab === "database" && !_dbListLoaded) {
            _dbListLoaded = true;
            loadIndexedBinaries();
        }
        if (tab === "projects" && !_projectsForCompareLoaded) {
            _projectsForCompareLoaded = true;
            loadProjectsForCompare();
        }
    }

    document.getElementById("sim-mode-tabs").addEventListener("click", function (e) {
        var tab = e.target.closest(".sim-tab");
        if (!tab) return;
        switchTab(tab.getAttribute("data-tab"));
    });

    // ====================================================================
    //  TAB 1: SIMILARITY (BSim)
    // ====================================================================

    function loadBsimStats() {
        fetchJSON("/dashboard/api/bsim/stats")
            .then(function (data) {
                if (!data.available) {
                    document.getElementById("bsim-stats-text").textContent = "BSim DB unavailable";
                    return;
                }
                var text = data.total_binaries + " binaries \u00b7 " +
                    data.total_functions + " functions";
                if (data.library_entries > 0) {
                    text += " \u00b7 " + data.library_entries + " library";
                }
                document.getElementById("bsim-stats-text").textContent = text;

                // Index status
                var statusEl = document.getElementById("bsim-index-status");
                var indexBtn = document.getElementById("bsim-index-btn");
                if (data.current_indexed) {
                    statusEl.innerHTML = "<span class=\"badge badge-clean\">INDEXED</span>";
                    indexBtn.textContent = "RE-INDEX";
                } else if (data.current_sha256) {
                    statusEl.innerHTML = "<span class=\"badge badge-dim\">NOT INDEXED</span>";
                    indexBtn.textContent = "INDEX";
                } else {
                    statusEl.innerHTML = "<span class=\"badge badge-dim\">NO FILE</span>";
                }
                indexBtn.disabled = !data.current_sha256;
                document.getElementById("bsim-triage-btn").disabled = !data.current_sha256;
            })
            .catch(function () {
                document.getElementById("bsim-stats-text").textContent = "Failed to load stats";
            });
    }

    function runIndex() {
        var spinner = document.getElementById("bsim-action-spinner");
        var btn = document.getElementById("bsim-index-btn");
        spinner.classList.remove("d-none");
        spinner.textContent = "Indexing...";
        btn.disabled = true;

        fetchJSON("/dashboard/api/bsim/index", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
            body: "{}"
        })
        .then(function (data) {
            spinner.classList.add("d-none");
            btn.disabled = false;
            if (data.error) {
                showToast(data.error, "error");
                return;
            }
            showToast("Indexed " + data.functions_indexed + " functions", "success");
            loadBsimStats();
        })
        .catch(function (err) {
            spinner.classList.add("d-none");
            btn.disabled = false;
            showToast("Index failed: " + err.message, "error");
        });
    }

    function runTriage() {
        var spinner = document.getElementById("bsim-action-spinner");
        var btn = document.getElementById("bsim-triage-btn");
        var errorPanel = document.getElementById("bsim-error");
        spinner.classList.remove("d-none");
        spinner.textContent = "Running triage...";
        btn.disabled = true;
        errorPanel.classList.add("d-none");

        fetchJSON("/dashboard/api/bsim/triage", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
            body: "{}"
        })
        .then(function (data) {
            spinner.classList.add("d-none");
            btn.disabled = false;
            if (data.error) {
                errorPanel.classList.remove("d-none");
                document.getElementById("bsim-error-msg").textContent = data.error;
                return;
            }
            renderTriageResults(data);
        })
        .catch(function (err) {
            spinner.classList.add("d-none");
            btn.disabled = false;
            errorPanel.classList.remove("d-none");
            document.getElementById("bsim-error-msg").textContent = "Triage failed: " + err.message;
        });
    }

    // --- Sorting helpers ---
    var _triageSortKeys = {
        binary: function (r) { return (r.binary_filename || "").toLowerCase(); },
        project: function (r) {
            var ps = r.projects || [];
            return ps.length ? (ps[0].name || "").toLowerCase() : "\uffff";
        },
        shared: function (r) { return r.shared_function_count || 0; },
        overlap: function (r) { return r.shared_function_ratio || 0; },
        avg_sim: function (r) { return r.avg_similarity || 0; },
        confidence: function (r) { return r.avg_confidence || 0; }
    };

    function _renderProjectsCell(projects) {
        // Render the project membership column. A binary may belong to >1
        // project; show the first as a badge with the rest as +N.
        var ps = projects || [];
        if (!ps.length) return "<span class=\"dim fs-11\">—</span>";
        var first = ps[0];
        var name = first.name || "";
        var truncated = name.length > 40 ? name.slice(0, 38) + "\u2026" : name;
        var html = "<span class=\"badge badge-tag\" title=\"" +
            escapeHtml(name) + "\">" + escapeHtml(truncated) + "</span>";
        if (ps.length > 1) {
            var rest = ps.slice(1).map(function (p) { return p.name; }).join("\n");
            html += " <span class=\"badge badge-dim\" title=\"" + escapeHtml(rest) +
                "\">+" + (ps.length - 1) + "</span>";
        }
        return html;
    }

    function sortTriageBy(col) {
        if (_triageSort === col) {
            _triageSortAsc = !_triageSortAsc;
        } else {
            _triageSort = col;
            // Default descending for numeric, ascending for text
            _triageSortAsc = (col === "binary");
        }
        updateTriageSortArrows();
        _paintTriageRows();
    }

    function updateTriageSortArrows() {
        _updateSortArrows("bsim-triage-table", "triage", _triageSort, _triageSortAsc);
    }

    function renderTriageResults(data) {
        _triageResults = data.results || [];
        _expandedSha256 = "";
        _matchCache = {};
        document.getElementById("bsim-triage-count").textContent = _triageResults.length;

        if (!_triageResults.length) {
            document.getElementById("bsim-triage-tbody").innerHTML =
                "<tr><td colspan=\"8\" class=\"empty-msg\">No matches found. " +
                (data.total_functions_analyzed ? data.total_functions_analyzed + " functions analyzed." : "") +
                "</td></tr>";
            return;
        }
        _paintTriageRows();
    }

    function _paintTriageRows() {
        var sorted = _triageResults.slice();
        var keyFn = _triageSortKeys[_triageSort] || _triageSortKeys.shared;
        var asc = _triageSortAsc;
        sorted.sort(function (a, b) {
            var va = keyFn(a), vb = keyFn(b);
            if (va < vb) return asc ? -1 : 1;
            if (va > vb) return asc ? 1 : -1;
            return 0;
        });

        var html = "";
        for (var i = 0; i < sorted.length; i++) {
            var r = sorted[i];
            var overlapPct = (r.shared_function_ratio * 100).toFixed(1);
            var simClass = r.avg_similarity >= 0.8 ? "bsim-sim-high" :
                           r.avg_similarity >= 0.6 ? "bsim-sim-med" : "bsim-sim-low";
            var isExpanded = (_expandedSha256 === r.binary_sha256);
            html += "<tr class=\"bsim-triage-row\" data-sha256=\"" + escapeHtml(r.binary_sha256) +
                "\" data-filename=\"" + escapeHtml(r.binary_filename) + "\">";
            html += "<td class=\"bsim-expand-cell\"><span class=\"tree-expand-icon\">" +
                (isExpanded ? "&#9660;" : "&#9654;") + "</span></td>";
            html += "<td>" + escapeHtml(r.binary_filename);
            if (r.source === "library") {
                html += " <span class=\"badge badge-tool\">LIB</span>";
            }
            html += "</td>";
            html += "<td>" + _renderProjectsCell(r.projects) + "</td>";
            html += "<td class=\"mono\">" + r.shared_function_count + "</td>";
            html += "<td><div class=\"bsim-overlap-bar\"><div class=\"bsim-overlap-fill\" style=\"width:" +
                Math.min(overlapPct, 100) + "%\"></div><span class=\"bsim-overlap-text\">" +
                overlapPct + "%</span></div></td>";
            html += "<td class=\"mono " + simClass + "\">" + r.avg_similarity.toFixed(3) + "</td>";
            html += "<td class=\"mono\">" + r.avg_confidence.toFixed(2) + "</td>";
            html += "<td><button class=\"btn btn-sm bsim-diff-btn\" data-filename=\"" +
                escapeHtml(r.binary_filename) + "\">DIFF</button></td>";
            html += "</tr>";
            // Match detail row (expanded or hidden)
            html += "<tr class=\"bsim-match-detail-row" + (isExpanded ? "" : " d-none") +
                "\" id=\"bsim-detail-" + escapeHtml(r.binary_sha256) + "\">" +
                "<td colspan=\"8\"><div class=\"bsim-match-detail\">" +
                (isExpanded && _matchCache[r.binary_sha256] ? _matchCache[r.binary_sha256].html : "Loading...") +
                "</div></td></tr>";
        }
        document.getElementById("bsim-triage-tbody").innerHTML = html;
    }

    // Sort click handler for triage table headers
    document.getElementById("bsim-triage-table").addEventListener("click", function (e) {
        var th = e.target.closest("th.sortable[data-table='triage']");
        if (th) sortTriageBy(th.dataset.sort);
    });

    function toggleMatchDetail(sha256) {
        var detailRow = document.getElementById("bsim-detail-" + sha256);
        if (!detailRow) return;

        if (_expandedSha256 === sha256) {
            // Collapse
            detailRow.classList.add("d-none");
            _expandedSha256 = "";
            var triggerRow = document.querySelector(".bsim-triage-row[data-sha256=\"" + sha256 + "\"]");
            if (triggerRow) {
                var icon = triggerRow.querySelector(".tree-expand-icon");
                if (icon) icon.innerHTML = "&#9654;";
            }
            return;
        }

        // Collapse previous
        if (_expandedSha256) {
            var prevRow = document.getElementById("bsim-detail-" + _expandedSha256);
            if (prevRow) prevRow.classList.add("d-none");
            var prevTrigger = document.querySelector(".bsim-triage-row[data-sha256=\"" + _expandedSha256 + "\"]");
            if (prevTrigger) {
                var prevIcon = prevTrigger.querySelector(".tree-expand-icon");
                if (prevIcon) prevIcon.innerHTML = "&#9654;";
            }
        }

        _expandedSha256 = sha256;
        detailRow.classList.remove("d-none");
        var currentRow = document.querySelector(".bsim-triage-row[data-sha256=\"" + sha256 + "\"]");
        if (currentRow) {
            var expandIcon = currentRow.querySelector(".tree-expand-icon");
            if (expandIcon) expandIcon.innerHTML = "&#9660;";
        }

        // Use cache if available, otherwise fetch
        if (_matchCache[sha256] && _matchCache[sha256].matches) {
            var container = detailRow.querySelector(".bsim-match-detail");
            container.innerHTML = _buildMatchTableHtml(sha256);
            return;
        }

        fetchJSON("/dashboard/api/bsim/matches", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
            body: JSON.stringify({ binary_sha256: sha256 })
        })
        .then(function (data) {
            var cont = detailRow.querySelector(".bsim-match-detail");
            if (data.error || !data.available) {
                cont.textContent = data.error || "No match data available";
                return;
            }
            _matchCache[sha256] = { matches: data.matches || [], sort: "similarity", asc: false };
            cont.innerHTML = _buildMatchTableHtml(sha256);
        })
        .catch(function () {
            var cont = detailRow.querySelector(".bsim-match-detail");
            cont.textContent = "Failed to load match details";
        });
    }

    // --- Match detail sorting ---
    var _matchSortKeys = {
        addr: function (m) { return m.source_address || ""; },
        name_ours: function (m) { return (m.source_name || "").toLowerCase(); },
        name_theirs: function (m) { return (m.match_name || "").toLowerCase(); },
        similarity: function (m) { return m.similarity || 0; },
        confidence: function (m) { return m.confidence || 0; }
    };

    function sortMatchesBy(sha256, col) {
        var cache = _matchCache[sha256];
        if (!cache) return;
        if (cache.sort === col) {
            cache.asc = !cache.asc;
        } else {
            cache.sort = col;
            cache.asc = (col === "addr" || col === "name_ours" || col === "name_theirs");
        }
        var detailRow = document.getElementById("bsim-detail-" + sha256);
        if (detailRow) {
            var cont = detailRow.querySelector(".bsim-match-detail");
            cont.innerHTML = _buildMatchTableHtml(sha256);
        }
    }

    function _buildMatchTableHtml(sha256) {
        var cache = _matchCache[sha256];
        if (!cache || !cache.matches || !cache.matches.length) {
            return "No function matches recorded";
        }
        var sorted = cache.matches.slice();
        var keyFn = _matchSortKeys[cache.sort] || _matchSortKeys.similarity;
        var asc = cache.asc;
        sorted.sort(function (a, b) {
            var va = keyFn(a), vb = keyFn(b);
            if (va < vb) return asc ? -1 : 1;
            if (va > vb) return asc ? 1 : -1;
            return 0;
        });

        var sortCol = cache.sort || "similarity";
        var html = "<table class=\"data-table data-table-sm bsim-match-table\" data-sha256=\"" + escapeHtml(sha256) + "\">";
        html += "<thead><tr>";
        html += _matchTh("ADDR (OURS)", "addr", sortCol, asc);
        html += _matchTh("NAME (OURS)", "name_ours", sortCol, asc);
        html += _matchTh("NAME (THEIRS)", "name_theirs", sortCol, asc);
        html += _matchTh("SIMILARITY", "similarity", sortCol, asc);
        html += _matchTh("CONFIDENCE", "confidence", sortCol, asc);
        html += "</tr></thead><tbody>";

        for (var i = 0; i < sorted.length; i++) {
            var m = sorted[i];
            var simClass = m.similarity >= 0.8 ? "bsim-sim-high" :
                           m.similarity >= 0.6 ? "bsim-sim-med" : "bsim-sim-low";
            html += "<tr>";
            html += "<td class=\"mono\"><a class=\"func-link\" href=\"/dashboard/functions?highlight=" +
                encodeURIComponent(m.source_address) + "\">" + escapeHtml(m.source_address) + "</a></td>";
            html += "<td>" + escapeHtml(m.source_name) + "</td>";
            html += "<td>" + escapeHtml(m.match_name) + "</td>";
            html += "<td class=\"mono " + simClass + "\">" + (m.similarity || 0).toFixed(3) + "</td>";
            html += "<td class=\"mono\">" + (m.confidence || 0).toFixed(2) + "</td>";
            html += "</tr>";
        }
        html += "</tbody></table>";

        // Cache rendered HTML for repaint during triage re-sort
        cache.html = html;
        return html;
    }

    function _matchTh(label, col, activeCol, activeAsc) {
        var isActive = (col === activeCol);
        var arrow = isActive ? (activeAsc ? "&#9650;" : "&#9660;") : "";
        return "<th class=\"sortable" + (isActive ? " active" : "") +
            "\" data-msort=\"" + col + "\">" + label + " <span class=\"sort-arrow\">" + arrow + "</span></th>";
    }

    function diffFromTriage(filename) {
        switchTab("diff");
        // Try to select the file in the browser
        var rows = document.querySelectorAll(".file-browser-row");
        for (var i = 0; i < rows.length; i++) {
            var path = rows[i].getAttribute("data-path") || "";
            if (path === filename || path.indexOf(filename) !== -1) {
                selectFileRow(rows[i]);
                return;
            }
        }
        // If not found in browser, use manual mode
        switchDiffMode("manual");
        document.getElementById("diff-path-input").value = filename;
    }

    // Single delegated click handler for triage tbody (rows, DIFF buttons, match sort headers)
    document.getElementById("bsim-triage-tbody").addEventListener("click", function (e) {
        // Match detail table sort headers
        var th = e.target.closest("th.sortable[data-msort]");
        if (th) {
            var table = th.closest(".bsim-match-table");
            if (table) sortMatchesBy(table.dataset.sha256, th.dataset.msort);
            return;
        }
        // DIFF button
        var diffBtn = e.target.closest(".bsim-diff-btn");
        if (diffBtn) {
            var fname = diffBtn.getAttribute("data-filename");
            if (fname) diffFromTriage(fname);
            return;
        }
        // Row click -> expand/collapse
        var row = e.target.closest(".bsim-triage-row");
        if (row) {
            var sha = row.getAttribute("data-sha256");
            if (sha) toggleMatchDetail(sha);
        }
    });

    document.getElementById("bsim-index-btn").addEventListener("click", runIndex);
    document.getElementById("bsim-triage-btn").addEventListener("click", runTriage);

    // ====================================================================
    //  TAB 2: DIFF (BinDiff) — ported from diff.js
    // ====================================================================

    function switchDiffMode(mode) {
        var tabs = document.querySelectorAll(".diff-tab");
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.toggle("active", tabs[i].getAttribute("data-mode") === mode);
        }
        document.getElementById("diff-browse-panel").classList.toggle("d-none", mode !== "browse");
        document.getElementById("diff-manual-panel").classList.toggle("d-none", mode !== "manual");
    }

    // --- File browser sort keys ---
    var _fileSortKeys = {
        name: function (f) { return (f.relative_path || f.name || "").toLowerCase(); },
        size: function (f) { return f.size_bytes || 0; },
        format: function (f) { return (f.format_hint || "").toLowerCase(); }
    };

    function sortFilesBy(col) {
        if (_fileSort === col) {
            _fileSortAsc = !_fileSortAsc;
        } else {
            _fileSort = col;
            _fileSortAsc = (col === "name" || col === "format");
        }
        _updateSortArrows("file-browser-table", "files", _fileSort, _fileSortAsc);
        _paintFileRows();
    }

    function loadFileList() {
        var search = document.getElementById("file-browser-search").value.trim();
        var url = "/dashboard/api/list-files?sort=name";
        if (search) url += "&search=" + encodeURIComponent(search);

        fetchJSON(url)
            .then(function (data) {
                if (data.error) {
                    document.getElementById("file-browser-tbody").innerHTML =
                        "<tr><td colspan=\"3\" class=\"empty-msg\">" + escapeHtml(data.error) + "</td></tr>";
                    return;
                }
                _fileListData = data.files || [];
                _paintFileRows();
            })
            .catch(function () {
                document.getElementById("file-browser-tbody").innerHTML =
                    "<tr><td colspan=\"3\" class=\"empty-msg\">Failed to load file list.</td></tr>";
            });
    }

    function _paintFileRows() {
        var tbody = document.getElementById("file-browser-tbody");
        var sorted = _fileListData.slice();
        var keyFn = _fileSortKeys[_fileSort] || _fileSortKeys.name;
        var asc = _fileSortAsc;
        sorted.sort(function (a, b) {
            var va = keyFn(a), vb = keyFn(b);
            if (va < vb) return asc ? -1 : 1;
            if (va > vb) return asc ? 1 : -1;
            return 0;
        });
        if (!sorted.length) {
            tbody.innerHTML = "<tr><td colspan=\"3\" class=\"empty-msg\">No files found.</td></tr>";
            return;
        }
        var html = "";
        for (var i = 0; i < sorted.length; i++) {
            var f = sorted[i];
            var fpath = f.relative_path || f.name;
            var cls = (_selectedFilePath === fpath) ? "file-browser-row selected" : "file-browser-row";
            html += "<tr class=\"" + cls + "\" data-path=\"" + escapeHtml(fpath) + "\">";
            html += "<td class=\"mono\">" + escapeHtml(f.relative_path || f.name) + "</td>";
            html += "<td class=\"dim\">" + escapeHtml(f.size_human) + "</td>";
            html += "<td><span class=\"badge badge-dim\">" + escapeHtml(f.format_hint) + "</span></td>";
            html += "</tr>";
        }
        tbody.innerHTML = html;
    }

    function selectFileRow(row) {
        var prev = document.querySelector(".file-browser-row.selected");
        if (prev) prev.classList.remove("selected");
        row.classList.add("selected");
        _selectedFilePath = row.getAttribute("data-path");
        document.getElementById("file-browser-selected").textContent = _selectedFilePath;
        document.getElementById("diff-run-browse-btn").disabled = false;
    }

    function runDiffWith(filePath, spinnerId, btnId) {
        if (!filePath) return;
        var spinner = document.getElementById(spinnerId);
        var runBtn = document.getElementById(btnId);
        var errorPanel = document.getElementById("diff-error");
        var resultsPanel = document.getElementById("diff-results");

        spinner.classList.remove("d-none");
        runBtn.disabled = true;
        errorPanel.classList.add("d-none");
        resultsPanel.classList.add("d-none");

        fetchJSON("/dashboard/api/diff", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
            body: JSON.stringify({ file_path_b: filePath })
        })
        .then(function (data) {
            spinner.classList.add("d-none");
            runBtn.disabled = false;
            if (data.error) {
                errorPanel.classList.remove("d-none");
                document.getElementById("diff-error-msg").textContent = data.error;
                return;
            }
            renderDiffResults(data);
        })
        .catch(function (err) {
            spinner.classList.add("d-none");
            runBtn.disabled = false;
            errorPanel.classList.remove("d-none");
            document.getElementById("diff-error-msg").textContent = "Request failed: " + err.message;
        });
    }

    function renderDiffResults(data) {
        var resultsPanel = document.getElementById("diff-results");
        resultsPanel.classList.remove("d-none");

        var summaryHtml = "<div class=\"stats-grid\">";
        summaryHtml += _summaryCard("IDENTICAL", data.identical_count, "badge-clean");
        summaryHtml += _summaryCard("DIFFERING", data.differing_count, "badge-warning");
        summaryHtml += _summaryCard("UNMATCHED IN A", data.unmatched_a_count, "badge-danger");
        summaryHtml += _summaryCard("UNMATCHED IN B", data.unmatched_b_count, "badge-danger");
        summaryHtml += "</div>";
        summaryHtml += "<div class=\"dim fs-11 p-6-12\">Comparing <b>" + escapeHtml(data.file_a || "?") +
            "</b> (A) vs <b>" + escapeHtml(data.file_b || "?") + "</b> (B)</div>";
        document.getElementById("diff-summary-bar").innerHTML = summaryHtml;

        var panelsHtml = "";
        panelsHtml += _diffPanel("IDENTICAL FUNCTIONS", data.identical_functions || [], "identical", "diff-identical");
        panelsHtml += _diffPanel("DIFFERING FUNCTIONS", data.differing_functions || [], "differing", "diff-differing");
        panelsHtml += _diffPanel("UNMATCHED IN A", data.unmatched_in_a || [], "unmatched", "diff-unmatched");
        panelsHtml += _diffPanel("UNMATCHED IN B", data.unmatched_in_b || [], "unmatched", "diff-unmatched");
        document.getElementById("diff-panels").innerHTML = panelsHtml;
    }

    function _summaryCard(label, count, badgeClass) {
        return "<div class=\"panel stat-card\">" +
            "<div class=\"panel-header\">" + escapeHtml(label) + "</div>" +
            "<div class=\"stat-value\"><span class=\"badge " + badgeClass + "\" style=\"font-size:16px;padding:4px 12px\">" +
            escapeHtml(String(count)) + "</span></div></div>";
    }

    function _diffPanel(title, items, type, cssClass) {
        if (!items.length) {
            return "<div class=\"panel " + cssClass + "\">" +
                "<div class=\"panel-header\">" + escapeHtml(title) + " <span class=\"badge badge-dim\">0</span></div>" +
                "<div class=\"dim p-10\">None</div></div>";
        }
        var html = "<div class=\"panel " + cssClass + "\">";
        html += "<div class=\"panel-header cursor-pointer\">";
        html += "<span class=\"tree-expand-icon\">&#9660;</span> " + escapeHtml(title) +
            " <span class=\"badge badge-dim\">" + items.length + "</span></div>";
        html += "<div class=\"diff-panel-body\"><table class=\"data-table data-table-sm\"><thead><tr>";

        if (type === "identical") {
            html += "<th>ADDR (A)</th><th>ADDR (B)</th><th>NAME</th>";
        } else if (type === "differing") {
            html += "<th>ADDR (A)</th><th>NAME (A)</th><th>ADDR (B)</th><th>NAME (B)</th>";
        } else {
            html += "<th>ADDRESS</th><th>NAME</th>";
        }
        html += "</tr></thead><tbody>";

        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            html += "<tr>";
            if (type === "identical") {
                html += "<td class=\"mono\"><a class=\"func-link\" href=\"/dashboard/functions?highlight=" +
                    encodeURIComponent(item.addr_a) + "\">" + escapeHtml(item.addr_a) + "</a></td>";
                html += "<td class=\"mono\">" + escapeHtml(item.addr_b) + "</td>";
                html += "<td>" + escapeHtml(item.name) + "</td>";
            } else if (type === "differing") {
                html += "<td class=\"mono\"><a class=\"func-link\" href=\"/dashboard/functions?highlight=" +
                    encodeURIComponent(item.addr_a) + "\">" + escapeHtml(item.addr_a) + "</a></td>";
                html += "<td>" + escapeHtml(item.name_a) + "</td>";
                html += "<td class=\"mono\">" + escapeHtml(item.addr_b) + "</td>";
                html += "<td>" + escapeHtml(item.name_b) + "</td>";
            } else {
                html += "<td class=\"mono\"><a class=\"func-link\" href=\"/dashboard/functions?highlight=" +
                    encodeURIComponent(item.addr) + "\">" + escapeHtml(item.addr) + "</a></td>";
                html += "<td>" + escapeHtml(item.name) + "</td>";
            }
            html += "</tr>";
        }
        html += "</tbody></table></div></div>";
        return html;
    }

    // Diff event listeners
    document.getElementById("diff-panels").addEventListener("click", function (e) {
        var header = e.target.closest(".panel-header");
        if (header) header.parentNode.classList.toggle("collapsed");
    });

    document.getElementById("diff-mode-tabs").addEventListener("click", function (e) {
        var tab = e.target.closest(".diff-tab");
        if (!tab) return;
        switchDiffMode(tab.getAttribute("data-mode"));
    });

    document.getElementById("file-browser-tbody").addEventListener("click", function (e) {
        var row = e.target.closest(".file-browser-row");
        if (row) selectFileRow(row);
    });
    document.getElementById("file-browser-tbody").addEventListener("dblclick", function (e) {
        var row = e.target.closest(".file-browser-row");
        if (row) {
            selectFileRow(row);
            runDiffWith(_selectedFilePath, "diff-spinner-browse", "diff-run-browse-btn");
        }
    });

    document.getElementById("diff-run-browse-btn").addEventListener("click", function () {
        if (_selectedFilePath) {
            runDiffWith(_selectedFilePath, "diff-spinner-browse", "diff-run-browse-btn");
        }
    });

    document.getElementById("diff-run-btn").addEventListener("click", function () {
        var filePath = document.getElementById("diff-path-input").value.trim();
        if (!filePath) {
            showToast("Enter a path to the second binary", "warning");
            return;
        }
        runDiffWith(filePath, "diff-spinner", "diff-run-btn");
    });

    document.getElementById("diff-path-input").addEventListener("keyup", function (e) {
        if (e.key === "Enter") {
            var filePath = this.value.trim();
            if (filePath) runDiffWith(filePath, "diff-spinner", "diff-run-btn");
        }
    });

    document.getElementById("file-browser-search").addEventListener("input", function () {
        if (_debounceTimer) clearTimeout(_debounceTimer);
        _debounceTimer = setTimeout(loadFileList, 300);
    });
    document.getElementById("file-browser-search").addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
            if (_debounceTimer) clearTimeout(_debounceTimer);
            loadFileList();
        }
    });

    document.getElementById("file-browser-sort").addEventListener("change", loadFileList);

    // File browser column sort
    document.getElementById("file-browser-table").addEventListener("click", function (e) {
        var th = e.target.closest("th.sortable[data-table='files']");
        if (th) sortFilesBy(th.dataset.sort);
    });

    // ====================================================================
    //  TAB 3: DATABASE
    // ====================================================================

    // --- DB table sort keys ---
    var _dbSortKeys = {
        name: function (b) { return (b.filename || "").toLowerCase(); },
        project: function (b) {
            var ps = b.projects || [];
            return ps.length ? (ps[0].name || "").toLowerCase() : "\uffff";
        },
        arch: function (b) { return (b.architecture || "").toLowerCase(); },
        functions: function (b) { return b.function_count || 0; },
        source: function (b) { return (b.source || "").toLowerCase(); },
        indexed: function (b) { return b.indexed_at || ""; }
    };

    function sortDbBy(col) {
        if (_dbSort === col) {
            _dbSortAsc = !_dbSortAsc;
        } else {
            _dbSort = col;
            _dbSortAsc = (col === "name" || col === "arch" || col === "source" || col === "project");
        }
        _updateSortArrows("bsim-db-table", "db", _dbSort, _dbSortAsc);
        _paintDbRows();
    }

    function loadIndexedBinaries() {
        fetchJSON("/dashboard/api/bsim/binaries")
            .then(function (data) {
                if (data.error) {
                    document.getElementById("bsim-db-tbody").innerHTML =
                        "<tr><td colspan=\"7\" class=\"empty-msg\">" + escapeHtml(data.error) + "</td></tr>";
                    return;
                }
                _dbBinaries = data.binaries || [];
                document.getElementById("bsim-db-count").textContent = _dbBinaries.length;
                _paintDbRows();
            })
            .catch(function () {
                document.getElementById("bsim-db-tbody").innerHTML =
                    "<tr><td colspan=\"7\" class=\"empty-msg\">Failed to load.</td></tr>";
            });
    }

    function _paintDbRows() {
        var tbody = document.getElementById("bsim-db-tbody");
        var sorted = _dbBinaries.slice();
        var keyFn = _dbSortKeys[_dbSort] || _dbSortKeys.name;
        var asc = _dbSortAsc;
        sorted.sort(function (a, b) {
            var va = keyFn(a), vb = keyFn(b);
            if (va < vb) return asc ? -1 : 1;
            if (va > vb) return asc ? 1 : -1;
            return 0;
        });
        if (!sorted.length) {
            tbody.innerHTML = "<tr><td colspan=\"7\" class=\"empty-msg\">No binaries indexed.</td></tr>";
            return;
        }
        var html = "";
        for (var i = 0; i < sorted.length; i++) {
            var b = sorted[i];
            var dateStr = (b.indexed_at || "").replace("T", " ").substring(0, 19);
            var sourceLabel = b.source === "library" ? "<span class=\"badge badge-tool\">LIBRARY</span>" :
                "<span class=\"badge badge-dim\">USER</span>";
            html += "<tr>";
            html += "<td class=\"mono\">" + escapeHtml(b.filename || "") + "</td>";
            html += "<td>" + _renderProjectsCell(b.projects) + "</td>";
            html += "<td>" + escapeHtml(b.architecture || "") + "</td>";
            html += "<td class=\"mono\">" + (b.function_count || 0) + "</td>";
            html += "<td>" + sourceLabel + "</td>";
            html += "<td class=\"dim fs-11\">" + escapeHtml(dateStr) + "</td>";
            html += "<td><button class=\"btn btn-sm btn-danger bsim-delete-btn\" data-sha256=\"" +
                escapeHtml(b.sha256 || "") + "\" data-filename=\"" + escapeHtml(b.filename || "") +
                "\">DEL</button></td>";
            html += "</tr>";
        }
        tbody.innerHTML = html;
    }

    function deleteBinary(sha256, filename) {
        if (!confirm("Delete \"" + filename + "\" from the signature database?")) return;
        fetchJSON("/dashboard/api/bsim/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
            body: JSON.stringify({ sha256: sha256, confirm: true })
        })
        .then(function (data) {
            if (data.error) {
                showToast(data.error, "error");
                return;
            }
            showToast("Deleted " + filename, "success");
            loadIndexedBinaries();
            loadBsimStats();
        })
        .catch(function (err) {
            showToast("Delete failed: " + err.message, "error");
        });
    }

    function validateDb() {
        var btn = document.getElementById("bsim-validate-btn");
        btn.disabled = true;
        btn.textContent = "VALIDATING...";

        fetchJSON("/dashboard/api/bsim/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
            body: "{}"
        })
        .then(function (data) {
            btn.disabled = false;
            btn.textContent = "VALIDATE";
            renderHealthResults(data);
        })
        .catch(function (err) {
            btn.disabled = false;
            btn.textContent = "VALIDATE";
            showToast("Validation failed: " + err.message, "error");
        });
    }

    function renderHealthResults(data) {
        var panel = document.getElementById("bsim-health-panel");
        var body = document.getElementById("bsim-health-body");
        panel.classList.remove("d-none");

        if (data.error) {
            body.innerHTML = "<span class=\"badge-danger\">" + escapeHtml(data.error) + "</span>";
            return;
        }
        if (data.status === "empty") {
            body.textContent = data.message || "Database is empty.";
            return;
        }

        var html = "<div class=\"stats-grid\">";
        var stats = data.stats || {};
        html += "<div class=\"panel stat-card\"><div class=\"panel-header\">BINARIES</div><div class=\"stat-value\">" + (stats.total_binaries || 0) + "</div></div>";
        html += "<div class=\"panel stat-card\"><div class=\"panel-header\">FUNCTIONS</div><div class=\"stat-value\">" + (stats.total_functions || 0) + "</div></div>";
        html += "<div class=\"panel stat-card\"><div class=\"panel-header\">USER</div><div class=\"stat-value\">" + (stats.user_entries || 0) + "</div></div>";
        html += "<div class=\"panel stat-card\"><div class=\"panel-header\">LIBRARY</div><div class=\"stat-value\">" + (stats.library_entries || 0) + "</div></div>";
        html += "</div>";

        // Sanity test
        var sanity = data.sanity_test || {};
        if (sanity.results && sanity.results.length) {
            var allPassed = sanity.all_passed;
            html += "<div class=\"p-6-12\"><b>SELF-MATCH TEST:</b> " +
                (allPassed ? "<span class=\"badge badge-clean\">PASSED</span>" : "<span class=\"badge badge-danger\">FAILED</span>") +
                " (" + sanity.samples_tested + " samples)</div>";
        }

        // Health messages
        var health = data.health || [];
        for (var i = 0; i < health.length; i++) {
            html += "<div class=\"p-6-12 dim\">" + escapeHtml(health[i]) + "</div>";
        }

        body.innerHTML = html;
    }

    function clearDb() {
        if (!confirm("This will permanently delete ALL entries from the signature database. Continue?")) return;
        if (!confirm("Are you sure? This cannot be undone.")) return;

        fetchJSON("/dashboard/api/bsim/clear", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
            body: JSON.stringify({ confirm: true })
        })
        .then(function (data) {
            if (data.error) {
                showToast(data.error, "error");
                return;
            }
            showToast("Database cleared", "success");
            loadIndexedBinaries();
            loadBsimStats();
        })
        .catch(function (err) {
            showToast("Clear failed: " + err.message, "error");
        });
    }

    // Database event delegation
    document.getElementById("bsim-db-tbody").addEventListener("click", function (e) {
        var btn = e.target.closest(".bsim-delete-btn");
        if (!btn) return;
        var sha256 = btn.getAttribute("data-sha256");
        var filename = btn.getAttribute("data-filename");
        if (sha256) deleteBinary(sha256, filename || sha256.substring(0, 16));
    });

    document.getElementById("bsim-validate-btn").addEventListener("click", validateDb);
    document.getElementById("bsim-clear-btn").addEventListener("click", clearDb);

    // DB table column sort
    document.getElementById("bsim-db-table").addEventListener("click", function (e) {
        var th = e.target.closest("th.sortable[data-table='db']");
        if (th) sortDbBy(th.dataset.sort);
    });

    // ====================================================================
    //  Shared sort arrow updater
    // ====================================================================
    function _updateSortArrows(tableId, tableAttr, activeCol, asc) {
        document.querySelectorAll("#" + tableId + " th.sortable[data-table='" + tableAttr + "']").forEach(function (th) {
            var arrow = th.querySelector(".sort-arrow");
            if (th.dataset.sort === activeCol) {
                th.classList.add("active");
                arrow.innerHTML = asc ? "&#9650;" : "&#9660;";
            } else {
                th.classList.remove("active");
                arrow.innerHTML = "";
            }
        });
    }

    // ====================================================================
    //  Initial load
    // ====================================================================
    loadBsimStats();

    // Auto-load cached triage results on page load (cache_only: never triggers computation)
    fetchJSON("/dashboard/api/bsim/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrfToken() },
        body: JSON.stringify({ cache_only: true })
    })
    .then(function (data) {
        if (!data.error && data.available !== false && data.results && data.results.length) {
            renderTriageResults(data);
        }
    })
    .catch(function () { /* silently ignore — user can click RUN TRIAGE */ });

    // ====================================================================
    //  TAB: PROJECTS COMPARE
    // ====================================================================

    var _projCompareResults = null;
    var _projCompareSort = "jaccard";
    var _projCompareSortAsc = false;

    function loadProjectsForCompare() {
        var selA = document.getElementById("proj-compare-a");
        var selB = document.getElementById("proj-compare-b");
        if (!selA || !selB) return;
        fetchJSON("/dashboard/api/projects?sort_by=name").then(function (data) {
            var projs = (data && data.projects) || [];
            var optsHtml = '<option value="">— select —</option>';
            for (var i = 0; i < projs.length; i++) {
                var p = projs[i];
                optsHtml += '<option value="' + escapeHtml(p.id) + '">' +
                    escapeHtml(p.name) + ' (' + (p.member_count || 0) + ')</option>';
            }
            selA.innerHTML = optsHtml;
            selB.innerHTML = optsHtml;
            // Default project A to the active project (if any) so the
            // common "compare current project against another" workflow
            // is one click instead of two.
            var st = window._arkanaState || {};
            var active = st.active_project;
            if (active && active.id && !active.scratch) {
                selA.value = active.id;
            }
            updateCompareButtonState();
        }).catch(function () {
            selA.innerHTML = '<option value="">(failed to load projects)</option>';
            selB.innerHTML = '<option value="">(failed to load projects)</option>';
        });
    }

    function updateCompareButtonState() {
        var btn = document.getElementById("proj-compare-run-btn");
        if (!btn) return;
        var a = document.getElementById("proj-compare-a").value;
        var b = document.getElementById("proj-compare-b").value;
        btn.disabled = !(a && b && a !== b);
    }

    function runProjectCompare() {
        var a = document.getElementById("proj-compare-a").value;
        var b = document.getElementById("proj-compare-b").value;
        var thrEl = document.getElementById("proj-compare-threshold");
        var threshold = parseFloat(thrEl && thrEl.value) || 0.7;
        if (!a || !b || a === b) return;
        var btn = document.getElementById("proj-compare-run-btn");
        var spin = document.getElementById("proj-compare-spinner");
        btn.disabled = true;
        spin.classList.remove("d-none");
        document.getElementById("proj-compare-error").classList.add("d-none");

        var url = "/dashboard/api/bsim/compare-projects?project_a=" +
            encodeURIComponent(a) + "&project_b=" + encodeURIComponent(b) +
            "&threshold=" + encodeURIComponent(threshold);
        fetchJSON(url).then(function (data) {
            spin.classList.add("d-none");
            updateCompareButtonState();
            if (data.error) {
                showProjectCompareError(data.error);
                return;
            }
            _projCompareResults = data;
            renderProjectCompare(data);
        }).catch(function (err) {
            spin.classList.add("d-none");
            updateCompareButtonState();
            showProjectCompareError(err.message);
        });
    }

    function showProjectCompareError(msg) {
        var panel = document.getElementById("proj-compare-error");
        var body = document.getElementById("proj-compare-error-msg");
        body.textContent = msg || "Comparison failed.";
        panel.classList.remove("d-none");
    }

    function renderProjectCompare(data) {
        var summaryPanel = document.getElementById("proj-compare-summary-panel");
        var summary = document.getElementById("proj-compare-summary");
        var ag = data.aggregate || {};
        var html = "<div class=\"compare-summary-grid\">" +
            "<div><span class=\"dim\">Project A:</span> <strong>" +
                escapeHtml(data.project_a.name) + "</strong> (" + data.project_a.member_count + " members)</div>" +
            "<div><span class=\"dim\">Project B:</span> <strong>" +
                escapeHtml(data.project_b.name) + "</strong> (" + data.project_b.member_count + " members)</div>" +
            "<div><span class=\"dim\">Indexed pairs:</span> <strong>" +
                ag.indexed_pair_count + " / " + ag.pair_count + "</strong></div>" +
            "<div><span class=\"dim\">Total shared functions:</span> <strong>" +
                ag.total_shared + "</strong></div>" +
            "<div><span class=\"dim\">Avg jaccard:</span> <strong>" +
                ag.avg_jaccard.toFixed(3) + "</strong></div>" +
            "<div><span class=\"dim\">Max jaccard:</span> <strong>" +
                ag.max_jaccard.toFixed(3) + "</strong></div>" +
            "<div><span class=\"dim\">Avg similarity:</span> <strong>" +
                ag.avg_similarity.toFixed(3) + "</strong></div>" +
            "</div>";
        summary.innerHTML = html;
        summaryPanel.classList.remove("d-none");

        // Unindexed members hint
        var unPanel = document.getElementById("proj-compare-unindexed-panel");
        var unBody = document.getElementById("proj-compare-unindexed");
        var un = data.unindexed_members || [];
        if (un.length) {
            var lines = un.slice(0, 50).map(function (m) {
                return "<li><span class=\"mono\">" + escapeHtml(m.filename) +
                    "</span> in <em>" + escapeHtml(m.project) + "</em></li>";
            }).join("");
            unBody.innerHTML = "These members are not in the BSim DB and were skipped:" +
                "<ul class=\"member-list\">" + lines + "</ul>" +
                (un.length > 50 ? "<div class=\"dim\">… and " + (un.length - 50) + " more</div>" : "");
            unPanel.classList.remove("d-none");
        } else {
            unPanel.classList.add("d-none");
        }

        _paintProjCompareRows();
    }

    var _projCompareSortKeys = {
        jaccard: function (p) { return p.jaccard || 0; },
        shared: function (p) { return p.shared_function_count || 0; },
        avg_sim: function (p) { return p.avg_similarity || 0; }
    };

    function _paintProjCompareRows() {
        var data = _projCompareResults;
        if (!data) return;
        var pairs = (data.pairs || []).slice();
        var keyFn = _projCompareSortKeys[_projCompareSort] || _projCompareSortKeys.jaccard;
        var asc = _projCompareSortAsc;
        pairs.sort(function (a, b) {
            var va = keyFn(a), vb = keyFn(b);
            if (va < vb) return asc ? -1 : 1;
            if (va > vb) return asc ? 1 : -1;
            return 0;
        });

        document.getElementById("proj-compare-count").textContent = pairs.length;
        var tbody = document.getElementById("proj-compare-tbody");
        if (!pairs.length) {
            tbody.innerHTML = "<tr><td colspan=\"6\" class=\"empty-msg\">No pairs to compare.</td></tr>";
            return;
        }
        var rows = pairs.map(function (p) {
            var statusBadge;
            if (p.available) {
                var jaccard = p.jaccard || 0;
                var simClass = jaccard >= 0.5 ? "bsim-sim-high" :
                              jaccard >= 0.2 ? "bsim-sim-med" : "bsim-sim-low";
                statusBadge = "<span class=\"badge badge-clean\">OK</span>";
                return "<tr>" +
                    "<td class=\"mono fs-11\" title=\"" + escapeHtml(p.a_sha256) + "\">" +
                        escapeHtml(p.a_filename) + "</td>" +
                    "<td class=\"mono fs-11\" title=\"" + escapeHtml(p.b_sha256) + "\">" +
                        escapeHtml(p.b_filename) + "</td>" +
                    "<td class=\"mono " + simClass + "\">" + jaccard.toFixed(3) + "</td>" +
                    "<td class=\"mono\">" + (p.shared_function_count || 0) + "</td>" +
                    "<td class=\"mono\">" + (p.avg_similarity || 0).toFixed(3) + "</td>" +
                    "<td>" + statusBadge + "</td>" +
                "</tr>";
            }
            return "<tr class=\"dim\">" +
                "<td class=\"mono fs-11\">" + escapeHtml(p.a_filename) + "</td>" +
                "<td class=\"mono fs-11\">" + escapeHtml(p.b_filename) + "</td>" +
                "<td class=\"mono\">—</td><td class=\"mono\">—</td><td class=\"mono\">—</td>" +
                "<td><span class=\"badge badge-dim\" title=\"" +
                    escapeHtml(p.error || "") + "\">SKIPPED</span></td>" +
            "</tr>";
        }).join("");
        tbody.innerHTML = rows;
    }

    document.getElementById("proj-compare-a").addEventListener("change", updateCompareButtonState);
    document.getElementById("proj-compare-b").addEventListener("change", updateCompareButtonState);
    document.getElementById("proj-compare-run-btn").addEventListener("click", runProjectCompare);
    document.getElementById("proj-compare-table").addEventListener("click", function (e) {
        var th = e.target.closest("th.sortable[data-table='proj-compare']");
        if (!th) return;
        var col = th.dataset.sort;
        if (_projCompareSort === col) {
            _projCompareSortAsc = !_projCompareSortAsc;
        } else {
            _projCompareSort = col;
            _projCompareSortAsc = false;
        }
        _updateSortArrows("proj-compare-table", "proj-compare", _projCompareSort, _projCompareSortAsc);
        _paintProjCompareRows();
    });
})();

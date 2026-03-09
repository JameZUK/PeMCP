/* Arkana Dashboard — Binary Diff View */
(function () {
    "use strict";

    var _selectedFilePath = "";
    var _debounceTimer = null;

    // --- Mode switching ---
    function switchDiffMode(mode) {
        var tabs = document.querySelectorAll(".diff-tab");
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.toggle("active", tabs[i].getAttribute("data-mode") === mode);
        }
        document.getElementById("diff-browse-panel").classList.toggle("d-none", mode !== "browse");
        document.getElementById("diff-manual-panel").classList.toggle("d-none", mode !== "manual");
    }

    // --- File browser ---
    function loadFileList() {
        var search = document.getElementById("file-browser-search").value.trim();
        var sort = document.getElementById("file-browser-sort").value;
        var url = "/dashboard/api/list-files?sort=" + encodeURIComponent(sort);
        if (search) url += "&search=" + encodeURIComponent(search);

        fetchJSON(url)
            .then(function (data) {
                if (data.error) {
                    document.getElementById("file-browser-tbody").innerHTML =
                        "<tr><td colspan=\"3\" class=\"empty-msg\">" + escapeHtml(data.error) + "</td></tr>";
                    return;
                }
                renderFileList(data.files || []);
            })
            .catch(function () {
                document.getElementById("file-browser-tbody").innerHTML =
                    "<tr><td colspan=\"3\" class=\"empty-msg\">Failed to load file list.</td></tr>";
            });
    }

    function renderFileList(files) {
        var tbody = document.getElementById("file-browser-tbody");
        if (!files.length) {
            tbody.innerHTML = "<tr><td colspan=\"3\" class=\"empty-msg\">No files found.</td></tr>";
            return;
        }
        var html = "";
        for (var i = 0; i < files.length; i++) {
            var f = files[i];
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

    // --- Shared diff runner ---
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
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
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

    // --- Render diff results ---
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

        // Collapse toggle handled via delegated listener below
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

    // --- Wire up all event listeners ---
    // Delegated collapse toggle for diff result panels
    document.getElementById("diff-panels").addEventListener("click", function (e) {
        var header = e.target.closest(".panel-header");
        if (header) header.parentNode.classList.toggle("collapsed");
    });

    // Mode tabs
    document.getElementById("diff-mode-tabs").addEventListener("click", function (e) {
        var tab = e.target.closest(".diff-tab");
        if (!tab) return;
        switchDiffMode(tab.getAttribute("data-mode"));
    });

    // File browser: row click (delegation) and double-click
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

    // Browse mode RUN DIFF button
    document.getElementById("diff-run-browse-btn").addEventListener("click", function () {
        if (_selectedFilePath) {
            runDiffWith(_selectedFilePath, "diff-spinner-browse", "diff-run-browse-btn");
        }
    });

    // Manual mode RUN DIFF button
    document.getElementById("diff-run-btn").addEventListener("click", function () {
        var filePath = document.getElementById("diff-path-input").value.trim();
        if (!filePath) {
            showToast("Enter a path to the second binary", "warning");
            return;
        }
        runDiffWith(filePath, "diff-spinner", "diff-run-btn");
    });

    // Manual mode Enter key
    document.getElementById("diff-path-input").addEventListener("keyup", function (e) {
        if (e.key === "Enter") {
            var filePath = this.value.trim();
            if (filePath) runDiffWith(filePath, "diff-spinner", "diff-run-btn");
        }
    });

    // File browser search with debounce
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

    // Sort change
    document.getElementById("file-browser-sort").addEventListener("change", loadFileList);

    // Initial file list load
    loadFileList();
})();

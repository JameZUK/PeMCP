/* Arkana Dashboard — Sections enhancements (entropy heatmap + resources) */
(function () {
    "use strict";

    var _entropyData = null;
    var _heatmapListenerAttached = false;

    function loadEntropy() {
        fetch("/dashboard/api/entropy")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                _entropyData = data;
                renderEntropyBar(data);
                renderHeatmap(data);
            })
            .catch(function () { /* entropy is optional enhancement */ });
    }

    function renderEntropyBar(data) {
        var target = document.getElementById("entropy-bar");
        if (!target) return;
        var overall = data.overall || 0;
        var pct = (overall / 8.0 * 100).toFixed(1);
        var color = overall > 7.0 ? "var(--danger)" : overall > 5.0 ? "var(--warning)" : "var(--safe)";
        target.innerHTML =
            "<div class=\"entropy-overall\">" +
            "<span>Overall Entropy: <strong>" + escapeHtml(overall.toFixed(4)) + "</strong> / 8.0</span>" +
            "<div class=\"entropy-gauge\">" +
            "<div class=\"entropy-gauge-fill\" style=\"width:" + pct + "%;background:" + color + "\"></div>" +
            "</div></div>";
    }

    function renderHeatmap(data) {
        var target = document.getElementById("entropy-heatmap");
        if (!target || !data.heatmap || data.heatmap.length === 0) return;

        var html = "<div class=\"heatmap-grid\">";
        var fileSize = data.file_size || 1;
        var blockSize = Math.max(1, Math.floor(fileSize / data.heatmap.length));

        data.heatmap.forEach(function (entropy, idx) {
            var r = 0, g = 0;
            if (entropy <= 4.0) {
                // Green to yellow
                r = Math.floor(entropy / 4.0 * 255);
                g = 255;
            } else {
                // Yellow to red
                r = 255;
                g = Math.floor((8.0 - entropy) / 4.0 * 255);
            }
            var color = "rgb(" + r + "," + g + ",0)";
            var offset = idx * blockSize;
            html += "<div class=\"heatmap-cell\" style=\"background:" + color + "\" " +
                    "title=\"Offset: 0x" + offset.toString(16).toUpperCase() + " | Entropy: " + entropy.toFixed(2) + "\" " +
                    "data-offset=\"" + offset + "\"></div>";
        });
        html += "</div>";
        html += "<div class=\"heatmap-legend\">" +
                "<span style=\"color:#00ff00\">&#9632; LOW (0)</span> " +
                "<span style=\"color:#ffff00\">&#9632; MED (4)</span> " +
                "<span style=\"color:#ff0000\">&#9632; HIGH (8)</span>" +
                "</div>";
        target.innerHTML = html;

        // Click heatmap cell to jump to hex view (attach once to prevent accumulation)
        if (!_heatmapListenerAttached) {
            _heatmapListenerAttached = true;
            target.addEventListener("click", function (e) {
                var cell = e.target.closest(".heatmap-cell");
                if (cell) {
                    var offset = cell.getAttribute("data-offset");
                    if (offset) {
                        window.location.href = "/dashboard/hexview?offset=0x" + parseInt(offset, 10).toString(16).toUpperCase();
                    }
                }
            });
        }
    }

    function loadResources() {
        fetch("/dashboard/api/resources")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                renderResources(data);
            })
            .catch(function () { /* resources are optional */ });
    }

    function renderResources(data) {
        var target = document.getElementById("resources-detail");
        if (!target || !data.resources || data.resources.length === 0) return;

        var html = "<div class=\"table-wrap\"><table class=\"data-table data-table-sm\">";
        html += "<thead><tr><th>TYPE</th><th>NAME</th><th>SIZE</th><th>ENTROPY</th><th>LANGUAGE</th></tr></thead><tbody>";
        data.resources.forEach(function (r) {
            var entropyClass = r.high_entropy ? " badge-danger" : " badge-dim";
            html += "<tr>";
            html += "<td>" + escapeHtml(String(r.type || "?")) + "</td>";
            html += "<td>" + escapeHtml(String(r.name || "?")) + "</td>";
            html += "<td>" + escapeHtml(String(r.size || 0)) + "</td>";
            html += "<td><span class=\"badge" + entropyClass + "\">" + escapeHtml(String(r.entropy || 0)) + "</span></td>";
            html += "<td>" + escapeHtml(String(r.language || "?")) + "</td>";
            html += "</tr>";
        });
        html += "</tbody></table></div>";
        target.innerHTML = html;
    }

    // Add inline sparklines to section rows
    function addSparklines() {
        if (!_entropyData || !_entropyData.sections) return;
        var rows = document.querySelectorAll("#section-table tbody tr, .section-bar-row");
        // Sparklines are already shown via the entropy column — this is supplementary
    }

    // Initialize
    loadEntropy();
    loadResources();
})();

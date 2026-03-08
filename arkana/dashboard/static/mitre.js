/* Arkana Dashboard — MITRE ATT&CK / Threat Intel */
(function () {
    "use strict";

    var matrixContainer = document.getElementById("mitre-matrix");
    var summaryContainer = document.getElementById("mitre-summary");

    function refreshMitre() {
        fetch("/dashboard/api/mitre")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                renderSummary(data);
                renderMatrix(data);
                renderIOCs(data);
            })
            .catch(function () {
                if (summaryContainer) {
                    summaryContainer.innerHTML = "<div class=\"empty-msg\">Failed to load MITRE data.</div>";
                }
            });
    }

    function renderSummary(data) {
        if (!summaryContainer) return;
        var techCount = document.getElementById("mitre-tech-count");
        var iocCount = document.getElementById("mitre-ioc-count");
        if (techCount) techCount.textContent = (data.technique_count || 0) + " techniques";
        if (iocCount) iocCount.textContent = (data.ioc_count || 0) + " IOCs";

        if (!data.tactics || Object.keys(data.tactics).length === 0) {
            summaryContainer.innerHTML = "<div class=\"empty-msg\">No MITRE ATT&CK data available. Run enrichment analysis first.</div>";
            return;
        }

        var html = "<div class=\"mitre-stats\">";
        html += "<span class=\"badge badge-active\">" + escapeHtml(String(data.tactic_count || 0)) + " tactics</span> ";
        html += "<span class=\"badge badge-running\">" + escapeHtml(String(data.technique_count || 0)) + " techniques</span> ";
        html += "<span class=\"badge badge-dim\">" + escapeHtml(String(data.ioc_count || 0)) + " IOCs</span>";
        html += "</div>";
        summaryContainer.innerHTML = html;
    }

    function renderMatrix(data) {
        if (!matrixContainer || !data.tactics) return;
        var tactics = data.tactics;
        if (Object.keys(tactics).length === 0) {
            matrixContainer.innerHTML = "<div class=\"empty-msg\">No techniques mapped.</div>";
            return;
        }

        var html = "";
        Object.keys(tactics).forEach(function (tactic) {
            var techs = tactics[tactic];
            html += "<div class=\"mitre-tactic-col\">";
            html += "<div class=\"mitre-tactic-header\">" + escapeHtml(tactic.toUpperCase()) + "</div>";
            techs.forEach(function (t) {
                html += "<div class=\"mitre-technique-card\" data-technique-id=\"" + escapeHtml(t.id || "") + "\">";
                html += "<span class=\"mitre-tid\">" + escapeHtml(t.id || "") + "</span> ";
                html += "<span class=\"mitre-tname\">" + escapeHtml(t.name || "") + "</span>";
                if (t.confidence) {
                    html += " <span class=\"badge badge-dim\">" + escapeHtml(t.confidence) + "</span>";
                }
                if (t.description) {
                    html += "<div class=\"dim fs-10\">" + escapeHtml(t.description) + "</div>";
                }
                html += "</div>";
            });
            html += "</div>";
        });
        matrixContainer.innerHTML = html;
    }

    function renderIOCs(data) {
        var container = document.getElementById("ioc-table-container");
        if (!container || !data.iocs) return;
        if (Object.keys(data.iocs).length === 0) {
            container.innerHTML = "<div class=\"empty-msg\">No IOCs extracted.</div>";
            return;
        }

        var html = "";
        Object.keys(data.iocs).forEach(function (iocType) {
            var items = data.iocs[iocType];
            html += "<div class=\"ioc-section\">";
            html += "<div class=\"ioc-type-header\">" + escapeHtml(iocType.toUpperCase().replace(/_/g, " ")) + " <span class=\"badge badge-dim\">" + items.length + "</span></div>";
            html += "<div class=\"table-wrap\"><table class=\"data-table data-table-sm\"><tbody>";
            items.forEach(function (item) {
                var val = typeof item === "string" ? item : JSON.stringify(item);
                html += "<tr><td class=\"mono\">" + escapeHtml(val) + "</td></tr>";
            });
            html += "</tbody></table></div></div>";
        });
        container.innerHTML = html;
    }

    // Technique card click — show detail (could link to capa or functions)
    if (matrixContainer) {
        matrixContainer.addEventListener("click", function (e) {
            var card = e.target.closest(".mitre-technique-card");
            if (card) {
                card.classList.toggle("expanded");
            }
        });
    }
})();

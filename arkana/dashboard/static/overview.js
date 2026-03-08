/* Arkana Dashboard — Overview enhancements (triage, packing, similarity, export) */
(function () {
    "use strict";

    function loadTriagePanel() {
        var target = document.getElementById("triage-panel-content");
        if (!target) return;
        fetch("/dashboard/api/triage-report")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.available) {
                    target.innerHTML = "<div class=\"dim\">Triage data not yet available. Enrichment may still be running.</div>";
                    return;
                }
                var riskClass = "badge-dim";
                var level = (data.risk_level || "unknown").toLowerCase();
                if (level === "critical" || level === "high") riskClass = "badge-danger";
                else if (level === "medium" || level === "suspicious") riskClass = "badge-warning";
                else if (level === "low" || level === "clean") riskClass = "badge-completed";

                var html = "<div class=\"triage-summary-grid\">";
                html += "<div class=\"triage-card\"><div class=\"triage-card-label\">RISK LEVEL</div>";
                html += "<div class=\"badge " + riskClass + " triage-risk-badge\">" + escapeHtml(String(data.risk_level || "UNKNOWN").toUpperCase()) + "</div></div>";

                if (data.risk_score !== undefined) {
                    html += "<div class=\"triage-card\"><div class=\"triage-card-label\">RISK SCORE</div>";
                    html += "<div class=\"triage-card-value\">" + escapeHtml(String(data.risk_score)) + "</div></div>";
                }
                if (data.suspicious_count !== undefined) {
                    html += "<div class=\"triage-card\"><div class=\"triage-card-label\">SUSPICIOUS</div>";
                    html += "<div class=\"triage-card-value\">" + escapeHtml(String(data.suspicious_count)) + "</div></div>";
                }
                if (data.capabilities_count !== undefined) {
                    html += "<div class=\"triage-card\"><div class=\"triage-card-label\">CAPABILITIES</div>";
                    html += "<div class=\"triage-card-value\">" + escapeHtml(String(data.capabilities_count)) + "</div></div>";
                }
                html += "</div>";

                // Key findings
                if (data.findings && data.findings.length > 0) {
                    html += "<div class=\"triage-findings\"><div class=\"dim\">KEY FINDINGS:</div><ul>";
                    data.findings.slice(0, 10).forEach(function (f) {
                        var text = typeof f === "string" ? f : (f.description || f.finding || JSON.stringify(f));
                        html += "<li>" + escapeHtml(text.substring(0, 200)) + "</li>";
                    });
                    html += "</ul></div>";
                }
                target.innerHTML = html;
            })
            .catch(function () {
                if (target) target.innerHTML = "<div class=\"dim\">Failed to load triage data.</div>";
            });
    }

    function loadPackingCard() {
        var target = document.getElementById("packing-card-content");
        if (!target) return;
        fetch("/dashboard/api/packing")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.available) {
                    target.innerHTML = "<span class=\"dim\">N/A</span>";
                    return;
                }
                var html = "<div class=\"packing-info\">";
                var likelihood = String(data.packed_likelihood || "unknown");
                var packClass = likelihood.toLowerCase() === "high" || likelihood === "true" ? "badge-danger" :
                                likelihood.toLowerCase() === "medium" ? "badge-warning" : "badge-dim";
                html += "<span class=\"badge " + packClass + "\">" + escapeHtml(likelihood.toUpperCase()) + "</span>";
                if (data.packer_name) {
                    html += " <span class=\"dim\">" + escapeHtml(data.packer_name) + "</span>";
                }
                if (data.indicators && data.indicators.length > 0) {
                    html += "<div class=\"dim fs-10\" style=\"margin-top:4px\">";
                    data.indicators.slice(0, 5).forEach(function (ind) {
                        var text = typeof ind === "string" ? ind : (ind.description || JSON.stringify(ind));
                        html += escapeHtml(text.substring(0, 100)) + "<br>";
                    });
                    html += "</div>";
                }
                html += "</div>";
                target.innerHTML = html;
            })
            .catch(function () {
                if (target) target.innerHTML = "<span class=\"dim\">Error</span>";
            });
    }

    function loadSimilarityCard() {
        var target = document.getElementById("similarity-card-content");
        if (!target) return;
        fetch("/dashboard/api/similarity")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.available) {
                    target.innerHTML = "<span class=\"dim\">N/A</span>";
                    return;
                }
                var html = "<div class=\"similarity-hashes\">";
                if (data.imphash) {
                    html += "<div class=\"hash-row\"><span class=\"dim\">IMPHASH:</span> <span class=\"mono\">" +
                            escapeHtml(data.imphash) + "</span> <button class=\"btn-copy\" data-copy=\"" +
                            escapeHtml(data.imphash) + "\">COPY</button></div>";
                }
                if (data.ssdeep) {
                    html += "<div class=\"hash-row\"><span class=\"dim\">SSDEEP:</span> <span class=\"mono\">" +
                            escapeHtml(data.ssdeep) + "</span> <button class=\"btn-copy\" data-copy=\"" +
                            escapeHtml(data.ssdeep) + "\">COPY</button></div>";
                }
                if (data.tlsh) {
                    html += "<div class=\"hash-row\"><span class=\"dim\">TLSH:</span> <span class=\"mono\">" +
                            escapeHtml(data.tlsh) + "</span> <button class=\"btn-copy\" data-copy=\"" +
                            escapeHtml(data.tlsh) + "\">COPY</button></div>";
                }
                if (!data.imphash && !data.ssdeep && !data.tlsh) {
                    html += "<span class=\"dim\">No similarity hashes available.</span>";
                }
                html += "</div>";
                target.innerHTML = html;
            })
            .catch(function () {
                if (target) target.innerHTML = "<span class=\"dim\">Error</span>";
            });
    }

    function exportReport() {
        var btn = document.getElementById("btn-export-report");
        if (btn) btn.textContent = "EXPORTING...";
        fetch("/dashboard/api/export-report", {
            method: "POST",
            headers: {"X-CSRF-Token": getCsrfToken()},
        }).then(function (r) {
            if (!r.ok) throw new Error("Export failed");
            var disposition = r.headers.get("Content-Disposition") || "";
            var match = disposition.match(/filename="?([^"]+)"?/);
            var filename = match ? match[1] : "arkana_report.json";
            return r.blob().then(function (blob) {
                var url = URL.createObjectURL(blob);
                var a = document.createElement("a");
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showToast("Report exported", "success");
            });
        }).catch(function () {
            showToast("Export failed", "error");
        }).finally(function () {
            if (btn) btn.textContent = "EXPORT REPORT";
        });
    }

    // Copy button handler
    document.addEventListener("click", function (e) {
        if (e.target.classList.contains("btn-copy")) {
            var text = e.target.getAttribute("data-copy");
            if (text && navigator.clipboard) {
                navigator.clipboard.writeText(text).then(function () {
                    showToast("Copied", "success");
                });
            }
        }
        if (e.target.id === "btn-export-report") {
            exportReport();
        }
    });

    // Initialize panels
    loadTriagePanel();
    loadPackingCard();
    loadSimilarityCard();
})();

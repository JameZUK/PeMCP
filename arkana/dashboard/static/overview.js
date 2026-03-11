/* Arkana Dashboard — Overview (digest + report) */
(function () {
    "use strict";

    var _rawReport = "";

    function loadDigest() {
        var target = document.getElementById("digest-content");
        if (!target) return;
        target.innerHTML = "<div class=\"dim\">Loading digest...</div>";
        fetchJSON("/dashboard/api/digest")
            .then(function (data) {
                if (!data.available) {
                    target.innerHTML = "<div class=\"digest-empty\">No analysis data yet. Load a file and run analysis tools.</div>";
                    return;
                }
                var html = "";

                // Profile
                if (data.binary_profile) {
                    html += "<div class=\"digest-profile\">" + escapeHtml(data.binary_profile) + "</div>";
                }

                // Phase + Coverage row
                html += "<div class=\"digest-meta-row\">";
                if (data.analysis_phase) {
                    html += "<span class=\"badge badge-phase-" + escapeHtml(data.analysis_phase) + "\">" +
                            escapeHtml(data.analysis_phase.toUpperCase().replace("_", " ")) + "</span>";
                }
                if (data.coverage) {
                    var pctNum = parseFloat(data.coverage.pct) || 0;
                    html += "<span class=\"digest-coverage\">" +
                            escapeHtml(String(data.coverage.explored)) + "/" +
                            escapeHtml(String(data.coverage.total)) + " functions (" +
                            escapeHtml(data.coverage.pct) + ")</span>";
                    html += "<div class=\"progress-bar digest-progress\"><div class=\"progress-fill\" style=\"width:" +
                            Math.min(pctNum, 100) + "%\"></div></div>";
                }
                html += "</div>";

                // Key findings
                if (data.key_findings && data.key_findings.length > 0) {
                    html += "<div class=\"digest-section\">";
                    html += "<div class=\"digest-section-title\">KEY FINDINGS (" + escapeHtml(String(data.key_findings.length)) + ")</div>";
                    html += "<ul class=\"digest-findings\">";
                    var showCount = Math.min(data.key_findings.length, 5);
                    for (var i = 0; i < showCount; i++) {
                        html += "<li>" + escapeHtml(data.key_findings[i].substring(0, 200)) + "</li>";
                    }
                    if (data.key_findings.length > 5) {
                        html += "<li class=\"dim\">... and " + escapeHtml(String(data.key_findings.length - 5)) + " more</li>";
                    }
                    html += "</ul></div>";
                }

                // Conclusion / hypothesis
                if (data.conclusion && data.conclusion.length > 0) {
                    html += "<div class=\"digest-section\">";
                    html += "<div class=\"digest-section-title\">CONCLUSION</div>";
                    html += "<ul class=\"digest-findings digest-conclusion\">";
                    var maxConclusion = Math.min(data.conclusion.length, 8);
                    for (var ci = 0; ci < maxConclusion; ci++) {
                        html += "<li>" + escapeHtml(data.conclusion[ci]) + "</li>";
                    }
                    if (data.conclusion.length > 8) {
                        html += "<li class=\"dim\">... and " + escapeHtml(String(data.conclusion.length - 8)) + " more</li>";
                    }
                    html += "</ul></div>";
                }

                // Unexplored high priority
                if (data.unexplored_high_priority && data.unexplored_high_priority.length > 0) {
                    html += "<div class=\"digest-section\">";
                    html += "<div class=\"digest-section-title\">HIGH PRIORITY (" +
                            escapeHtml(String(data.unexplored_high_priority.length)) + ")</div>";
                    html += "<div class=\"digest-functions\">";
                    data.unexplored_high_priority.forEach(function (fn) {
                        html += "<div class=\"digest-func-row digest-priority\">" +
                                "<span class=\"badge badge-warning\">" + escapeHtml(String(fn.score)) + "</span> " +
                                "<a class=\"func-link\" href=\"/dashboard/functions?highlight=" +
                                encodeURIComponent(fn.addr) + "\">" +
                                escapeHtml(fn.addr) + "</a> " +
                                "<span class=\"dim\">" + escapeHtml(fn.name) + "</span> " +
                                "<span class=\"digest-func-summary dim\">" + escapeHtml(fn.reason) + "</span>" +
                                "</div>";
                    });
                    html += "</div></div>";
                }

                // Analyst notes
                if (data.analyst_notes && data.analyst_notes.length > 0) {
                    html += "<div class=\"digest-section\">";
                    html += "<div class=\"digest-section-title\">ANALYST NOTES (" +
                            escapeHtml(String(data.analyst_notes.length)) + ")</div>";
                    html += "<ul class=\"digest-findings\">";
                    data.analyst_notes.forEach(function (n) {
                        html += "<li><span class=\"badge badge-cat-" + escapeHtml(n.category) + "\">" +
                                escapeHtml(n.category.toUpperCase()) + "</span> " +
                                escapeHtml(n.content) + "</li>";
                    });
                    html += "</ul></div>";
                }

                // User flags
                if (data.user_flags) {
                    var flagged = data.user_flags.flagged || [];
                    var suspicious = data.user_flags.suspicious || [];
                    if (flagged.length > 0 || suspicious.length > 0) {
                        html += "<div class=\"digest-section\">";
                        html += "<div class=\"digest-section-title\">TRIAGE FLAGS</div>";
                        if (flagged.length > 0) {
                            html += "<div><span class=\"badge badge-flagged\">FLAGGED</span> ";
                            flagged.forEach(function (addr) {
                                html += "<a class=\"func-link\" href=\"/dashboard/functions?highlight=" +
                                        encodeURIComponent(addr) + "\">" + escapeHtml(addr) + "</a> ";
                            });
                            html += "</div>";
                        }
                        if (suspicious.length > 0) {
                            html += "<div style=\"margin-top:4px\"><span class=\"badge badge-suspicious\">SUSPICIOUS</span> ";
                            suspicious.forEach(function (addr) {
                                html += "<a class=\"func-link\" href=\"/dashboard/functions?highlight=" +
                                        encodeURIComponent(addr) + "\">" + escapeHtml(addr) + "</a> ";
                            });
                            html += "</div>";
                        }
                        html += "</div>";
                    }
                }

                target.innerHTML = html;
            })
            .catch(function () {
                if (target) target.innerHTML = "<div class=\"dim\">Failed to load digest.</div>";
            });
    }

    function openReportModal() {
        var modal = document.getElementById("report-modal");
        if (modal) modal.style.display = "flex";
    }

    function closeReportModal() {
        var modal = document.getElementById("report-modal");
        if (modal) modal.style.display = "none";
    }

    function generateReport() {
        var reportText = document.getElementById("report-text");
        if (reportText) reportText.textContent = "Generating report...";
        _rawReport = "";
        openReportModal();

        fetch("/dashboard/api/generate-report", {
            method: "POST",
            headers: {"X-CSRF-Token": getCsrfToken()},
        }).then(function (r) {
            if (!r.ok) throw new Error("Generation failed (" + r.status + ")");
            return r.json();
        }).then(function (data) {
            if (!data.available) {
                if (reportText) reportText.textContent = "No analysis data available. Load a file first.";
                return;
            }
            _rawReport = data.report || "";
            if (reportText) reportText.textContent = _rawReport;
        }).catch(function (err) {
            if (reportText) reportText.textContent = "Error: " + (err.message || "report generation failed");
        });
    }

    function copyReport() {
        if (!_rawReport) {
            showToast("No report to copy", "error");
            return;
        }
        if (navigator.clipboard) {
            navigator.clipboard.writeText(_rawReport).then(function () {
                showToast("Report copied to clipboard", "success");
            }).catch(function () {
                showToast("Copy failed — check browser permissions", "error");
            });
        }
    }

    function downloadReport() {
        if (!_rawReport) {
            showToast("No report to download", "error");
            return;
        }
        var blob = new Blob([_rawReport], {type: "text/markdown"});
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "arkana_report.md";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Report downloaded", "success");
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

    // Event delegation
    document.addEventListener("click", function (e) {
        var action = e.target.getAttribute("data-action");
        if (action === "copy-hash") {
            var hash = e.target.getAttribute("data-hash");
            if (hash && navigator.clipboard) {
                navigator.clipboard.writeText(hash).then(function () {
                    showToast("Hash copied", "success");
                }).catch(function () {
                    showToast("Copy failed", "error");
                });
            }
        } else if (action === "refresh-digest") {
            loadDigest();
        } else if (action === "generate-report") {
            generateReport();
        } else if (action === "copy-conclusion" || (e.target.closest && e.target.closest("[data-action='copy-conclusion']"))) {
            var body = document.querySelector(".conclusion-body");
            if (body) {
                var text = body.innerText || body.textContent || "";
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(function () {
                        showToast("Conclusion copied", "success");
                    }).catch(function () {
                        showToast("Copy failed", "error");
                    });
                }
            }
        } else if (action === "copy-report") {
            copyReport();
        } else if (action === "download-report") {
            downloadReport();
        } else if (action === "close-report") {
            closeReportModal();
        } else if (e.target.id === "btn-export-report") {
            exportReport();
        }
    });

    // Close modal on Escape
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
            closeReportModal();
        }
    });

    // Initialize
    loadDigest();
})();

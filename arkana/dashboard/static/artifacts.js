/* Arkana Dashboard — Artifacts page interactions
 *
 * CSP-safe: no inline scripts. Uses fetchJSON, getCsrfToken, escapeHtml,
 * and showToast helpers from dashboard.js.
 */
(function () {
    "use strict";

    var tbody = document.getElementById("artifacts-tbody");
    if (!tbody) return;

    var filterInput = document.getElementById("artifacts-filter");
    var kindSelect = document.getElementById("artifacts-kind");
    var toolSelect = document.getElementById("artifacts-tool");
    var tagSelect = document.getElementById("artifacts-tag");
    var sortSelect = document.getElementById("artifacts-sort");
    var countBadge = document.getElementById("artifacts-count");
    var selectAll = document.getElementById("select-all");
    var bulkTagBtn = document.getElementById("btn-bulk-tag");
    var bulkDeleteBtn = document.getElementById("btn-bulk-delete");

    var debounceTimer = null;

    // -----------------------------------------------------------------
    //  Data load + render
    // -----------------------------------------------------------------
    function reload() {
        var params = new URLSearchParams();
        if (filterInput && filterInput.value) params.set("filter", filterInput.value);
        if (kindSelect && kindSelect.value) params.set("kind", kindSelect.value);
        if (toolSelect && toolSelect.value) params.set("tool", toolSelect.value);
        if (tagSelect && tagSelect.value) params.set("tag", tagSelect.value);
        if (sortSelect && sortSelect.value) params.set("sort", sortSelect.value);
        var url = "/dashboard/api/artifacts" + (params.toString() ? "?" + params : "");
        fetchJSON(url).then(function (data) {
            renderRows(data);
            updateFacets(data);
            if (countBadge) countBadge.textContent = String(data.filtered_count || 0);
        }).catch(function (e) {
            showToast("Failed to load artifacts: " + e.message, "error");
        });
    }

    function renderRows(data) {
        var rows = data.artifacts || [];
        if (!rows.length) {
            tbody.innerHTML = '<tr><td colspan="11"><div class="empty-msg">No artifacts match the current filters.</div></td></tr>';
            return;
        }
        var html = rows.map(function (a) {
            var icon = a.kind === "directory" ? "📁" : "📄";
            var tags = (a.tags || []).map(function (t) {
                return '<span class="badge badge-tag">' + escapeHtml(t) + "</span>";
            }).join("");
            return (
                '<tr class="artifact-row" data-artifact-id="' + escapeHtml(a.id) + '" data-kind="' + escapeHtml(a.kind) + '">' +
                  '<td class="col-check"><input type="checkbox" class="artifact-select" data-artifact-id="' + escapeHtml(a.id) + '"></td>' +
                  '<td class="col-icon">' + icon + "</td>" +
                  '<td class="col-name mono">' + escapeHtml(a.name || "") + "</td>" +
                  '<td class="col-desc">' + escapeHtml(a.description || "") + "</td>" +
                  '<td class="col-size mono">' + formatSize(a.size) + "</td>" +
                  '<td class="col-tool fs-11">' + escapeHtml(a.source_tool || "") + "</td>" +
                  '<td class="col-time mono fs-11">' + escapeHtml((a.created_at || "").slice(0, 19)) + "</td>" +
                  '<td class="col-time mono fs-11">' + escapeHtml((a.modified_at || "").slice(0, 19)) + "</td>" +
                  '<td class="col-sha mono fs-11" title="' + escapeHtml(a.sha256 || "") + '" data-action="copy-sha" data-sha="' + escapeHtml(a.sha256 || "") + '">' + escapeHtml(a.short_sha || "") + "</td>" +
                  '<td class="col-tags">' + tags + "</td>" +
                  '<td class="col-actions">' +
                    '<button class="btn btn-sm" data-action="expand" data-artifact-id="' + escapeHtml(a.id) + '" type="button">▼</button>' +
                    '<button class="btn btn-sm" data-action="download" data-artifact-id="' + escapeHtml(a.id) + '" type="button">⬇</button>' +
                    '<button class="btn btn-sm btn-danger" data-action="delete" data-artifact-id="' + escapeHtml(a.id) + '" type="button">×</button>' +
                  "</td>" +
                "</tr>" +
                '<tr class="artifact-detail hidden" data-detail-for="' + escapeHtml(a.id) + '">' +
                  '<td colspan="11"><div class="artifact-detail-body" data-artifact-id="' + escapeHtml(a.id) + '"></div></td>' +
                "</tr>"
            );
        }).join("");
        tbody.innerHTML = html;
        if (selectAll) selectAll.checked = false;
        updateBulkButtons();
    }

    function updateFacets(data) {
        var f = data.facets || {};
        populate(toolSelect, f.tools || []);
        populate(tagSelect, f.tags || []);
    }

    function populate(select, items) {
        if (!select) return;
        var current = select.value;
        var html = '<option value="">All</option>';
        items.forEach(function (it) {
            var name = it.name || "";
            html += '<option value="' + escapeHtml(name) + '"' + (name === current ? " selected" : "") + ">" + escapeHtml(name) + " (" + (it.count || 0) + ")</option>";
        });
        select.innerHTML = html;
    }

    function formatSize(bytes) {
        if (!bytes) return "0";
        var b = Number(bytes);
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
        if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + " MB";
        return (b / (1024 * 1024 * 1024)).toFixed(1) + " GB";
    }

    // -----------------------------------------------------------------
    //  Action dispatch (delegated)
    // -----------------------------------------------------------------
    tbody.addEventListener("click", function (e) {
        var btn = e.target.closest("[data-action]");
        if (!btn) return;
        var action = btn.getAttribute("data-action");
        var aid = btn.getAttribute("data-artifact-id");
        if (action === "expand") {
            e.preventDefault();
            return toggleDetail(aid);
        }
        if (action === "download") {
            e.preventDefault();
            window.location.href = "/dashboard/api/artifacts/download?id=" + encodeURIComponent(aid);
            return;
        }
        if (action === "delete") {
            e.preventDefault();
            return deleteArtifact(aid);
        }
        if (action === "copy-sha") {
            e.preventDefault();
            var sha = btn.getAttribute("data-sha");
            if (sha && navigator.clipboard) {
                navigator.clipboard.writeText(sha).then(function () {
                    showToast("SHA256 copied", "success");
                });
            }
            return;
        }
    });

    function toggleDetail(aid) {
        var row = tbody.querySelector('tr.artifact-detail[data-detail-for="' + aid + '"]');
        if (!row) return;
        if (!row.classList.contains("hidden")) {
            row.classList.add("hidden");
            return;
        }
        row.classList.remove("hidden");
        var body = row.querySelector(".artifact-detail-body");
        body.textContent = "Loading...";
        fetchJSON("/dashboard/api/artifacts/detail?id=" + encodeURIComponent(aid)).then(function (a) {
            if (a.error) throw new Error(a.error);
            body.innerHTML = renderDetail(a);
        }).catch(function (e) {
            body.innerHTML = '<div class="dim">Failed to load: ' + escapeHtml(e.message) + "</div>";
        });
    }

    function renderDetail(a) {
        var members = "";
        if (a.kind === "directory" && a.members) {
            members = '<div class="detail-section"><strong>Members (' + (a.member_count || a.members.length) + ')</strong><ul class="member-list">';
            a.members.slice(0, 200).forEach(function (m) {
                members += "<li><span class=\"mono fs-11\">" + escapeHtml(m.relative || "") + "</span> <span class=\"dim\">(" + formatSize(m.size) + ")</span></li>";
            });
            members += "</ul></div>";
        }
        var notes = a.notes
            ? '<div class="detail-section"><strong>Notes</strong><pre class="mono fs-11">' + escapeHtml(a.notes) + "</pre></div>"
            : "";
        return (
            '<div class="artifact-detail-content">' +
              '<div class="detail-section"><strong>Path:</strong> <span class="mono fs-11">' + escapeHtml(a.path || "") + "</span></div>" +
              '<div class="detail-section"><strong>Original path:</strong> <span class="mono fs-11">' + escapeHtml(a.original_path || "") + "</span></div>" +
              '<div class="detail-section"><strong>SHA256:</strong> <span class="mono fs-11">' + escapeHtml(a.sha256 || "") + "</span></div>" +
              '<div class="detail-section"><strong>MD5:</strong> <span class="mono fs-11">' + escapeHtml(a.md5 || "") + "</span></div>" +
              '<div class="detail-section"><strong>Type:</strong> ' + escapeHtml(a.detected_type || "") + "</div>" +
              '<div class="detail-section">' +
                '<label class="dim">Description:</label> ' +
                '<input type="text" class="input-search detail-description" data-artifact-id="' + escapeHtml(a.id) + '" value="' + escapeHtml(a.description || "") + '">' +
              "</div>" +
              '<div class="detail-section">' +
                '<label class="dim">Tags (comma-separated):</label> ' +
                '<input type="text" class="input-search detail-tags" data-artifact-id="' + escapeHtml(a.id) + '" value="' + escapeHtml((a.tags || []).join(", ")) + '">' +
              "</div>" +
              '<div class="detail-section">' +
                '<label class="dim">Notes:</label> ' +
                '<textarea class="input-search detail-notes" data-artifact-id="' + escapeHtml(a.id) + '" rows="3">' + escapeHtml(a.notes || "") + "</textarea>" +
              "</div>" +
              '<button class="btn btn-sm btn-primary detail-save" data-artifact-id="' + escapeHtml(a.id) + '" type="button">SAVE</button>' +
              members + notes +
            "</div>"
        );
    }

    tbody.addEventListener("click", function (e) {
        var saveBtn = e.target.closest(".detail-save");
        if (!saveBtn) return;
        var aid = saveBtn.getAttribute("data-artifact-id");
        var detailRow = tbody.querySelector('tr.artifact-detail[data-detail-for="' + aid + '"]');
        if (!detailRow) return;
        var desc = detailRow.querySelector(".detail-description");
        var tags = detailRow.querySelector(".detail-tags");
        var notesEl = detailRow.querySelector(".detail-notes");
        var tagList = (tags && tags.value || "").split(",").map(function (t) { return t.trim(); }).filter(Boolean);
        fetchJSON("/dashboard/api/artifacts/update", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken(),
            },
            body: JSON.stringify({
                id: aid,
                description: desc ? desc.value : "",
                tags: tagList,
                replace_tags: true,
                notes: notesEl ? notesEl.value : "",
            }),
        }).then(function (resp) {
            if (resp.error) throw new Error(resp.error);
            showToast("Saved", "success");
            reload();
        }).catch(function (e) {
            showToast("Save failed: " + e.message, "error");
        });
    });

    function deleteArtifact(aid) {
        if (!window.confirm("Delete artifact? (the file on disk is left in place)")) return;
        fetchJSON("/dashboard/api/artifacts/delete", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken(),
            },
            body: JSON.stringify({ id: aid }),
        }).then(function (resp) {
            if (resp.error) throw new Error(resp.error);
            showToast("Deleted", "success");
            reload();
        }).catch(function (e) {
            showToast("Delete failed: " + e.message, "error");
        });
    }

    // -----------------------------------------------------------------
    //  Bulk select
    // -----------------------------------------------------------------
    function selectedIds() {
        return Array.from(tbody.querySelectorAll(".artifact-select:checked"))
            .map(function (cb) { return cb.getAttribute("data-artifact-id"); });
    }
    function updateBulkButtons() {
        var n = selectedIds().length;
        if (bulkTagBtn) bulkTagBtn.disabled = n === 0;
        if (bulkDeleteBtn) bulkDeleteBtn.disabled = n === 0;
    }
    tbody.addEventListener("change", function (e) {
        if (e.target.classList.contains("artifact-select")) updateBulkButtons();
    });
    if (selectAll) {
        selectAll.addEventListener("change", function () {
            tbody.querySelectorAll(".artifact-select").forEach(function (cb) {
                cb.checked = selectAll.checked;
            });
            updateBulkButtons();
        });
    }
    if (bulkDeleteBtn) {
        bulkDeleteBtn.addEventListener("click", function () {
            var ids = selectedIds();
            if (!ids.length) return;
            if (!window.confirm("Delete " + ids.length + " artifact(s)?")) return;
            fetchJSON("/dashboard/api/artifacts/bulk", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken(),
                },
                body: JSON.stringify({ op: "delete", ids: ids }),
            }).then(function (resp) {
                if (resp.error) throw new Error(resp.error);
                showToast("Deleted " + (resp.deleted_count || 0) + " artifact(s)", "success");
                reload();
            }).catch(function (e) {
                showToast("Bulk delete failed: " + e.message, "error");
            });
        });
    }
    if (bulkTagBtn) {
        bulkTagBtn.addEventListener("click", function () {
            var ids = selectedIds();
            if (!ids.length) return;
            var input = window.prompt("Tags to apply (comma-separated):", "");
            if (input === null) return;
            var tags = input.split(",").map(function (t) { return t.trim(); }).filter(Boolean);
            if (!tags.length) return;
            fetchJSON("/dashboard/api/artifacts/bulk", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken(),
                },
                body: JSON.stringify({ op: "tag", ids: ids, tags: tags }),
            }).then(function (resp) {
                if (resp.error) throw new Error(resp.error);
                showToast("Updated " + (resp.updated_count || 0) + " artifact(s)", "success");
                reload();
            }).catch(function (e) {
                showToast("Bulk tag failed: " + e.message, "error");
            });
        });
    }

    // -----------------------------------------------------------------
    //  Filter / sort change handlers
    // -----------------------------------------------------------------
    function debouncedReload() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(reload, 200);
    }
    if (filterInput) filterInput.addEventListener("input", debouncedReload);
    if (kindSelect) kindSelect.addEventListener("change", reload);
    if (toolSelect) toolSelect.addEventListener("change", reload);
    if (tagSelect) tagSelect.addEventListener("change", reload);
    if (sortSelect) sortSelect.addEventListener("change", reload);

    // Auto-refresh every 10s so background-tool-generated artifacts appear
    // without manual reload.
    setInterval(reload, 10000);

    if (typeof window.showToast !== "function") {
        window.showToast = function (msg) { console.log("[arkana]", msg); };
    }
})();

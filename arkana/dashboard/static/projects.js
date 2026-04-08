/* Arkana Dashboard — Projects page interactions
 *
 * CSP-safe: no inline scripts, all handlers attached via event delegation
 * on data-action attributes. Uses the global fetchJSON, getCsrfToken,
 * escapeHtml, and showToast helpers from dashboard.js.
 */
(function () {
    "use strict";

    var grid = document.getElementById("projects-grid");
    if (!grid) return;

    var filterInput = document.getElementById("projects-filter");
    var tagSelect = document.getElementById("projects-tag-filter");
    var sortSelect = document.getElementById("projects-sort");
    var newBtn = document.getElementById("btn-new-project");

    var debounceTimer = null;

    // -----------------------------------------------------------------
    //  Data load + render
    // -----------------------------------------------------------------
    function reloadGrid() {
        var params = new URLSearchParams();
        if (filterInput && filterInput.value) params.set("filter", filterInput.value);
        if (tagSelect && tagSelect.value) params.set("tag", tagSelect.value);
        if (sortSelect && sortSelect.value) params.set("sort_by", sortSelect.value);
        var url = "/dashboard/api/projects" + (params.toString() ? "?" + params : "");

        fetchJSON(url).then(function (data) {
            renderGrid(data);
            updateTagFilter(data);
        }).catch(function (e) {
            showToast("Failed to load projects: " + e.message, "error");
        });
    }

    function _buildProjectCardHtml(p, activeId) {
        var tags = (p.tags || []).map(function (t) {
            return '<span class="badge badge-tag">' + escapeHtml(t) + "</span>";
        }).join("");
        var lastOpened = p.last_opened ? formatRelative(p.last_opened) : "—";
        var primary = p.primary_filename || "(none)";
        var modeBadge = p.primary_mode
            ? '<span class="badge badge-dim">' + escapeHtml(String(p.primary_mode).toUpperCase()) + "</span>"
            : "";
        var activeBadge = (p.id === activeId)
            ? '<span class="badge badge-success">ACTIVE</span>'
            : "";
        var cardClass = "project-card" + (p.id === activeId ? " active" : "");
        var lastTabAttr = p.last_tab ? ' data-last-tab="' + escapeHtml(p.last_tab) + '"' : "";
        return (
            '<div class="' + cardClass + '" data-project-id="' + escapeHtml(p.id) + '" data-project-name="' + escapeHtml(p.name) + '"' + lastTabAttr + '>' +
              '<div class="project-card-header">' +
                '<span class="project-name" data-action="rename" data-project-id="' + escapeHtml(p.id) + '">' + escapeHtml(p.name) + "</span>" +
                activeBadge +
              "</div>" +
              '<div class="project-card-body">' +
                '<div class="project-row"><span class="dim">Primary:</span> <span class="mono">' + escapeHtml(primary) + "</span> " + modeBadge + "</div>" +
                '<div class="project-row"><span class="dim">Members:</span> ' + p.member_count + "</div>" +
                '<div class="project-row"><span class="dim">Last opened:</span> <span class="mono fs-11">' + escapeHtml(lastOpened) + "</span></div>" +
                (tags ? '<div class="project-row">' + tags + "</div>" : "") +
              "</div>" +
              '<div class="project-card-actions">' +
                '<button class="btn btn-sm btn-primary" data-action="open" data-project-id="' + escapeHtml(p.id) + '" type="button">OPEN</button>' +
                '<button class="btn btn-sm" data-action="expand" data-project-id="' + escapeHtml(p.id) + '" type="button">FILES ▼</button>' +
                '<button class="btn btn-sm" data-action="rename" data-project-id="' + escapeHtml(p.id) + '" type="button">RENAME</button>' +
                '<button class="btn btn-sm" data-action="tag" data-project-id="' + escapeHtml(p.id) + '" type="button">TAGS</button>' +
                '<button class="btn btn-sm btn-danger" data-action="delete" data-project-id="' + escapeHtml(p.id) + '" type="button">DELETE</button>' +
              "</div>" +
              '<div class="project-card-detail hidden" data-detail-for="' + escapeHtml(p.id) + '">' +
                '<div class="project-detail-loading dim fs-11">Loading members...</div>' +
              "</div>" +
            "</div>"
        );
    }

    function renderGrid(data) {
        var projects = data.projects || [];
        var activeId = data.active_project_id || "";

        // Pin the active project to a dedicated full-width banner above the
        // grid so the user immediately sees which project they're working
        // in. Filter it out of the regular grid so it doesn't appear twice.
        var activeBannerEl = document.getElementById("active-project-banner");
        var activePanelEl = document.getElementById("active-project-panel");
        if (activeBannerEl && activePanelEl) {
            var activeProject = null;
            if (activeId) {
                for (var ai = 0; ai < projects.length; ai++) {
                    if (projects[ai].id === activeId) {
                        activeProject = projects[ai];
                        break;
                    }
                }
            }
            if (activeProject) {
                activeBannerEl.innerHTML = _buildProjectCardHtml(activeProject, activeId);
                activePanelEl.classList.remove("hidden");
            } else {
                activeBannerEl.innerHTML = "";
                activePanelEl.classList.add("hidden");
            }
        }
        var others = activeId ? projects.filter(function (p) { return p.id !== activeId; }) : projects;

        if (!others.length && !activeId) {
            grid.innerHTML = '<div class="empty-msg">No projects yet. Open a binary and add a note to get started.</div>';
            return;
        }
        if (!others.length) {
            grid.innerHTML = '<div class="empty-msg dim">No other projects.</div>';
            return;
        }
        var html = others.map(function (p) { return _buildProjectCardHtml(p, activeId); }).join("");
        grid.innerHTML = html;
    }

    function updateTagFilter(data) {
        if (!tagSelect) return;
        var seen = {};
        (data.projects || []).forEach(function (p) {
            (p.tags || []).forEach(function (t) { seen[t] = true; });
        });
        var current = tagSelect.value;
        var keep = '<option value="">All tags</option>';
        Object.keys(seen).sort().forEach(function (t) {
            keep += '<option value="' + escapeHtml(t) + '"' + (t === current ? " selected" : "") + ">" + escapeHtml(t) + "</option>";
        });
        tagSelect.innerHTML = keep;
    }

    // formatRelative() lives in dashboard.js as a top-level helper so any
    // page that loads dashboard.js (every page) can reuse it. We rely on
    // it via the global scope.

    // Format any [data-epoch] elements rendered server-side. Called on
    // initial load (server-rendered cards have raw epoch in their text)
    // and after any reloadGrid() (client renders pre-formatted strings).
    function formatEpochSpans(root) {
        var nodes = (root || document).querySelectorAll("[data-epoch]");
        for (var i = 0; i < nodes.length; i++) {
            var ep = nodes[i].getAttribute("data-epoch");
            if (ep) nodes[i].textContent = formatRelative(ep);
        }
    }

    // -----------------------------------------------------------------
    //  Action dispatch (delegated)
    // -----------------------------------------------------------------
    grid.addEventListener("click", function (e) {
        var btn = e.target.closest("[data-action]");
        if (!btn) return;
        var action = btn.getAttribute("data-action");
        // Member-open buttons carry their own data-sha — route them first.
        if (action === "open-member") {
            e.preventDefault();
            var mpid = btn.getAttribute("data-project-id");
            var msha = btn.getAttribute("data-sha");
            if (mpid && msha) openProject(mpid, msha);
            return;
        }
        var pid = btn.getAttribute("data-project-id");
        if (!pid) return;
        e.preventDefault();
        if (action === "open") return openProject(pid);
        if (action === "expand") return toggleDetail(pid, btn);
        if (action === "rename") return renameProject(pid, btn);
        if (action === "tag") return tagProject(pid);
        if (action === "delete") return deleteProject(pid, btn);
    });

    function toggleDetail(pid, btn) {
        var card = grid.querySelector('.project-card[data-project-id="' + pid + '"]');
        if (!card) return;
        var detail = card.querySelector('.project-card-detail[data-detail-for="' + pid + '"]');
        if (!detail) return;
        if (!detail.classList.contains("hidden")) {
            detail.classList.add("hidden");
            if (btn) btn.textContent = "FILES ▼";
            return;
        }
        detail.classList.remove("hidden");
        if (btn) btn.textContent = "FILES ▲";
        detail.innerHTML = '<div class="project-detail-loading dim fs-11">Loading members...</div>';
        fetchJSON("/dashboard/api/projects/detail?project_id=" + encodeURIComponent(pid)).then(function (data) {
            if (data.error) throw new Error(data.error);
            detail.innerHTML = renderMembers(pid, data);
        }).catch(function (e) {
            detail.innerHTML = '<div class="dim fs-11">Failed to load: ' + escapeHtml(e.message) + "</div>";
        });
    }

    function renderMembers(pid, p) {
        var members = p.members || [];
        if (!members.length) {
            return '<div class="dim fs-11">This project has no member binaries.</div>';
        }
        var rows = members.map(function (m) {
            var name = m.filename || "(unnamed)";
            var sha8 = (m.sha256 || "").slice(0, 12);
            var sizeKb = m.size ? (m.size / 1024).toFixed(1) + " KB" : "—";
            var mode = m.mode ? String(m.mode).toUpperCase() : "";
            var badges = "";
            if (m.is_primary) badges += '<span class="badge badge-success">PRIMARY</span> ';
            if (m.is_last_active) badges += '<span class="badge badge-dim">LAST ACTIVE</span> ';
            if (!m.present) badges += '<span class="badge badge-dim" title="Binary file not copied into the project yet">STUB</span> ';
            return (
                '<li class="project-member-row">' +
                  '<div class="member-head">' +
                    '<span class="mono">' + escapeHtml(name) + "</span> " +
                    (mode ? '<span class="badge badge-dim">' + escapeHtml(mode) + "</span> " : "") +
                    badges +
                  "</div>" +
                  '<div class="member-meta dim fs-11">' +
                    '<span class="mono">' + escapeHtml(sha8) + "</span> · " +
                    '<span>' + sizeKb + "</span>" +
                  "</div>" +
                  '<div class="member-actions">' +
                    '<button class="btn btn-sm btn-primary" data-action="open-member" data-project-id="' + escapeHtml(pid) + '" data-sha="' + escapeHtml(m.sha256 || "") + '" type="button">OPEN</button>' +
                  "</div>" +
                "</li>"
            );
        }).join("");
        return (
            '<div class="project-members">' +
              '<div class="fs-11 dim">' + members.length + ' member binary(s)</div>' +
              '<ul class="project-member-list">' + rows + "</ul>" +
            "</div>"
        );
    }

    var OPEN_REDIRECT_DELAY_MS = 800;

    function applyOptimisticActive(pid) {
        // Move the .active marker (and OPENING badge) to the clicked card
        // immediately so the user gets visual feedback. The real source of
        // truth re-applies on the next reloadGrid() — backend SSE drives the
        // arkana-active-project-changed event we listen for below.
        var allCards = grid.querySelectorAll(".project-card");
        for (var i = 0; i < allCards.length; i++) {
            var c = allCards[i];
            var cpid = c.getAttribute("data-project-id");
            // Strip any prior OPENING/ACTIVE badge from sibling cards
            var existingBadge = c.querySelector(".badge-opening, .badge-success");
            if (cpid === pid) {
                c.classList.add("active");
                if (existingBadge) existingBadge.remove();
                var header = c.querySelector(".project-card-header");
                if (header) {
                    var b = document.createElement("span");
                    b.className = "badge badge-opening";
                    b.textContent = "OPENING\u2026";
                    header.appendChild(b);
                }
                // Disable buttons on the clicked card to prevent double-clicks.
                var btns = c.querySelectorAll(".project-card-actions button");
                for (var j = 0; j < btns.length; j++) {
                    btns[j].disabled = true;
                }
            } else {
                c.classList.remove("active");
                if (existingBadge && existingBadge.classList.contains("badge-success")) {
                    existingBadge.remove();
                }
            }
        }
    }

    function openProject(pid, sha256) {
        // Read the project's saved last_tab from the data attribute on the
        // card so we can land the user back where they left off.
        var lastTab = "";
        var card = grid.querySelector('.project-card[data-project-id="' + pid + '"]');
        if (card) lastTab = card.getAttribute("data-last-tab") || "";

        // Optimistic UI: shift the active marker to the clicked card *now*
        // so the user doesn't see the old project highlighted while the
        // backend's open_file_tool churns through triage/CFG.
        applyOptimisticActive(pid);
        // Tell the nav handler in dashboard.js to render "(opening…)"
        // instead of the stale filename until the new binary loads.
        window._arkana = window._arkana || {};
        window._arkana.opening = true;

        var body = { project_id: pid };
        if (sha256) body.binary_sha256 = sha256;
        fetchJSON("/dashboard/api/projects/open", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken(),
            },
            body: JSON.stringify(body),
        }).then(function (resp) {
            if (resp.error) throw new Error(resp.error);
            showToast("Project opened — loading binary...", "success");
            // Resolve target URL: dashboard/<last_tab>, falling back to overview.
            var target = "/dashboard/";
            if (lastTab && lastTab !== "overview" && lastTab !== "projects") {
                target = "/dashboard/" + lastTab;
            }
            // Short delay so overlay restoration completes server-side first.
            setTimeout(function () { window.location.href = target; }, OPEN_REDIRECT_DELAY_MS);
        }).catch(function (e) {
            // Roll back optimistic state so the user can retry without
            // a stale OPENING badge stuck on the failed card.
            window._arkana = window._arkana || {};
            window._arkana.opening = false;
            reloadGrid();
            showToast("Open failed: " + e.message, "error");
        });
    }

    // When the SSE-fed dashboard.js notices the active project actually
    // changed on the backend, refresh our card grid so badges and the
    // "▶ ACTIVE" indicator land on the correct card. Also clear the
    // _arkana.opening flag so the nav stops showing "(opening…)".
    document.addEventListener("arkana-active-project-changed", function () {
        window._arkana = window._arkana || {};
        window._arkana.opening = false;
        // The redirect target may already be loading; harmless to reload
        // grid in either case.
        reloadGrid();
    });

    function renameProject(pid, btn) {
        var card = btn.closest(".project-card");
        var current = card ? card.getAttribute("data-project-name") : "";
        var newName = window.prompt("New project name:", current || "");
        if (!newName || newName === current) return;
        fetchJSON("/dashboard/api/projects/rename", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken(),
            },
            body: JSON.stringify({ project_id: pid, new_name: newName }),
        }).then(function (resp) {
            if (resp.error) throw new Error(resp.error);
            showToast("Renamed", "success");
            reloadGrid();
        }).catch(function (e) {
            showToast("Rename failed: " + e.message, "error");
        });
    }

    function tagProject(pid) {
        var card = grid.querySelector('.project-card[data-project-id="' + pid + '"]');
        var existing = card ? Array.from(card.querySelectorAll(".badge-tag")).map(function (el) { return el.textContent; }) : [];
        var input = window.prompt(
            "Tags (comma-separated):",
            existing.join(", ")
        );
        if (input === null) return;
        var tags = input.split(",").map(function (t) { return t.trim(); }).filter(Boolean);
        fetchJSON("/dashboard/api/projects/tag", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken(),
            },
            body: JSON.stringify({ project_id: pid, add: tags, replace: true }),
        }).then(function (resp) {
            if (resp.error) throw new Error(resp.error);
            showToast("Tags updated", "success");
            reloadGrid();
        }).catch(function (e) {
            showToast("Tag update failed: " + e.message, "error");
        });
    }

    function deleteProject(pid, btn) {
        var card = btn.closest(".project-card");
        var name = card ? card.getAttribute("data-project-name") : pid;
        if (!window.confirm("Delete project '" + name + "'? This cannot be undone.")) return;
        fetchJSON("/dashboard/api/projects/delete", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken(),
            },
            body: JSON.stringify({ project_id: pid, confirm: true }),
        }).then(function (resp) {
            if (resp.error) throw new Error(resp.error);
            showToast("Deleted", "success");
            reloadGrid();
        }).catch(function (e) {
            showToast("Delete failed: " + e.message, "error");
        });
    }

    // -----------------------------------------------------------------
    //  New-project modal
    // -----------------------------------------------------------------
    var modal = document.getElementById("modal-new-project");
    if (newBtn && modal) {
        newBtn.addEventListener("click", function () {
            modal.classList.remove("hidden");
            var nameInput = document.getElementById("new-project-name");
            if (nameInput) nameInput.focus();
        });
        modal.addEventListener("click", function (e) {
            var btn = e.target.closest("[data-action='close-modal']");
            if (btn) {
                modal.classList.add("hidden");
                clearNewProjectError();
            }
        });
        var confirmBtn = document.getElementById("btn-create-project-confirm");
        if (confirmBtn) {
            confirmBtn.addEventListener("click", function () {
                var nameInput = document.getElementById("new-project-name");
                var tagsInput = document.getElementById("new-project-tags");
                var name = (nameInput && nameInput.value || "").trim();
                if (!name) {
                    showNewProjectError("Name is required");
                    return;
                }
                var tags = (tagsInput && tagsInput.value || "")
                    .split(",")
                    .map(function (t) { return t.trim(); })
                    .filter(Boolean);
                fetchJSON("/dashboard/api/projects", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": getCsrfToken(),
                    },
                    body: JSON.stringify({ name: name, tags: tags }),
                }).then(function (resp) {
                    if (resp.error) throw new Error(resp.error);
                    modal.classList.add("hidden");
                    if (nameInput) nameInput.value = "";
                    if (tagsInput) tagsInput.value = "";
                    clearNewProjectError();
                    showToast("Project created", "success");
                    reloadGrid();
                }).catch(function (e) {
                    showNewProjectError(e.message);
                });
            });
        }
    }

    function showNewProjectError(msg) {
        var el = document.getElementById("new-project-error");
        if (el) {
            el.textContent = msg;
            el.classList.remove("hidden");
        }
    }
    function clearNewProjectError() {
        var el = document.getElementById("new-project-error");
        if (el) {
            el.textContent = "";
            el.classList.add("hidden");
        }
    }

    // -----------------------------------------------------------------
    //  Filter / sort change handlers
    // -----------------------------------------------------------------
    function debouncedReload() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(reloadGrid, 200);
    }
    if (filterInput) filterInput.addEventListener("input", debouncedReload);
    if (tagSelect) tagSelect.addEventListener("change", reloadGrid);
    if (sortSelect) sortSelect.addEventListener("change", reloadGrid);

    // -----------------------------------------------------------------
    //  Importable archives panel
    // -----------------------------------------------------------------
    var archivesList = document.getElementById("importable-archives-list");
    var archivesCount = document.getElementById("importable-archives-count");
    var rescanBtn = document.getElementById("btn-rescan-archives");

    function loadArchives() {
        if (!archivesList) return;
        fetchJSON("/dashboard/api/projects/importable-archives").then(function (data) {
            renderArchives(data);
        }).catch(function (e) {
            archivesList.innerHTML = '<div class="empty-msg dim">Failed to scan: ' + escapeHtml(e.message) + '</div>';
        });
    }

    function renderArchives(data) {
        var archives = (data && data.archives) || [];
        if (archivesCount) {
            archivesCount.textContent = archives.length ? "(" + archives.length + " found)" : "";
        }
        if (!archives.length) {
            archivesList.innerHTML = '<div class="empty-msg dim">No archives found in output directories.</div>';
            return;
        }
        var html = '<table class="data-table data-table-sm"><thead><tr>' +
            '<th>Name</th><th>Size</th><th>Modified</th><th>Status</th><th>Action</th>' +
            '</tr></thead><tbody>';
        archives.forEach(function (a) {
            var sizeKb = (a.size / 1024).toFixed(1) + " KB";
            var dt = new Date(Number(a.mtime) * 1000).toLocaleString();
            var statusBadge = a.likely_imported
                ? '<span class="badge badge-dim">likely imported</span>'
                : '<span class="badge badge-tag">new</span>';
            html += '<tr>' +
                '<td class="mono fs-11">' + escapeHtml(a.name) + '</td>' +
                '<td class="mono fs-11">' + sizeKb + '</td>' +
                '<td class="fs-11">' + escapeHtml(dt) + '</td>' +
                '<td>' + statusBadge + '</td>' +
                '<td><button class="btn btn-sm btn-primary" data-action="import-archive" data-path="' + escapeHtml(a.path) + '" type="button">IMPORT</button></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
        archivesList.innerHTML = html;
    }

    if (archivesList) {
        archivesList.addEventListener("click", function (e) {
            var btn = e.target.closest("[data-action='import-archive']");
            if (!btn) return;
            e.preventDefault();
            var path = btn.getAttribute("data-path");
            if (!path) return;
            btn.disabled = true;
            btn.textContent = "...";
            fetchJSON("/dashboard/api/projects/import-archive", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken(),
                },
                body: JSON.stringify({ path: path }),
            }).then(function (resp) {
                if (resp.error) throw new Error(resp.error);
                if (resp.status === "already_imported") {
                    showToast("Already imported as " + resp.project_name, "info");
                } else {
                    showToast("Imported as " + resp.project_name, "success");
                }
                reloadGrid();
                loadArchives();
            }).catch(function (err) {
                showToast("Import failed: " + err.message, "error");
                btn.disabled = false;
                btn.textContent = "IMPORT";
            });
        });
    }
    if (rescanBtn) rescanBtn.addEventListener("click", loadArchives);
    // Load on page load
    loadArchives();
    // Format any server-rendered [data-epoch] spans on the initial page.
    formatEpochSpans(document);

    // Defensive global toast helper in case dashboard.js hasn't installed
    // one yet on this page.
    if (typeof window.showToast !== "function") {
        window.showToast = function (msg) { console.log("[arkana]", msg); };
    }
})();

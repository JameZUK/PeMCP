/* Arkana Dashboard — Capabilities (CAPA) */
(function () {
    "use strict";

    var searchInput = document.getElementById("capa-search");
    var groupSelect = document.getElementById("capa-group");
    var tbody = document.getElementById("capa-tbody");
    var container = document.getElementById("capa-rules-container");
    var _debounce;

    function reloadCapabilities() {
        fetchJSON("/dashboard/api/capabilities")
            .then(function (data) {
                renderRules(data);
                var ruleCount = document.getElementById("capa-rule-count");
                var attackCount = document.getElementById("capa-attack-count");
                if (ruleCount) ruleCount.textContent = (data.stats ? data.stats.total_rules : 0) + " rules";
                if (attackCount) attackCount.textContent = (data.stats ? data.stats.total_attack_tactics : 0) + " ATT&CK tactics";
            })
            .catch(function () {
                if (container) container.innerHTML = "<div class=\"empty-msg\">Failed to load capabilities data.</div>";
            });
    }

    function renderRules(data) {
        if (!data.rules || data.rules.length === 0) {
            if (container) container.innerHTML = "<div class=\"empty-msg\">No capa results available.</div>";
            return;
        }

        var search = searchInput ? searchInput.value.toLowerCase() : "";
        var group = groupSelect ? groupSelect.value : "none";
        var filtered = data.rules;

        if (search) {
            filtered = filtered.filter(function (r) {
                return (r.name || "").toLowerCase().indexOf(search) !== -1 ||
                       (r.namespace || "").toLowerCase().indexOf(search) !== -1 ||
                       (r.description || "").toLowerCase().indexOf(search) !== -1;
            });
        }

        if (group === "namespace") {
            renderGrouped(filtered, "namespace");
        } else if (group === "attack") {
            renderAttackGrouped(data);
        } else {
            renderFlat(filtered);
        }
    }

    function renderFlat(rules) {
        var html = "<div class=\"table-wrap\"><table class=\"data-table\" id=\"capa-table\">";
        html += "<thead><tr><th>RULE</th><th>NAMESPACE</th><th>SCOPE</th><th>MATCHES</th><th>FUNCTIONS</th></tr></thead><tbody>";
        rules.forEach(function (rule) {
            html += "<tr>";
            html += "<td>" + escapeHtml(rule.name || "") + "</td>";
            html += "<td class=\"dim\">" + escapeHtml(rule.namespace || "") + "</td>";
            html += "<td><span class=\"badge badge-dim\">" + escapeHtml(rule.scope || "file") + "</span></td>";
            html += "<td>" + (rule.addresses ? rule.addresses.length : 0) + "</td>";
            html += "<td>" + renderAddresses(rule.addresses || []) + "</td>";
            html += "</tr>";
            if (rule.description) {
                html += "<tr class=\"capa-desc-row\"><td colspan=\"5\" class=\"dim fs-10\">" + escapeHtml(rule.description) + "</td></tr>";
            }
        });
        html += "</tbody></table></div>";
        if (container) container.innerHTML = html;
    }

    function renderGrouped(rules, field) {
        var groups = {};
        rules.forEach(function (r) {
            var key = r[field] || "(ungrouped)";
            if (!groups[key]) groups[key] = [];
            groups[key].push(r);
        });

        var html = "";
        Object.keys(groups).sort().forEach(function (key) {
            html += "<div class=\"capa-group\">";
            html += "<div class=\"capa-group-header\">" + escapeHtml(key) + " <span class=\"badge badge-dim\">" + groups[key].length + "</span></div>";
            html += "<div class=\"table-wrap\"><table class=\"data-table data-table-sm\"><tbody>";
            groups[key].forEach(function (rule) {
                html += "<tr>";
                html += "<td>" + escapeHtml(rule.name || "") + "</td>";
                html += "<td><span class=\"badge badge-dim\">" + escapeHtml(rule.scope || "file") + "</span></td>";
                html += "<td>" + renderAddresses(rule.addresses || []) + "</td>";
                html += "</tr>";
            });
            html += "</tbody></table></div></div>";
        });
        if (container) container.innerHTML = html;
    }

    function renderAttackGrouped(data) {
        var mapping = data.attack_mapping || {};
        if (Object.keys(mapping).length === 0) {
            if (container) container.innerHTML = "<div class=\"empty-msg\">No ATT&CK mapping available.</div>";
            return;
        }

        var html = "";
        Object.keys(mapping).sort().forEach(function (tactic) {
            var items = mapping[tactic];
            html += "<div class=\"capa-group\">";
            html += "<div class=\"capa-group-header\">" + escapeHtml(tactic.toUpperCase()) + " <span class=\"badge badge-dim\">" + items.length + "</span></div>";
            html += "<div class=\"table-wrap\"><table class=\"data-table data-table-sm\"><tbody>";
            items.forEach(function (item) {
                html += "<tr>";
                html += "<td class=\"mono\">" + escapeHtml(item.id || "") + "</td>";
                html += "<td>" + escapeHtml(item.rule || "") + "</td>";
                html += "</tr>";
            });
            html += "</tbody></table></div></div>";
        });
        if (container) container.innerHTML = html;
    }

    function renderAddresses(addresses) {
        var html = "";
        addresses.forEach(function (addr) {
            if (addr.func_name) {
                html += "<a href=\"/dashboard/functions?highlight=" + encodeURIComponent(addr.func_addr || "") + "\" class=\"capa-func-link\">&#8594; " + escapeHtml(addr.func_name) + "</a> ";
            } else {
                html += "<span class=\"mono dim\">" + escapeHtml(addr.address || "") + "</span> ";
            }
        });
        return html;
    }

    if (searchInput) {
        searchInput.addEventListener("input", function () {
            clearTimeout(_debounce);
            _debounce = setTimeout(reloadCapabilities, 300);
        });
    }
    if (groupSelect) {
        groupSelect.addEventListener("change", reloadCapabilities);
    }
})();

/* Arkana Dashboard — Type Editor */
(function () {
    "use strict";

    var modal = document.getElementById("type-modal");
    var modalTitle = document.getElementById("modal-title");
    var modalName = document.getElementById("modal-name");
    var modalSize = document.getElementById("modal-size");
    var modalFields = document.getElementById("modal-fields");
    var modalValues = document.getElementById("modal-values");
    var modalFieldsContainer = document.getElementById("modal-fields-container");
    var modalValuesContainer = document.getElementById("modal-values-container");
    var modalError = document.getElementById("modal-error");
    var _editingKind = "struct";
    var _editingOrigName = null;

    function showModal(kind, name) {
        _editingKind = kind;
        _editingOrigName = name || null;
        modalTitle.textContent = (name ? "EDIT " : "NEW ") + kind.toUpperCase();
        modalName.value = name || "";
        modalSize.value = "0";
        modalFields.innerHTML = "";
        modalValues.innerHTML = "";
        modalError.classList.add("hidden");

        if (kind === "struct") {
            modalFieldsContainer.classList.remove("hidden");
            modalValuesContainer.classList.add("hidden");
        } else {
            modalFieldsContainer.classList.add("hidden");
            modalValuesContainer.classList.remove("hidden");
        }

        if (name) {
            // Load existing type
            fetch("/dashboard/api/types")
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    var list = kind === "struct" ? data.structs : data.enums;
                    var found = null;
                    (list || []).forEach(function (t) {
                        if (t.name === name) found = t;
                    });
                    if (found) {
                        modalSize.value = found.size || 0;
                        if (kind === "struct" && found.fields) {
                            found.fields.forEach(function (f) {
                                addFieldRow(f.name || "", f.type || "", f.offset || 0, f.size || 0);
                            });
                        } else if (kind === "enum" && found.values) {
                            Object.keys(found.values).forEach(function (k) {
                                addValueRow(k, found.values[k]);
                            });
                        }
                    }
                });
        }

        modal.classList.remove("hidden");
    }

    function hideModal() {
        modal.classList.add("hidden");
        _editingOrigName = null;
    }

    function addFieldRow(name, type, offset, size) {
        var row = document.createElement("div");
        row.className = "type-field-row filter-bar";
        row.innerHTML =
            "<input type=\"text\" placeholder=\"name\" class=\"field-name\" value=\"" + escapeHtml(name || "") + "\">" +
            "<input type=\"text\" placeholder=\"type\" class=\"field-type\" value=\"" + escapeHtml(type || "") + "\">" +
            "<input type=\"number\" placeholder=\"offset\" class=\"field-offset\" value=\"" + (offset || 0) + "\">" +
            "<input type=\"number\" placeholder=\"size\" class=\"field-size\" value=\"" + (size || 0) + "\">" +
            "<button class=\"btn-triage btn-flag field-remove\">X</button>";
        modalFields.appendChild(row);
    }

    function addValueRow(name, value) {
        var row = document.createElement("div");
        row.className = "type-field-row filter-bar";
        row.innerHTML =
            "<input type=\"text\" placeholder=\"name\" class=\"value-name\" value=\"" + escapeHtml(name || "") + "\">" +
            "<input type=\"number\" placeholder=\"value\" class=\"value-val\" value=\"" + (value || 0) + "\">" +
            "<button class=\"btn-triage btn-flag field-remove\">X</button>";
        modalValues.appendChild(row);
    }

    function saveType() {
        var name = modalName.value.trim();
        if (!name || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
            modalError.textContent = "Invalid name. Must match [a-zA-Z_][a-zA-Z0-9_]*.";
            modalError.classList.remove("hidden");
            return;
        }

        var size = parseInt(modalSize.value, 10) || 0;
        var url, body;

        if (_editingKind === "struct") {
            var fields = [];
            var rows = modalFields.querySelectorAll(".type-field-row");
            for (var i = 0; i < rows.length; i++) {
                var fn = rows[i].querySelector(".field-name").value.trim();
                var ft = rows[i].querySelector(".field-type").value.trim();
                var fo = parseInt(rows[i].querySelector(".field-offset").value, 10) || 0;
                var fs = parseInt(rows[i].querySelector(".field-size").value, 10) || 0;
                if (fn) {
                    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(fn)) {
                        modalError.textContent = "Invalid field name: " + fn;
                        modalError.classList.remove("hidden");
                        return;
                    }
                    fields.push({name: fn, type: ft, offset: fo, size: fs});
                }
            }
            url = "/dashboard/api/types/struct";
            body = {name: name, size: size, fields: fields};
        } else {
            var values = {};
            var vrows = modalValues.querySelectorAll(".type-field-row");
            for (var j = 0; j < vrows.length; j++) {
                var vn = vrows[j].querySelector(".value-name").value.trim();
                var vv = parseInt(vrows[j].querySelector(".value-val").value, 10) || 0;
                if (vn) values[vn] = vv;
            }
            url = "/dashboard/api/types/enum";
            body = {name: name, size: size, values: values};
        }

        // Delete old name if renamed
        var chain = Promise.resolve();
        if (_editingOrigName && _editingOrigName !== name) {
            chain = fetch("/dashboard/api/types/delete?name=" + encodeURIComponent(_editingOrigName), {
                method: "POST",
                headers: {"X-CSRF-Token": getCsrfToken()},
            });
        }

        chain.then(function () {
            return fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken(),
                },
                body: JSON.stringify(body),
            });
        }).then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                modalError.textContent = data.error;
                modalError.classList.remove("hidden");
            } else {
                hideModal();
                window.location.reload();
            }
        })
        .catch(function () {
            modalError.textContent = "Save failed.";
            modalError.classList.remove("hidden");
        });
    }

    function deleteType(name) {
        if (!confirm("Delete type '" + name + "'?")) return;
        fetch("/dashboard/api/types/delete?name=" + encodeURIComponent(name), {
            method: "POST",
            headers: {"X-CSRF-Token": getCsrfToken()},
        }).then(function (r) { return r.json(); })
        .then(function (data) {
            if (!data.error) window.location.reload();
            else showToast(data.error, "error");
        });
    }

    // Event delegation
    document.addEventListener("click", function (e) {
        if (e.target.id === "btn-new-struct") showModal("struct");
        if (e.target.id === "btn-new-enum") showModal("enum");
        if (e.target.id === "modal-save") saveType();
        if (e.target.id === "modal-cancel") hideModal();
        if (e.target.id === "modal-add-field") addFieldRow("", "", 0, 0);
        if (e.target.id === "modal-add-value") addValueRow("", 0);
        if (e.target.classList.contains("field-remove")) {
            e.target.parentElement.remove();
        }
        if (e.target.classList.contains("type-edit-btn")) {
            showModal(e.target.getAttribute("data-kind"), e.target.getAttribute("data-name"));
        }
        if (e.target.classList.contains("type-delete-btn")) {
            deleteType(e.target.getAttribute("data-name"));
        }
    });

    // Close modal on backdrop click
    if (modal) {
        modal.addEventListener("click", function (e) {
            if (e.target === modal) hideModal();
        });
    }
})();

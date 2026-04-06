/* Arkana Dashboard — Settings Page */
(function () {
    "use strict";

    // --- Theme switching ---
    var themeCards = document.getElementById("theme-cards");
    if (themeCards) {
        themeCards.addEventListener("click", function (e) {
            var card = e.target.closest("[data-theme-choice]");
            if (!card) return;
            var theme = card.getAttribute("data-theme-choice");
            _applyTheme(theme);
            _saveTheme(theme);
            // Update active state on cards
            var cards = themeCards.querySelectorAll(".theme-card");
            for (var i = 0; i < cards.length; i++) {
                cards[i].classList.toggle("active", cards[i] === card);
            }
        });
    }

    function _applyTheme(theme) {
        if (theme === "crt") {
            document.documentElement.removeAttribute("data-theme");
        } else {
            document.documentElement.setAttribute("data-theme", theme);
        }
        // Show/hide scanlines and vignette
        var scanlines = document.querySelector(".scanlines");
        var vignette = document.querySelector(".vignette");
        if (scanlines) scanlines.style.display = (theme === "crt") ? "" : "none";
        if (vignette) vignette.style.display = (theme === "crt") ? "" : "none";
    }

    function _saveTheme(theme) {
        var csrf = _getCsrf();
        var body = {};
        body["dashboard_theme"] = theme;
        fetch("/dashboard/api/settings", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf
            },
            body: JSON.stringify(body)
        }).then(function (r) {
            if (!r.ok) {
                _showStatus("Failed to save theme", true);
            }
        }).catch(function () {
            _showStatus("Network error saving theme", true);
        });
    }

    // --- Save all settings ---
    var btnSave = document.getElementById("btn-save");
    if (btnSave) {
        btnSave.addEventListener("click", function () {
            var settings = _collectSettings();
            var csrf = _getCsrf();
            btnSave.disabled = true;
            btnSave.textContent = "SAVING...";
            fetch("/dashboard/api/settings", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrf
                },
                body: JSON.stringify(settings)
            }).then(function (r) {
                return r.json();
            }).then(function (data) {
                if (data.errors && Object.keys(data.errors).length > 0) {
                    var msgs = [];
                    for (var k in data.errors) {
                        msgs.push(k + ": " + data.errors[k]);
                    }
                    _showStatus("Errors: " + msgs.join(", "), true);
                } else {
                    _showStatus("Settings saved", false);
                    if (data.restart_required) {
                        var notice = document.getElementById("restart-notice");
                        if (notice) notice.classList.add("visible");
                    }
                }
            }).catch(function () {
                _showStatus("Network error", true);
            }).finally(function () {
                btnSave.disabled = false;
                btnSave.textContent = "SAVE SETTINGS";
            });
        });
    }

    // --- Reset all ---
    var btnReset = document.getElementById("btn-reset-all");
    if (btnReset) {
        btnReset.addEventListener("click", function () {
            if (!confirm("Reset all settings to defaults? This cannot be undone.")) return;
            var csrf = _getCsrf();
            fetch("/dashboard/api/settings/reset", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrf
                },
                body: "{}"
            }).then(function (r) {
                if (r.ok) {
                    _showStatus("All settings reset to defaults", false);
                    // Reload to reflect new values
                    setTimeout(function () { location.reload(); }, 800);
                } else {
                    _showStatus("Failed to reset settings", true);
                }
            }).catch(function () {
                _showStatus("Network error", true);
            });
        });
    }

    // --- Helpers ---

    function _collectSettings() {
        var settings = {};
        var items = document.querySelectorAll(".setting-item");
        for (var i = 0; i < items.length; i++) {
            var key = items[i].getAttribute("data-key");
            var numInput = items[i].querySelector("input[type='number']");
            var chkInput = items[i].querySelector("input[type='checkbox']");
            if (numInput && !numInput.disabled) {
                settings[key] = numInput.value;
            } else if (chkInput && !chkInput.disabled) {
                settings[key] = chkInput.checked;
            }
        }
        return settings;
    }

    function _getCsrf() {
        var meta = document.querySelector("meta[name='csrf-token']");
        return meta ? meta.getAttribute("content") : "";
    }

    function _showStatus(msg, isError) {
        var el = document.getElementById("save-status");
        if (!el) return;
        el.textContent = msg;
        el.classList.toggle("error", !!isError);
        el.classList.add("visible");
        setTimeout(function () {
            el.classList.remove("visible");
        }, 4000);
    }
})();

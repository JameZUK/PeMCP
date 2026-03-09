/* Arkana Dashboard — Notes search */
(function () {
    "use strict";

    var searchInput = document.getElementById("notes-search");
    var notesList = document.getElementById("notes-list");
    var countBadge = document.getElementById("notes-count");

    if (!searchInput || !notesList) return;

    var debounceTimer = null;

    searchInput.addEventListener("input", function () {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(filterNotes, 150);
    });

    function filterNotes() {
        var query = searchInput.value.trim().toLowerCase();
        var cards = notesList.querySelectorAll(".note-card");
        var visible = 0;

        cards.forEach(function (card) {
            var text = card.getAttribute("data-note-text") || "";
            if (!query || text.indexOf(query) !== -1) {
                card.style.display = "";
                visible++;
            } else {
                card.style.display = "none";
            }
        });

        if (countBadge) {
            countBadge.textContent = String(visible);
        }
    }
})();

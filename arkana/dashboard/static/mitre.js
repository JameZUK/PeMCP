/* Arkana Dashboard — MITRE ATT&CK / Threat Intel */
(function () {
    "use strict";

    var matrixContainer = document.getElementById("mitre-matrix");

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

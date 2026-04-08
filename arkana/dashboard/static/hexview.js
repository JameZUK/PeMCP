/* Arkana Dashboard — Hex View (infinite scroll) */
(function () {
    "use strict";

    var offsetInput = document.getElementById("hex-offset");
    var goBtn = document.getElementById("hex-go");
    var tbody = document.getElementById("hex-tbody");
    var rangeSpan = document.getElementById("hex-range");
    var fileInfo = document.getElementById("hex-file-info");
    var scrollContainer = document.getElementById("hex-scroll-container");
    var loadingEl = document.getElementById("hex-loading");

    // Chunk size: 4096 bytes = 256 rows of 16 bytes
    var CHUNK_BYTES = 4096;
    // How many bytes to keep in the DOM at most (64KB = 4096 rows)
    var MAX_DOM_BYTES = 65536;
    var ROWS_PER_CHUNK = CHUNK_BYTES / 16;
    var MAX_DOM_ROWS = MAX_DOM_BYTES / 16;

    var _totalSize = 0;
    // Track what range of offsets is currently rendered
    var _renderedStart = 0;  // byte offset of first rendered row
    var _renderedEnd = 0;    // byte offset just past last rendered row
    var _loading = false;
    var _initialized = false;

    function parseOffset(val) {
        val = val.trim();
        if (val.indexOf("0x") === 0 || val.indexOf("0X") === 0) {
            return parseInt(val, 16);
        }
        return parseInt(val, 10);
    }

    function fmtAddr(offset) {
        return "0x" + offset.toString(16).toUpperCase().padStart(8, "0");
    }

    function updateRangeBadge() {
        if (_renderedStart === _renderedEnd) {
            rangeSpan.textContent = "";
            return;
        }
        rangeSpan.textContent = fmtAddr(_renderedStart) + " — " + fmtAddr(_renderedEnd);
    }

    /** Build HTML for rows from a fetched data response. */
    function buildRowsHtml(lines) {
        if (!Array.isArray(lines)) return "";
        var html = "";
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i];
            html += "<tr>" +
                "<td class=\"mono hex-offset-col\">" + escapeHtml(line.offset) + "</td>" +
                "<td class=\"mono hex-bytes-col\">" + escapeHtml(line.hex) + "</td>" +
                "<td class=\"mono hex-ascii-col\">" + escapeHtml(line.ascii) + "</td>" +
                "</tr>";
        }
        return html;
    }

    /** Fetch a chunk of hex data from the API. */
    function fetchChunk(offset, length, callback) {
        if (offset < 0) offset = 0;
        if (_totalSize > 0 && offset >= _totalSize) { callback(null); return; }
        fetchJSON("/dashboard/api/hex?offset=" + offset + "&length=" + length)
            .then(function (data) {
                if (data.error) { callback(null); return; }
                if (data.total_size) _totalSize = data.total_size;
                fileInfo.textContent = "File size: " + _totalSize.toLocaleString() + " bytes";
                callback(data);
            })
            .catch(function () { callback(null); });
    }

    /** Append rows at the bottom of the table (scroll down). */
    function appendChunk(data) {
        if (!data || !data.lines || data.lines.length === 0) return;
        var html = buildRowsHtml(data.lines);
        tbody.insertAdjacentHTML("beforeend", html);
        _renderedEnd = data.offset + (data.length || 0);

        // Trim top if DOM is too large
        while (tbody.children.length > MAX_DOM_ROWS) {
            tbody.removeChild(tbody.firstChild);
        }
        _renderedStart = _renderedEnd - (tbody.children.length * 16);
        if (_renderedStart < 0) _renderedStart = 0;
        updateRangeBadge();
    }

    /** Prepend rows at the top of the table (scroll up). */
    function prependChunk(data) {
        if (!data || !data.lines || data.lines.length === 0) return;
        // Save scroll position
        var oldScrollTop = scrollContainer.scrollTop;
        var oldScrollHeight = scrollContainer.scrollHeight;

        var html = buildRowsHtml(data.lines);
        tbody.insertAdjacentHTML("afterbegin", html);
        _renderedStart = data.offset;

        // Restore scroll position (shift by new content height)
        var newScrollHeight = scrollContainer.scrollHeight;
        scrollContainer.scrollTop = oldScrollTop + (newScrollHeight - oldScrollHeight);

        // Trim bottom if DOM is too large
        while (tbody.children.length > MAX_DOM_ROWS) {
            tbody.removeChild(tbody.lastChild);
        }
        _renderedEnd = _renderedStart + (tbody.children.length * 16);
        if (_totalSize > 0 && _renderedEnd > _totalSize) _renderedEnd = _totalSize;
        updateRangeBadge();
    }

    /** Initial load: clear and fill from a given offset. */
    function jumpTo(offset) {
        if (isNaN(offset) || offset < 0) offset = 0;
        // Align to 16-byte boundary
        offset = Math.floor(offset / 16) * 16;
        tbody.innerHTML = "";
        _renderedStart = offset;
        _renderedEnd = offset;
        _loading = true;
        loadingEl.classList.remove("d-none");

        fetchChunk(offset, CHUNK_BYTES, function (data) {
            _loading = false;
            loadingEl.classList.add("d-none");
            if (!data) {
                tbody.innerHTML = "<tr><td colspan=\"3\" class=\"empty-msg\">No data at this offset.</td></tr>";
                return;
            }
            _totalSize = data.total_size || 0;
            appendChunk(data);
            scrollContainer.scrollTop = 0;
            _initialized = true;
        });
    }

    /** Load more data when scrolling down. */
    function loadMore() {
        if (_loading) return;
        if (_totalSize > 0 && _renderedEnd >= _totalSize) return;
        _loading = true;
        loadingEl.classList.remove("d-none");
        fetchChunk(_renderedEnd, CHUNK_BYTES, function (data) {
            _loading = false;
            loadingEl.classList.add("d-none");
            appendChunk(data);
        });
    }

    /** Load more data when scrolling up. */
    function loadEarlier() {
        if (_loading) return;
        if (_renderedStart <= 0) return;
        _loading = true;
        var fetchStart = Math.max(0, _renderedStart - CHUNK_BYTES);
        var fetchLen = _renderedStart - fetchStart;
        fetchChunk(fetchStart, fetchLen, function (data) {
            _loading = false;
            prependChunk(data);
        });
    }

    // --- Scroll listener ---
    var _scrollDebounce = null;
    var _persistDebounce = null;
    scrollContainer.addEventListener("scroll", function () {
        if (!_initialized) return;
        if (_scrollDebounce) return;
        _scrollDebounce = setTimeout(function () {
            _scrollDebounce = null;
            var scrollTop = scrollContainer.scrollTop;
            var scrollHeight = scrollContainer.scrollHeight;
            var clientHeight = scrollContainer.clientHeight;

            // Near bottom: load more
            if (scrollTop + clientHeight >= scrollHeight - 100) {
                loadMore();
            }
            // Near top: load earlier
            if (scrollTop <= 100) {
                loadEarlier();
            }
        }, 50);
        // Persist hex_offset to project manifest (debounced 1s, best-effort)
        if (_persistDebounce) clearTimeout(_persistDebounce);
        _persistDebounce = setTimeout(function () {
            if (typeof window.saveDashboardState === "function") {
                window.saveDashboardState("hex_offset", _renderedStart);
            }
        }, 1000);
    }, {passive: true});

    // --- Jump-to controls ---
    goBtn.addEventListener("click", function () {
        jumpTo(parseOffset(offsetInput.value));
    });
    offsetInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") jumpTo(parseOffset(offsetInput.value));
    });

    // --- Mouse wheel: if at scroll boundary, load next/prev ---
    scrollContainer.addEventListener("wheel", function (e) {
        if (!_initialized) return;
        var scrollTop = scrollContainer.scrollTop;
        var scrollHeight = scrollContainer.scrollHeight;
        var clientHeight = scrollContainer.clientHeight;

        // Scrolling down past bottom
        if (e.deltaY > 0 && scrollTop + clientHeight >= scrollHeight - 5) {
            loadMore();
        }
        // Scrolling up past top
        if (e.deltaY < 0 && scrollTop <= 5) {
            loadEarlier();
        }
    }, {passive: true});

    // --- Initial load ---
    // Priority: explicit ?offset= URL param > restored hex_offset from
    // active project's dashboard_state > start at 0.
    var params = new URLSearchParams(window.location.search);
    var initOffset = params.get("offset");
    if (initOffset) {
        offsetInput.value = initOffset;
        jumpTo(parseOffset(initOffset));
    } else {
        var st = (window._arkana && window._arkana.state) || {};
        var dashState = (st.active_project && st.active_project.dashboard_state) || {};
        var savedOffset = dashState.hex_offset;
        if (savedOffset && Number(savedOffset) > 0) {
            jumpTo(Number(savedOffset));
        } else {
            jumpTo(0);
        }
    }
})();

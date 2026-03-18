(function() {
    function initLocaleSelector() {
        var localeSelect = document.getElementById("login-select-toggle");
        if (!localeSelect) {
            return;
        }

        localeSelect.addEventListener("change", function() {
            if (localeSelect.value) {
                window.location.href = localeSelect.value;
            }
        });
    }
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initLocaleSelector, { once: true });
    } else {
        initLocaleSelector();
    }
})();

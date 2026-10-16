(function() {
    function init() {
        var countdown = document.getElementById("oid4vp-request-uri-countdown");
        var remaining = document.getElementById("oid4vp-request-uri-remaining");
        if (!countdown || !remaining) {
            return;
        }

        // Count from page load instead of an absolute server time, so a wrong client clock does
        // not shift the deadline.
        var deadline = Date.now() + Number(countdown.dataset.expiresInSeconds) * 1000;
        var timer = window.setInterval(update, 1000);

        function update() {
            var seconds = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
            remaining.textContent = Math.floor(seconds / 60) + ":" + String(seconds % 60).padStart(2, "0");
            if (seconds === 0) {
                window.clearInterval(timer);
                window.location.replace(countdown.dataset.expiredUrl);
            }
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();

(function() {
    function parseConfig(root) {
        if (!root) {
            return null;
        }

        var statusUrl = root.dataset.statusUrl || "";
        var state = root.dataset.state || "";
        if (!statusUrl || !state) {
            return null;
        }

        return {
            statusUrl: statusUrl,
            state: state
        };
    }

    function buildStatusUrl(config) {
        return config.statusUrl + "?state=" + encodeURIComponent(config.state);
    }

    // The server builds the redirect from the base this page was loaded from. A URL on another
    // origin did not come from it.
    function sameOriginUrl(value) {
        try {
            var url = new URL(value, window.location.href);
            return url.origin === window.location.origin ? url.href : null;
        } catch (error) {
            return null;
        }
    }

    function initOid4vpCrossDeviceSse(config) {
        if (!config || !config.statusUrl || !config.state) {
            return null;
        }

        var statusUrl = buildStatusUrl(config);
        var currentSource = null;
        var stopped = false;

        window.__oid4vpSseReady = false;

        function stop() {
            stopped = true;
            if (currentSource) {
                currentSource.close();
            }
        }

        function connect() {
            if (stopped) {
                return;
            }
            currentSource = new EventSource(statusUrl);

            currentSource.addEventListener("complete", function(event) {
                window.__oid4vpSseReady = true;
                stop();
                try {
                    var data = JSON.parse(event.data);
                    var target = sameOriginUrl(data.redirect_uri);
                    if (target) {
                        window.location.href = target;
                    } else {
                        console.error("OID4VP: Ignoring redirect to another origin");
                    }
                } catch (error) {
                    console.error("OID4VP: Failed to parse completion event", error);
                }
            });

            currentSource.addEventListener("failed", function(event) {
                window.__oid4vpSseReady = true;
                stop();
                try {
                    var data = JSON.parse(event.data);
                    var target = sameOriginUrl(data.redirect_uri);
                    if (target) {
                        window.location.href = target;
                    } else {
                        console.error("OID4VP: Ignoring redirect to another origin");
                    }
                } catch (error) {
                    console.error("OID4VP: Failed to parse failure event", error);
                }
            });

            currentSource.addEventListener("ping", function() {
                window.__oid4vpSseReady = true;
            });

            currentSource.addEventListener("timeout", function() {
                window.__oid4vpSseReady = true;
            });

            currentSource.addEventListener("expired", function() {
                window.__oid4vpSseReady = true;
                stop();
            });

            currentSource.onopen = function() {
                window.__oid4vpSseReady = true;
            };

            currentSource.onerror = function() {
                window.__oid4vpSseReady = false;
            };
        }

        connect();

        return {
            close: function() {
                stop();
            }
        };
    }

    window.initOid4vpCrossDeviceSse = initOid4vpCrossDeviceSse;

    var config = parseConfig(document.getElementById("oid4vp-cross-device-sse-config"));
    if (config) {
        initOid4vpCrossDeviceSse(config);
    }
})();

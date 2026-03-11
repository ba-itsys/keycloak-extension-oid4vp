(function() {
    function parseConfig(root) {
        if (!root) {
            return null;
        }

        var statusUrl = root.dataset.statusUrl || "";
        var requestHandle = root.dataset.requestHandle || "";
        var pollIntervalMs = Number(root.dataset.pollIntervalMs || "2000");

        if (!statusUrl || !requestHandle) {
            return null;
        }

        return {
            pollIntervalMs: Number.isFinite(pollIntervalMs) ? pollIntervalMs : 2000,
            statusUrl: statusUrl,
            requestHandle: requestHandle
        };
    }

    function buildStatusUrl(config) {
        return config.statusUrl + "?request_handle=" + encodeURIComponent(config.requestHandle);
    }

    function initOid4vpCrossDeviceSse(config) {
        if (!config || !config.statusUrl || !config.requestHandle) {
            return null;
        }

        var statusUrl = buildStatusUrl(config);
        var pollIntervalMs = config.pollIntervalMs || 2000;
        var currentSource = null;

        window.__oid4vpSseReady = false;

        function connect() {
            currentSource = new EventSource(statusUrl);

            currentSource.addEventListener("complete", function(event) {
                window.__oid4vpSseReady = true;
                currentSource.close();
                try {
                    var data = JSON.parse(event.data);
                    if (data.redirect_uri) {
                        window.location.href = data.redirect_uri;
                    }
                } catch (error) {
                    console.error("OID4VP: Failed to parse completion event", error);
                }
            });

            currentSource.addEventListener("ping", function() {
                window.__oid4vpSseReady = true;
            });

            currentSource.addEventListener("timeout", function() {
                window.__oid4vpSseReady = true;
                currentSource.close();
                connect();
            });

            currentSource.onopen = function() {
                window.__oid4vpSseReady = true;
            };

            currentSource.onerror = function() {
                window.__oid4vpSseReady = false;
                currentSource.close();
                window.setTimeout(connect, pollIntervalMs);
            };
        }

        connect();

        return {
            close: function() {
                if (currentSource) {
                    currentSource.close();
                }
            }
        };
    }

    window.initOid4vpCrossDeviceSse = initOid4vpCrossDeviceSse;

    var config = parseConfig(document.getElementById("oid4vp-cross-device-sse-config"));
    if (config) {
        initOid4vpCrossDeviceSse(config);
    }
})();

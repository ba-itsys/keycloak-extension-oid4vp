<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        Sign in with Wallet
    <#elseif section = "form">
        <form id="oid4vpForm"
              action="${formActionUrl!''}"
              method="post">
            <input type="hidden" id="state" name="state" value="${state!''}"/>
            <input type="hidden" id="vp_token" name="vp_token"/>
            <input type="hidden" id="response" name="response"/>
            <input type="hidden" id="error" name="error"/>
            <input type="hidden" id="error_description" name="error_description"/>
        </form>

        <div class="${properties.kcFormGroupClass!}">
            <p>Present a verifiable credential from your wallet to sign in.</p>
        </div>

        <#-- Same-device redirect button -->
        <#if (sameDeviceEnabled!false) && (sameDeviceWalletUrl!'')?has_content>
            <div class="${properties.kcFormGroupClass!}">
                <a href="${sameDeviceWalletUrl!''}"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   style="display: block; text-align: center; text-decoration: none;">
                    Open Wallet App
                </a>
            </div>
        </#if>

        <#-- Cross-device QR code -->
        <#if (crossDeviceEnabled!false) && (qrCodeBase64!'')?has_content>
            <div class="${properties.kcFormGroupClass!}" style="text-align: center; margin-top: 20px;">
                <#if (sameDeviceEnabled!false)>
                    <p style="margin-bottom: 10px;">Or scan with your phone:</p>
                <#else>
                    <p style="margin-bottom: 10px;">Scan with your wallet app:</p>
                </#if>
                <img src="data:image/png;base64,${qrCodeBase64!''}"
                     alt="QR Code for wallet login"
                     data-wallet-url="${crossDeviceWalletUrl!''}"
                     style="max-width: 250px; border: 1px solid #ddd; padding: 10px; background: white;"/>
                <p style="font-size: 12px; color: #666; margin-top: 10px;">
                    Scan this QR code with your wallet app
                </p>
            </div>
        </#if>

        <#if social.providers?? && social.providers?size gt 0>
            <div class="${properties.kcFormGroupClass!}">
                <hr/>
                <p>Or sign in with another method:</p>
                <ul class="${properties.kcFormSocialAccountListClass!}">
                    <#list social.providers as p>
                        <li class="${properties.kcFormSocialAccountListItemClass!}">
                            <a href="${p.loginUrl}" id="social-${p.alias}" class="${properties.kcFormSocialAccountButtonClass!}">
                                <#if p.iconClasses?has_content>
                                    <i class="${properties.kcFormSocialAccountButtonTextClass!} ${p.iconClasses!}" aria-hidden="true"></i>
                                </#if>
                                <span class="${properties.kcFormSocialAccountButtonText!}">${p.displayName!}</span>
                            </a>
                        </li>
                    </#list>
                </ul>
            </div>
        </#if>

        <#-- SSE: auto-redirect when wallet completes authentication -->
        <#if (crossDeviceStatusUrl!'')?has_content && ((crossDeviceEnabled!false) || (sameDeviceEnabled!false))>
            <script nonce="${cspNonce!}">
                (function() {
                    var state = document.getElementById('state').value;
                    if (!state) return;

                    var statusUrl = '${crossDeviceStatusUrl!''}' + '?state=' + encodeURIComponent(state);

                    function connect() {
                        var es = new EventSource(statusUrl);

                        es.addEventListener('complete', function(e) {
                            es.close();
                            try {
                                var data = JSON.parse(e.data);
                                if (data.redirect_uri) {
                                    window.location.href = data.redirect_uri;
                                }
                            } catch (err) {
                                console.error('OID4VP: Failed to parse completion event', err);
                            }
                        });

                        es.addEventListener('timeout', function() {
                            es.close();
                            connect();
                        });

                        es.onerror = function() {
                            console.log('OID4VP: SSE connection error, reconnecting...');
                        };
                    }

                    connect();
                })();
            </script>
        </#if>
    </#if>
</@layout.registrationLayout>

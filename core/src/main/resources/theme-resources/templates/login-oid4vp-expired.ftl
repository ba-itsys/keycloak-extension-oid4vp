<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("oid4vpLinkExpiredTitle")}
    <#elseif section = "form">
        <p id="oid4vp-link-expired">${msg("oid4vpLinkExpired")}</p>
        <div class="${properties.kcFormGroupClass!}">
            <a id="oid4vp-get-new-link"
               href="${refreshUrl!''}"
               class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
               style="display: block; text-align: center; text-decoration: none;">
                ${msg("oid4vpGetNewLink")}
            </a>
        </div>

        <#-- A wallet that fetched a request object before it expired can still complete the login. -->
        <#if (crossDeviceStatusUrl!'')?has_content>
            <div id="oid4vp-cross-device-sse-config"
                 data-status-url="${crossDeviceStatusUrl}"
                 hidden></div>
            <script nonce="${cspNonce!}" src="${url.resourcesPath}/js/oid4vp-cross-device-sse.js"></script>
        </#if>
    </#if>
</@layout.registrationLayout>

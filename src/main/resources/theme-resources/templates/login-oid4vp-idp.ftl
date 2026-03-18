<#-- Use a dedicated layout so the broker-bound OID4VP step does not inherit Keycloak's generic restart polling. -->
<#import "oid4vp-template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("oid4vpLoginTitle")}
    <#elseif section = "form">
        <form id="oid4vpForm"
              action="${formActionUrl!''}"
              method="post">
            <input type="hidden" id="state" name="state" value="${state!''}"/>
            <input type="hidden" id="requestHandle" value="${requestHandle!''}"/>
            <input type="hidden" id="crossDeviceRequestHandle" value="${crossDeviceRequestHandle!''}"/>
            <input type="hidden" id="vp_token" name="vp_token"/>
            <input type="hidden" id="response" name="response"/>
            <input type="hidden" id="error" name="error"/>
            <input type="hidden" id="error_description" name="error_description"/>
        </form>

        <#-- Same-device redirect button -->
        <#if (sameDeviceEnabled!false) && (sameDeviceWalletUrl!'')?has_content>
            <div class="${properties.kcFormGroupClass!}">
                <a id="oid4vp-open-wallet"
                   href="${sameDeviceWalletUrl!''}"
                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   style="display: block; text-align: center; text-decoration: none;">
                    ${msg("oid4vpOpenWalletApp")}
                </a>
            </div>
        </#if>

        <#-- Cross-device QR code -->
        <#if (crossDeviceEnabled!false) && (qrCodeBase64!'')?has_content>
            <div class="${properties.kcFormGroupClass!}" style="text-align: center; margin-top: 20px;">
                <#if (sameDeviceEnabled!false)>
                    <p style="margin-bottom: 10px;">${msg("oid4vpScanWithPhone")}</p>
                <#else>
                    <p style="margin-bottom: 10px;">${msg("oid4vpScanWithWalletApp")}</p>
                </#if>
                <img id="oid4vp-qr-code"
                     src="data:image/png;base64,${qrCodeBase64!''}"
                     alt="${msg("oid4vpQrCodeAlt")}"
                     data-wallet-url="${crossDeviceWalletUrl!''}"
                     style="max-width: 250px; border: 1px solid #ddd; padding: 10px; background: white;"/>
            </div>
        </#if>

        <#assign hasAlternativeProvider = false>
        <#if social.providers?? && social.providers?size gt 0>
            <#list social.providers as p>
                <#if p.alias != (currentBrokerAlias!'')>
                    <#assign hasAlternativeProvider = true>
                    <#break>
                </#if>
            </#list>
        </#if>

        <#if hasAlternativeProvider>
            <div class="${properties.kcFormGroupClass!}">
                <hr/>
                <p>${msg("oid4vpAlternativeMethods")}</p>
                <ul class="${properties.kcFormSocialAccountListClass!}">
                    <#list social.providers as p>
                        <#if p.alias != (currentBrokerAlias!'')>
                            <li class="${properties.kcFormSocialAccountListItemClass!}">
                                <a href="${p.loginUrl}" id="social-${p.alias}" class="${properties.kcFormSocialAccountButtonClass!}">
                                    <#if p.iconClasses?has_content>
                                        <i class="${properties.kcFormSocialAccountButtonTextClass!} ${p.iconClasses!}" aria-hidden="true"></i>
                                    </#if>
                                    <span class="${properties.kcFormSocialAccountButtonText!}">${p.displayName!}</span>
                                </a>
                            </li>
                        </#if>
                    </#list>
                </ul>
            </div>
        </#if>

        <#if (crossDeviceStatusUrl!'')?has_content && (crossDeviceEnabled!false)>
            <div id="oid4vp-cross-device-sse-config"
                 data-status-url="${crossDeviceStatusUrl!''}"
                 data-request-handle="${crossDeviceRequestHandle!''}"
                 data-poll-interval-ms="${crossDevicePollIntervalMs!'2000'}"
                 hidden></div>
            <script nonce="${cspNonce!}" src="${url.resourcesPath}/js/oid4vp-cross-device-sse.js"></script>
        </#if>
    </#if>
</@layout.registrationLayout>

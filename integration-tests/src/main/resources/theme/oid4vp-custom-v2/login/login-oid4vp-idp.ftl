<#import "oid4vp-template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        Custom wallet login
    <#elseif section = "form">
        <p id="custom-oid4vp-page">Custom wallet content</p>
        <a id="oid4vp-open-wallet" href="${sameDeviceWalletUrl}">Open Wallet</a>
    </#if>
</@layout.registrationLayout>

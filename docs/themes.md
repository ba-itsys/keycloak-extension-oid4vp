# Customizing the Wallet Login Page

The extension renders `login-oid4vp-idp.ftl` through Keycloak's selected **login theme**.
Keycloak looks for the template in that theme, its imports and parents, then in provider
`theme-resources`. The extension supplies its default template through this last fallback.
A template in the selected named theme takes precedence over the extension.

## Override in a Theme JAR

For a theme called `ourtheme`, use this source layout:

```text
src/main/resources/
├── META-INF/keycloak-themes.json
└── theme/ourtheme/login/
    ├── theme.properties
    └── login-oid4vp-idp.ftl
```

The descriptor registers the login theme:

```json
{
  "themes": [
    { "name": "ourtheme", "types": ["login"] }
  ]
}
```

Place the theme JAR in Keycloak's `providers/` directory, rebuild an optimized Keycloak
installation as usual, and restart. Select `ourtheme` under **Realm settings → Themes →
Login theme**. Check the application's **Login theme** setting too: a client theme override
takes precedence over the realm's theme.

The deployed JAR must contain `theme/ourtheme/login/login-oid4vp-idp.ftl`. Templates go
directly in the `login/` directory. A file at `theme/ourtheme/login-oid4vp-idp.ftl`,
`theme/ourtheme/login/templates/login-oid4vp-idp.ftl`, or
`theme/ourtheme/login/resources/login-oid4vp-idp.ftl` is not a login template.

For a directory theme, the equivalent deployed path is
`themes/ourtheme/login/login-oid4vp-idp.ftl`.

Putting a replacement in another provider's `theme-resources/templates/` creates a
duplicate fallback resource on the classpath. That location does not give your template
priority over the extension. Use a named theme for overrides.

## Preserve Wallet Flow Behavior

The extension renders two pages. `login-oid4vp-idp.ftl` shows the wallet button, the QR code
and a countdown. `login-oid4vp-expired.ftl` replaces it when the countdown reaches zero and
offers a new link. Both import the login theme's `template.ftl`, so they follow the selected
theme's layout and language switcher. Errors use Keycloak's standard error page. Start with the
extension's templates when changing their appearance, and keep the values below.

`login-oid4vp-idp.ftl`:

| Value | Purpose |
|-------|---------|
| `sameDeviceEnabled`, `sameDeviceWalletUrl` | Whether to show the wallet button and its destination |
| `crossDeviceEnabled`, `qrCodeBase64`, `crossDeviceWalletUrl` | Whether to show the QR code, its PNG data, and wallet URL |
| `requestUriExpiresInSeconds`, `requestUriExpiredUrl` | Seconds until the first link on the page expires, and the expired page to open then |
| `crossDeviceStatusUrl` | SSE status endpoint that follows the cross-device attempts of this tab |
| `currentBrokerAlias` | Excludes the current provider from alternative login methods |

`login-oid4vp-expired.ftl`:

| Value | Purpose |
|-------|---------|
| `refreshUrl` | Renders the wallet login page with new links |
| `crossDeviceStatusUrl` | SSE status endpoint, set while a cross-device attempt can still complete |

For the countdown, preserve `#oid4vp-request-uri-countdown` with its `data-expires-in-seconds`
and `data-expired-url` attributes, the `#oid4vp-request-uri-remaining` element, and the
`js/oid4vp-request-uri-countdown.js` script. For cross-device login, preserve
`#oid4vp-cross-device-sse-config`, its `data-status-url` attribute, and the
`js/oid4vp-cross-device-sse.js` script on both pages. Keycloak serves the extension's fallback
scripts through `${url.resourcesPath}` for the selected theme as well. Preserve the script nonce
`${cspNonce!}`.

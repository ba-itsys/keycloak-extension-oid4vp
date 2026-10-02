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

Start with the extension's `login-oid4vp-idp.ftl` when changing its appearance. Keep the
wallet URLs and the cross-device completion wiring:

| Value | Purpose |
|-------|---------|
| `sameDeviceEnabled`, `sameDeviceWalletUrl` | Whether to show the wallet button and its destination |
| `crossDeviceEnabled`, `qrCodeBase64`, `crossDeviceWalletUrl` | Whether to show the QR code, its PNG data, and wallet URL |
| `crossDeviceStatusUrl`, `crossDeviceState` | SSE status endpoint and the login attempt to follow |
| `currentBrokerAlias` | Excludes the current provider from alternative login methods |

For cross-device login, preserve `#oid4vp-cross-device-sse-config`, its `data-status-url`
and `data-state` attributes, and the `js/oid4vp-cross-device-sse.js` script. Keycloak
serves the extension's fallback scripts through `${url.resourcesPath}` for the selected
theme as well. Preserve the script nonce `${cspNonce!}`.

## When the Original Template Still Appears

Check the **built artifact**, since resource-copying steps may overwrite the edited
source or omit it. For example:

```bash
jar tf your-theme.jar
unzip -p your-theme.jar theme/ourtheme/login/login-oid4vp-idp.ftl
unzip -p your-theme.jar META-INF/keycloak-themes.json
```

Verify the exact path and file contents, the descriptor's `login` type, and the effective
realm/client login theme. Also check for multiple deployed JARs defining the same theme
name, and deploy the updated artifact to every Keycloak instance serving the application.

While developing, disable theme and template caches:

```bash
bin/kc.sh start-dev \
  --spi-theme--static-max-age=-1 \
  --spi-theme--cache-themes=false \
  --spi-theme--cache-templates=false
```

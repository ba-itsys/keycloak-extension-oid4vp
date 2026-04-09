import http from 'k6/http';
import exec from 'k6/execution';
import { browser } from 'k6/browser';

const ADMIN_BASE_URI = env('LOAD_ADMIN_BASE_URI', 'http://localhost:18080');
const BROWSER_BASE_URIS = csvEnv('LOAD_BROWSER_BASE_URIS', 'http://localhost:18081,http://localhost:18082');
const WALLET_BASE_URI = env('LOAD_WALLET_BASE_URI', 'http://localhost:18085');
const WALLET_INTERNAL_BASE_URI = env('LOAD_WALLET_INTERNAL_BASE_URI', 'http://oid4vc-dev:8085');
const REALM_NAME = env('LOAD_REALM', 'wallet-demo');
const ADMIN_REALM_NAME = env('LOAD_ADMIN_REALM', 'master');
const ADMIN_USERNAME = env('LOAD_ADMIN_USERNAME', 'admin');
const ADMIN_PASSWORD = env('LOAD_ADMIN_PASSWORD', 'admin');
const ADMIN_CLIENT_ID = env('LOAD_ADMIN_CLIENT_ID', 'admin-cli');
const IDP_ALIAS = env('LOAD_IDP_ALIAS', 'oid4vp');
const BROWSER_CLIENT_ID = env('LOAD_BROWSER_CLIENT_ID', 'wallet-mock');
const BROWSER_REDIRECT_URI = env('LOAD_BROWSER_REDIRECT_URI', '');
const SD_JWT_VCT = env('LOAD_SD_JWT_VCT', 'urn:eudi:pid:de:1');
const RATE_PER_SECOND = intEnv('LOAD_RATE_PER_SECOND', 10);
const DURATION_SECONDS = intEnv('LOAD_DURATION_SECONDS', 30);
const PRE_ALLOCATED_VUS = intEnv('LOAD_PRE_ALLOCATED_VUS', 40);
const MAX_VUS = intEnv('LOAD_MAX_VUS', PRE_ALLOCATED_VUS);
const LOGIN_PAGE_TIMEOUT_MS = intEnv('LOAD_LOGIN_PAGE_TIMEOUT_MS', 10000);
const OID4VP_PAGE_TIMEOUT_MS = intEnv('LOAD_OID4VP_PAGE_TIMEOUT_MS', 10000);
const POST_WALLET_TIMEOUT_MS = intEnv('LOAD_POST_WALLET_TIMEOUT_MS', 20000);
const CALLBACK_TIMEOUT_MS = intEnv('LOAD_CALLBACK_TIMEOUT_MS', 20000);
const CONFIGURE_IDP = boolEnv('LOAD_CONFIGURE_IDP', true);
const INSECURE_TLS = boolEnv('LOAD_INSECURE_TLS', false);

const PKCE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const SD_JWT_ONLY_DCQL = JSON.stringify({
    credentials: [
        {
            id: 'pid_sd_jwt',
            format: 'dc+sd-jwt',
            meta: { vct_values: [SD_JWT_VCT] },
            claims: [{ path: ['given_name'] }, { path: ['family_name'] }, { path: ['birthdate'] }],
        },
    ],
});

export const options = {
    insecureSkipTLSVerify: INSECURE_TLS,
    scenarios: {
        browser_sse: {
            executor: 'constant-arrival-rate',
            exec: 'loginFlow',
            rate: RATE_PER_SECOND,
            timeUnit: '1s',
            duration: `${DURATION_SECONDS}s`,
            preAllocatedVUs: PRE_ALLOCATED_VUS,
            maxVUs: MAX_VUS,
            options: {
                browser: {
                    type: 'chromium',
                },
            },
        },
    },
};

export function setup() {
    console.log(`Admin base URI: ${ADMIN_BASE_URI}`);
    console.log(`Browser base URIs: ${BROWSER_BASE_URIS.join(', ')}`);
    console.log(`Wallet base URI: ${WALLET_BASE_URI}`);
    console.log(`Wallet internal base URI: ${WALLET_INTERNAL_BASE_URI}`);
    console.log(`Realm: ${REALM_NAME}`);
    console.log(`Browser client ID: ${BROWSER_CLIENT_ID}`);
    console.log(`Rate: ${RATE_PER_SECOND} logins/s`);
    console.log(`Duration: ${DURATION_SECONDS}s`);
    console.log(`Pre-allocated VUs: ${PRE_ALLOCATED_VUS}`);
    console.log(`Max VUs: ${MAX_VUS}`);

    if (!CONFIGURE_IDP) {
        return;
    }

    const admin = new AdminApi();
    admin.configureOid4vpIdp();
}

export async function loginFlow() {
    const browserBaseUri = pickUri(BROWSER_BASE_URIS, exec.vu.idInTest - 1);
    const expectedRedirectUri = buildBrowserRedirectUri(browserBaseUri);
    const context = await browser.newContext({ ignoreHTTPSErrors: INSECURE_TLS });
    const page = await context.newPage();

    try {
        await page.goto(buildAuthorizationUrl(browserBaseUri, expectedRedirectUri), { waitUntil: 'networkidle' });
        await page.locator('a#social-oid4vp').waitFor({ state: 'visible', timeout: LOGIN_PAGE_TIMEOUT_MS });
        await page.locator('a#social-oid4vp').click();

        await page.locator('#oid4vp-qr-code').waitFor({ state: 'visible', timeout: OID4VP_PAGE_TIMEOUT_MS });
        const walletUrl = await page.locator('#oid4vp-qr-code').getAttribute('data-wallet-url');
        if (!walletUrl) {
            throw new Error('Cross-device wallet URL missing from login page');
        }

        await acceptPresentationRequest(walletUrl);
        await waitForWalletCompletion(page, expectedRedirectUri);

        if (!(await hasFirstBrokerLoginForm(page))) {
            await waitForCallbackUrl(page, expectedRedirectUri, CALLBACK_TIMEOUT_MS);
            return;
        }

        await completeFirstBrokerLogin(page, expectedRedirectUri);
    } finally {
        await page.close();
        await context.close();
    }
}

async function acceptPresentationRequest(walletUrl) {
    let response = walletPost('/api/presentations', { uri: walletUrl });
    if (isSessionExpiredResponse(response.body)) {
        response = walletPost('/api/presentations', { uri: walletUrl });
    }
    if (response.status !== 200) {
        throw new Error(`Wallet presentation request failed: ${response.status} ${response.body}`);
    }
}

async function waitForWalletCompletion(page, expectedRedirectUri) {
    const deadline = Date.now() + POST_WALLET_TIMEOUT_MS;
    while (Date.now() < deadline) {
        if (isExpectedCallback(page.url(), expectedRedirectUri)) {
            return;
        }
        if (await hasFirstBrokerLoginForm(page)) {
            return;
        }
        await page.waitForTimeout(250);
    }
    throw new Error(`OID4VP browser flow did not progress after wallet response. Current URL: ${page.url()}`);
}

async function completeFirstBrokerLogin(page, expectedRedirectUri) {
    const suffix = `${exec.vu.idInTest}-${exec.scenario.iterationInTest}`;
    await fillIfVisible(page, 'input[name="username"]', `load-oid4vp-${suffix}`);
    await fillIfVisible(page, 'input[name="email"]', `load-oid4vp-${suffix}@example.com`);
    await fillIfVisible(page, 'input[name="firstName"]', 'Load');
    await fillIfVisible(page, 'input[name="lastName"]', 'Tester');
    await page.locator('input[type="submit"], button[type="submit"]').first().click();
    await waitForCallbackUrl(page, expectedRedirectUri, CALLBACK_TIMEOUT_MS);
}

async function waitForCallbackUrl(page, expectedRedirectUri, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const currentUrl = page.url();
        if (isExpectedCallback(currentUrl, expectedRedirectUri)) {
            if (!/[?&]code=/.test(currentUrl)) {
                throw new Error(`Login completed without authorization code: ${currentUrl}`);
            }
            return;
        }
        await page.waitForTimeout(250);
    }
    throw new Error(`Browser did not reach callback URL. Current URL: ${page.url()}`);
}

async function hasFirstBrokerLoginForm(page) {
    return (await page.locator('input[name="username"]').count()) > 0;
}

async function fillIfVisible(page, selector, value) {
    const locator = page.locator(selector);
    if ((await locator.count()) === 0) {
        return;
    }
    await locator.first().fill(value);
}

function isExpectedCallback(currentUrl, expectedRedirectUri) {
    return currentUrl === expectedRedirectUri || currentUrl.startsWith(`${expectedRedirectUri}?`);
}

function buildAuthorizationUrl(browserBaseUri, redirectUri) {
    const realmBase = `${trimTrailingSlash(browserBaseUri)}/realms/${encodeURIComponent(REALM_NAME)}`;
    const state = `load-${exec.vu.idInTest}-${exec.scenario.iterationInTest}-${Date.now()}`;
    return `${realmBase}/protocol/openid-connect/auth`
        + `?client_id=${encodeURIComponent(BROWSER_CLIENT_ID)}`
        + `&redirect_uri=${encodeURIComponent(redirectUri)}`
        + '&response_type=code'
        + '&scope=openid'
        + `&state=${encodeURIComponent(state)}`
        + `&code_challenge=${encodeURIComponent(PKCE_CHALLENGE)}`
        + '&code_challenge_method=S256';
}

function buildBrowserRedirectUri(browserBaseUri) {
    if (BROWSER_REDIRECT_URI) {
        return BROWSER_REDIRECT_URI;
    }
    return `${trimTrailingSlash(browserBaseUri)}/${encodeURIComponent(BROWSER_CLIENT_ID)}/callback`;
}

function walletPost(path, body) {
    return request(
        `${trimTrailingSlash(WALLET_BASE_URI)}${path}`,
        'POST',
        JSON.stringify(body),
        { 'Content-Type': 'application/json' },
        false,
    );
}

class AdminApi {
    constructor() {
        this.token = this.requestToken();
    }

    configureOid4vpIdp() {
        const idpPath = `/admin/realms/${encodeURIComponent(REALM_NAME)}/identity-provider/instances/${encodeURIComponent(IDP_ALIAS)}`;
        const idp = this.getJson(idpPath);
        const config = idp.config || {};

        config.doNotStoreUsers = 'true';
        config.sameDeviceEnabled = 'false';
        config.crossDeviceEnabled = 'true';
        config.enforceHaip = 'false';
        config.clientIdScheme = 'plain';
        config.responseMode = 'direct_post.jwt';
        config.dcqlQuery = SD_JWT_ONLY_DCQL;
        config.trustListUrl = `${trimTrailingSlash(WALLET_INTERNAL_BASE_URI)}/api/trustlist?vct=${encodeURIComponent(SD_JWT_VCT)}`;
        config.trustListSigningCertPem = '';
        config.trustListLoTEType = '';
        config.trustedAuthoritiesMode = 'none';
        config.x509CertificatePem = '';
        config.x509SigningKeyJwk = '';
        config.verifierInfo = '';
        config.userMappingClaim = 'family_name';
        config.userMappingClaimMdoc = 'family_name';
        idp.config = config;

        this.putJson(idpPath, idp);
    }

    requestToken() {
        const tokenUri = `${trimTrailingSlash(ADMIN_BASE_URI)}/realms/${encodeURIComponent(ADMIN_REALM_NAME)}/protocol/openid-connect/token`;
        const form = encodeForm({
            grant_type: 'password',
            client_id: ADMIN_CLIENT_ID,
            username: ADMIN_USERNAME,
            password: ADMIN_PASSWORD,
        });
        const response = request(
            tokenUri,
            'POST',
            form,
            {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Forwarded-Proto': 'https',
            },
            false,
        );
        if (response.status !== 200) {
            throw new Error(`Admin token request failed: ${response.status} ${response.body}`);
        }
        const payload = JSON.parse(response.body);
        return payload.access_token;
    }

    getJson(path) {
        const response = request(this.resolve(path), 'GET', null, this.authHeaders(), false);
        if (response.status !== 200) {
            throw new Error(`GET ${path} failed: ${response.status} ${response.body}`);
        }
        return JSON.parse(response.body);
    }

    putJson(path, body) {
        const response = request(
            this.resolve(path),
            'PUT',
            JSON.stringify(body),
            {
                ...this.authHeaders(),
                'Content-Type': 'application/json',
            },
            false,
        );
        if (response.status !== 200 && response.status !== 204) {
            throw new Error(`PUT ${path} failed: ${response.status} ${response.body}`);
        }
    }

    authHeaders() {
        return {
            Authorization: `Bearer ${this.token}`,
            'X-Forwarded-Proto': 'https',
        };
    }

    resolve(path) {
        if (path.startsWith('http://') || path.startsWith('https://')) {
            return path;
        }
        return `${trimTrailingSlash(ADMIN_BASE_URI)}${path.startsWith('/') ? '' : '/'}${path}`;
    }
}

function request(url, method, body, headers, expectJson) {
    const response = http.request(method, url, body, {
        headers,
        redirects: 0,
        timeout: '30s',
    });
    if (expectJson && response.status >= 200 && response.status < 300) {
        try {
            response.json();
        } catch (error) {
            throw new Error(`Expected JSON response from ${url}: ${error.message}`);
        }
    }
    return response;
}

function isSessionExpiredResponse(body) {
    if (!body) {
        return false;
    }
    try {
        const parsed = JSON.parse(body);
        const nested = parsed.response;
        if (!nested || nested.status_code !== 400) {
            return false;
        }
        const nestedBody = typeof nested.body === 'string' ? JSON.parse(nested.body) : nested.body;
        return nestedBody && nestedBody.error === 'session_expired';
    } catch (error) {
        return false;
    }
}

function encodeForm(values) {
    return Object.entries(values)
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
        .join('&');
}

function env(name, fallback) {
    return __ENV[name] && __ENV[name] !== '' ? __ENV[name] : fallback;
}

function csvEnv(name, fallback) {
    return env(name, fallback)
        .split(',')
        .map((value) => value.trim())
        .filter((value) => value !== '');
}

function intEnv(name, fallback) {
    const value = parseInt(env(name, String(fallback)), 10);
    return Number.isFinite(value) ? value : fallback;
}

function boolEnv(name, fallback) {
    const value = env(name, fallback ? 'true' : 'false').toLowerCase();
    return value === 'true' || value === '1' || value === 'yes';
}

function pickUri(values, index) {
    return values[index % values.length];
}

function trimTrailingSlash(value) {
    return value.endsWith('/') ? value.slice(0, -1) : value;
}

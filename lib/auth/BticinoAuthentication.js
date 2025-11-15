const BticinoProxy = require('./BticinoProxy');
const crypto = require('crypto');
const open = require('open');
const EventEmitter = require('events');
const config = require('../config/config');

/**
 * BticinoAuthentication
 * High-level authentication orchestrator built on top of {@link BticinoProxy}.
 * Responsibilities:
 *  1. Start / stop the local debug proxy
 *  2. Generate & track a secure `state` for the Azure AD B2C authorize request
 *  3. Open the system browser (optional) to perform the login through the proxy
 *  4. Wait until the mobile custom-scheme redirect is intercepted and extract the authorization code
 *  5. Exchange the authorization code for B2C (and optionally Legrand) tokens, unless disabled
 *  6. Schedule automatic refresh before expiry
 *  7. Emit an event `tokenCreated` whenever a fresh token set is acquired (initial / refresh / forced)
 *  8. Emit an event `tokenRefreshed` ONLY for refresh events (scheduled / forced / immediate)
 *  9. Emit an event `loginUrl` when an interactive login is required. Payload: an object
 *     containing `{ state, loginUrl, url }` where `loginUrl` is the absolute URL to open
 *     and `url` is the path-only authorize URL.
 *
 * Environment variables influencing behaviour (mirrors proxy):
 *  - `DISABLE_LEGRAND_TOKEN=1`  : skip Legrand secondary token
 *  - `USE_HTTPS=1`               : run proxy with self-signed HTTPS
 *
 * Typical usage:
 * @example
 * const BticinoAuthentication = require('./BticinoAuthentication');
 * const auth = new BticinoAuthentication({ autoOpenBrowser: true });
 * auth.on('tokenCreated', (t, meta) => console.log('Tokens received. Access (short) =', t.b2cAccessToken.slice(0,40), 'meta=', meta));
 * // Listen for interactive login URL when the library requires user interaction
 * auth.on('loginUrl', ({ state, loginUrl }) => console.log('Open this login URL:', loginUrl));
 * const { tokens } = await auth.authenticate();
 * console.log('Access token expires at', tokens.expiresAt);
 * // Later on (optional forced refresh)
 * await auth.forceRefresh();
 * // When shutting down your app/service
 * auth.stop();
 */
/**
 * Events emitted by this class:
 * @emits BticinoAuthentication#loginUrlCreated {Object} Emitted when interactive login is required. Payload: {state, loginUrl, url}
 * @emits BticinoAuthentication#tokenCreated {Object} Emitted after new tokens are acquired.
 * @emits BticinoAuthentication#tokenRefreshed {Object} Emitted when tokens are refreshed.
 */
class BticinoAuthentication extends EventEmitter {
    /**
     * Create a BticinoAuthentication instance.
     * @param {Object} [options]
     * @param {boolean} [options.forceLogin=false] Force re-login (prompt=login)
     * @param {number} [options.timeoutMs=180000] Timeout for interactive login (ms)
     * @param {boolean} [options.autoOpenBrowser=false] Automatically open browser for login
     * @param {boolean} [options.autoStopOnAuth=true] Stop local proxy immediately after capturing code
     * @param {boolean} [options.debug=false] Enable debug logs
     * @param {boolean} [options.autoRefresh=true] Automatically schedule token refresh before expiry
     * @param {number} [options.refreshSkewSec=60] Seconds to subtract from expiry when scheduling refresh
     * @param {boolean} [options.unrefRefreshTimer=true] Call `unref()` on the refresh timer when supported
     * @param {boolean} [options.installExitHooks=false] Install process signal handlers (SIGINT/SIGTERM)
     * @param {string} [options.proxyHost] Optional host override for the local proxy
     * @param {number} [options.proxyPort] Optional port override for the local proxy
     * @param {Object} [options.initialTokens] Optional initial tokens object (will be enriched)
     * @param {string|null} [options.successPage=null] Optional HTML template to show after auth capture; passed to the proxy
     */
    constructor(options = {}) {
        super();
        // Merge provided options with sensible defaults
        this.opts = Object.assign({
            forceLogin: false,
            timeoutMs: 180000,
            autoOpenBrowser: false,
            autoStopOnAuth: true,
            debug: false,
            autoRefresh: true,
            refreshSkewSec: 60,
            unrefRefreshTimer: true,
            installExitHooks: false,
            proxyHost: undefined,
            proxyPort: undefined,
            successPage: undefined
        }, options || {});

        // Build proxy options from resolved opts
        const proxyOpts = {
            debug: !!this.opts.debug,
            successPage: this.opts.successPage,
            host: this.opts.proxyHost,
            port: this.opts.proxyPort
        };
        this.proxy = new BticinoProxy(proxyOpts);

        this._started = false;
        this.currentTokens = null;
        this._refreshTimer = null;
        // `sipClientId` and `forceCertificates` constructor options were removed
        // to simplify the API: consumers should provide those per-call to
        // `registerDevice()` or persist them themselves when handling events.
        // If initial tokens were provided via options, ingest them now
        if (this.opts.initialTokens) {
            try {
                this.currentTokens = this._enrich(this.opts.initialTokens);
                this._log('Initial tokens provided via constructor');
                // schedule refresh if needed
                if (this.opts.autoRefresh && this._isStillValid(this.currentTokens)) {
                    this._scheduleRefresh(this.currentTokens);
                }
            } catch (e) {
                this._log('Failed to process initial tokens:', e.message);
            }
        }

        if (this.opts.installExitHooks) {
            this._installProcessHooks();
        }
    }

    /**
     * Set initial tokens programmatically after construction.
     * Accepts either an object (parsed JSON) or a JSON string (raw file content).
     * The token object should match the structure returned by the token exchange (e.g.
     * { b2cAccessToken, b2cRefreshToken, expiresIn, receivedAt, ... }).
     *
    * Behavior:
    * - tokens will be enriched with timing metadata via `_enrich()`.
    * - if `autoRefresh` is true and tokens are still valid a refresh will be scheduled.
     *
     * @param {Object|string} tokens Token object or JSON string (raw file contents)
     * @throws {Error} if JSON parsing fails or tokens are invalid
     */
    setInitialTokens(tokens) {
        try {
            let parsed = tokens;
            if (typeof tokens === 'string') {
                // tolerate raw JSON string input (e.g. fs.readFileSync(path, 'utf8'))
                try { parsed = JSON.parse(tokens); } catch (e) { throw new Error('Failed to parse tokens JSON string: ' + e.message); }
            }
            this.currentTokens = this._enrich(parsed);
            this._log('Initial tokens set programmatically via setInitialTokens(): ' + JSON.stringify(this.currentTokens, null, 2));
            // Persistence removed: consumer is responsible for storing tokens.
            if (this.opts.autoRefresh && this._isStillValid(this.currentTokens)) this._scheduleRefresh(this.currentTokens);
        } catch (e) {
            this._log('Failed to set initial tokens:', e.message);
            throw e;
        }
    }

    // `setSipClientId()` has been removed: consumers must persist any SIP
    // client identifier externally and can pass it to `registerDevice()` as
    // a per-call option when required.

    /**
     * Conditional logger (internal).
     * @private
     */
    _log(...args) { if (this.opts.debug) console.log(...args); }

    /**
     * Conditional warn logger (internal).
     * @private
     */
    _warn(...args) { if (this.opts.debug) console.warn(...args); }

    /**
     * Internal error logger — always log errors to stderr.
     * Keeping a dedicated method allows consistent formatting and future hooks.
     * @private
     */
    _error(...args) { console.error(...args); }

    /**
    * Ensure the underlying {@link BticinoProxy} is started exactly once.
     * Safe to call multiple times.
     * @returns {Promise<void>}
     * @example
     * await auth.ensureStarted(); // idempotent
     */
    async ensureStarted() {
        if (!this._started) {
            await this.proxy.start();
            this._started = true;
        }
    }

    /**
     * Construct the proxied Azure AD B2C authorization URL and register its state.
     * @returns {{state:string,url:string,fullUrl:string}}
     *  - `state`: generated random hex string
     *  - `url`: path-only authorize URL (relative to proxy)
     *  - `fullUrl`: full absolute URL (http/https + host + port)
     * @example
     * const { fullUrl } = auth.prepareLoginUrl();
     * console.log('Open this in a browser:', fullUrl);
     */
    prepareLoginUrl() {
        const state = crypto.randomBytes(16).toString('hex');
        this.proxy.validStates.set(state, Date.now());
        const scopeEnc = encodeURIComponent(this.proxy.b2cConfig.scope);
        const basePath = '/EliotClouduamprd.onmicrosoft.com/oauth2/v2.0/authorize';
        const force = this.opts.forceLogin ? '&prompt=login' : '';
        const pathUrl = `${basePath}?client_id=${this.proxy.b2cConfig.clientId}&redirect_uri=${encodeURIComponent(this.proxy.b2cConfig.redirectUri)}&response_type=code&scope=${scopeEnc}&p=${this.proxy.b2cConfig.policy}&state=${state}${force}`;
        const proto = config.USE_HTTPS === '1' ? 'https' : 'http';
        const hostDisplay = (this.proxy.host === '0.0.0.0') ? 'localhost' : this.proxy.host;
        const fullUrl = `${proto}://${hostDisplay}:${this.proxy.port}${pathUrl}`;
        return { state, url: pathUrl, fullUrl };
    }

    // getLoginUrl() removed — use `authenticate()` which will emit a `loginUrl`
    // event when interactive login is required. This keeps the public surface
    // smaller and centralises interactive flows inside authenticate().

    /**
     * Poll until the proxy records an authorization code or timeout expires.
     * @param {string} expectedState State value to validate (ignored if falsy)
     * @returns {Promise<{code:string,state:string}>}
     * @throws {Error} on timeout
     * @example
     * const promise = auth.waitForAuthorizationCode(myState);
     * // ... user logs in ...
     * const { code } = await promise;
     */
    waitForAuthorizationCode(expectedState) {
        return new Promise((resolve, reject) => {
            const start = Date.now();
            const poll = () => {
                if (this.proxy.capturedAuthCode) {
                    const { code, state } = this.proxy.capturedAuthCode;
                    if (!expectedState || state === expectedState) {
                        return resolve({ code, state });
                    }
                }
                if (Date.now() - start > this.opts.timeoutMs) {
                    return reject(new Error('Timeout waiting for authorization code'));
                }
                setTimeout(poll, 700);
            };
            poll();
        });
    }

    /**
     * Complete authentication flow with lazy proxy start.
     * Flow:
     *  1. Try cached tokens (valid → return)
     *  2. If expired & refresh token exists → attempt immediate refresh (no proxy needed)
     *  3. If still no valid tokens → start proxy, interactive login, capture code
     *  4. Optionally stop proxy server immediately (autoStopOnAuth) BEFORE exchanging tokens
     *  5. Exchange code (unless disabled), enrich + schedule refresh
     * @returns {Promise<{code:string|null,state:string|null,tokens?:Object,fromCache?:boolean,refreshed?:boolean}>}
     */
    async authenticate() {
        // 0. If tokens were provided programmatically (constructor or setInitialTokens), prefer them first
        if (this.currentTokens) {
            // Normalize/enrich any provided token shape so downstream checks work
            try {
                this.currentTokens = this._enrich(this.currentTokens);
            } catch (e) {
                this._log('Failed enriching provided tokens:', e && e.message);
            }

            this._log('Initial tokens set programmatically, checking validity...');
            if (this.opts.debug) {
                this._log('token keys:', Object.keys(this.currentTokens || {}));
                this._log('expiresAtMs:', this.currentTokens?.expiresAtMs, 'now:', Date.now(), 'hasRefreshToken:', !!this.currentTokens?.b2cRefreshToken);
            }

            if (this._isStillValid(this.currentTokens)) {
                this._log('Using provided tokens (still valid)');
                this._scheduleRefresh(this.currentTokens);
                // If configured, run the device registration sequence even when tokens were provided
                // Registration is now explicit. Consumers should call `auth.registerDevice()`
                // after selecting a plant/gateway. Automatic registration during
                // authenticate() was removed to avoid performing server-side changes
                // before the caller has chosen the target plant.
                return { code: null, state: null, tokens: this.currentTokens, fromCache: 'provided' };
            }

            if (this.currentTokens?.b2cRefreshToken) {
                try {
                    this._log('Provided tokens expired → attempting immediate refresh using b2cRefreshToken');
                    const refreshed = await this._refreshNow(this.currentTokens.b2cRefreshToken, { immediate: true, source: 'provided' });
                    this._log('Immediate refresh (provided tokens) succeeded');
                    // Registration is now explicit and must be triggered by the consumer.
                    return { code: null, state: null, tokens: refreshed, fromCache: 'provided', refreshed: true };
                } catch (e) {
                    this._log('Immediate refresh (provided tokens) failed, proceeding with interactive login; error:', e && (e.stack || e.message || e));
                }
            } else {
                if (this.opts.debug) this._log('No b2cRefreshToken present in provided tokens — will fall back to interactive login');
            }
        }

        // 1. Need interactive login → start proxy now
        this._log('No valid tokens available, starting interactive login flow...');

        await this.ensureStarted();
        const { state, url: pathUrl, fullUrl } = this.prepareLoginUrl();
        this._log('Authorization URL:', fullUrl);

        // Emit an event so callers (e.g. main.js) can present or open the URL
        // in their own context/UI. Payload includes state, the absolute URL and
        // the path-only URL.
        try {
            this.emit('loginUrlCreated', { state, loginUrl: fullUrl, url: pathUrl });
        } catch (e) {
            this._log('emit(loginUrlCreated) error:', e && e.message);
        }

        if (this.opts.autoOpenBrowser) {
            try {
                await open(fullUrl);
                this._log('Browser opened for authentication');
            } catch (e) {
                this._log('Could not auto-open browser, open manually.');
            }
        }

        this._log('Waiting for authorization code (state=' + state + ') ...');
        const { code, state: returnedState } = await this.waitForAuthorizationCode(state);
        this._log('Authorization code captured');

        // 3. Stop proxy server immediately if configured (retain ability to call token endpoints)
        if (this.opts.autoStopOnAuth) {
            try {
                if (this.proxy && this.proxy.server) {
                    this.proxy.stop();
                    this._started = false; // allow future restarts for future logins
                }
            } catch (e) {
                this._log('Failed stopping proxy (ignored):', e.message);
            }
        }

        // 4. Exchange code for tokens
        let tokens;
        try {
            const includeLegrand = this.opts.legrand !== undefined ? this.opts.legrand : undefined;
            tokens = await this.proxy.exchangeCodeForTokens(code, { includeLegrand });
            this._log('Token exchange completed');
            this._handleNewTokens(tokens);
            // Registration is explicit: consumers should call `auth.registerDevice()`
            // after selecting plant/gateway. The library will not automatically
            // register devices during authenticate().
        } catch (e) {
            this._error('Token exchange failed:', e.message);
        }
        return { code, state: returnedState, tokens };
    }

    /**
     * Stop the proxy and cancel any scheduled token refresh timer.
     * Safe to call multiple times.
     * @example
     * auth.stop();
     */
    stop() {
        // New semantics: ONLY stop proxy, keep refresh timer alive so auto-refresh continues.
        if (this.proxy) this.proxy.stop();
        this._started = false;
    }

    /**
     * Graceful shutdown alias (semantic convenience for higher level apps).
     * Ensures timers are cleared and proxy stopped so the process can exit cleanly.
     * @example
     * await auth.shutdown();
     */
    async shutdown() {
        // Perform a graceful shutdown: cancel refresh timer and stop proxy.
        try {
            if (this._refreshTimer) {
                try { clearTimeout(this._refreshTimer); } catch (_) { }
                this._refreshTimer = null;
            }
        } catch (_) { }

        try {
            if (this.proxy && typeof this.proxy.stop === 'function') {
                // Support both sync and async stop implementations.
                const res = this.proxy.stop();
                if (res && typeof res.then === 'function') {
                    try { await res; } catch (_) { }
                }
            }
        } catch (e) {
            this._log('Error stopping proxy during shutdown:', e && e.message);
        }
        this._started = false;
    }

    /**
     * Alias for shutdown().
     */
    dispose() { this.stop(); }

    /**
     * Internal: enrich + persist + callback + schedule refresh.
     * @private
     * @param {Object} tokens Raw token object from proxy exchange/refresh
     * @param {Object} meta Metadata flags (refresh, forced, scheduled, immediate)
     */
    _handleNewTokens(tokens, meta = {}) {
        if (!tokens) return;
        const enriched = this._enrich(tokens);
        this.currentTokens = enriched;
        // Persistence removed: consumer is responsible for storing tokens.
        // Emit events for consumers
        try { this.emit('tokenCreated', enriched, meta); } catch (e) { this._log('emit(tokenCreated) error:', e && e.message); }
        if (meta && meta.refresh) {
            try { this.emit('tokenRefreshed', enriched, meta); } catch (e) { this._log('emit(tokenRefreshed) error:', e && e.message); }
        }
        if (this.opts.autoRefresh) this._scheduleRefresh(enriched);
    }

    /**
     * Internal: schedule a refresh prior to expiry (skew configurable).
     * @private
     * @param {Object} tokens Enriched token object (must include refresh token & expiresAtMs)
     */
    _scheduleRefresh(tokens) {
        if (!tokens?.b2cRefreshToken || !tokens.expiresAtMs) return;
        const skewMs = this.opts.refreshSkewSec * 1000;
        const delay = Math.max(5000, tokens.expiresAtMs - Date.now() - skewMs);
        this._log(`Scheduling token refresh in ${Math.round(delay / 1000)}s (skew ${this.opts.refreshSkewSec}s)`);
        if (this._refreshTimer) clearTimeout(this._refreshTimer);
        this._refreshTimer = setTimeout(() => this._doRefresh(), delay);
        if (this.opts.unrefRefreshTimer && typeof this._refreshTimer.unref === 'function') {
            this._refreshTimer.unref();
        }
        const when = new Date(Date.now() + delay).toISOString();
        this._log(`Next refresh scheduled at ${when}`);
    }



    /**
     * Create and return an API client bound to this authentication instance.
     */
    createApiClient(options = {}) {
        const BticinoApiClient = require('../api/BticinoApiClient');
        const api = new BticinoApiClient(this, {
            debug: !!(options.debug || this.opts.debug)
        });
        return api;
    }

    /**
     * Force creation/provisioning of certificates for an existing device.
     * Only accepts the minimal parameters required for certificate provisioning
     * and delegates to `registerDevice()` with `forceCertificates: true`.
     * @param {Object} [options]
     * @param {string} [options.plantId] Plant UUID (required if `gatewayId` not provided)
     * @param {string} [options.gatewayId] Gateway module UUID (optional; can be inferred from `plantId`)
     * @returns {Promise<any>} Result of the provisioning sequence
     * @example
     * await auth.provisionCertificates({ plantId: '<plant-id>' });
     */
    async provisionCertificates(options = {}) {
        const { plantId, gatewayId } = options || {};
        const callOpts = { forceCertificates: true };
        if (plantId) callOpts.plantId = plantId;
        if (gatewayId) callOpts.gatewayId = gatewayId;
        // propagate debug from instance
        callOpts.debug = !!this.opts.debug;
        return this.registerDevice(callOpts);
    }

    /**
     * Explicitly register the device (server-side registration + certificate provisioning).
     * Should be called by consumers after selecting plant/gateway via the API client.
     */
    async registerDevice(options = {}) {
        const opts = Object.assign({ debug: !!this.opts.debug, async: false }, options || {});
        const { BticinoRegisterDevice } = require('./BticinoRegisterDevice');
        const api = this.createApiClient({ debug: opts.debug });
        const emitter = opts.emitter || new EventEmitter();

        // Forward important events
        emitter.on('registered', (payload) => {
            try {
                this.emit('deviceRegistered', payload);
            } catch (e) {
                this._error('emit(deviceRegistered) error:', e && e.message);
            }
        });

        // certificatesProvisioned event removed; consumers should listen to 'certificatesCreated' instead.

        emitter.on('certificatesCreated', (info) => {
            try {
                this.emit('certificatesCreated', info);
            } catch (e) {
                this._error('emit(certificatesCreated) error:', e && e.message);
            }
        });

        const seqOptions = { debug: !!opts.debug, emitter, forceCertificates: !!opts.forceCertificates };

        if (opts.plantId) seqOptions.plantId = opts.plantId;
        if (opts.gatewayId) seqOptions.gatewayId = opts.gatewayId;
        // Allow caller to specify the name under which the SIP device will be registered.
        if (opts.clientName) seqOptions.clientName = opts.clientName;
        const promise = BticinoRegisterDevice(this, api, seqOptions);
        if (opts.async) {
            // Start in background; attach a handler to avoid unhandled rejections
            promise.then(() => this._log('registerDevice completed (background)')).catch(err => this._log('registerDevice (background) error:', err && err.message));
            return promise;
        }
        // Default: await completion and return result
        const result = await promise;
        return result;
    }

    /**
     * Internal: perform scheduled refresh (logs errors, does not throw to caller).
     * @private
     */
    async _doRefresh() {
        if (!this.currentTokens?.b2cRefreshToken) return;
        this._log('Performing scheduled token refresh...');
        try {
            const includeLegrand = this.opts.legrand !== undefined ? this.opts.legrand : undefined;
            const refreshed = await this.proxy.refreshAccessToken(this.currentTokens.b2cRefreshToken, { includeLegrand });
            this._log('Refresh succeeded');
            this._handleNewTokens(refreshed, { refresh: true, scheduled: true });
        } catch (e) {
            this._log('Scheduled refresh failed:', e.message);
        }
    }

    /**
     * Internal: add derived timing metadata to token object.
     * @private
     * @param {Object} tokens Raw token response
     * @returns {Object} enriched token object
     */
    _enrich(tokens) {
        // Clone incoming object so we can normalize without mutating caller data
        const t = { ...tokens };

        // Normalize common OAuth field names to the library's expected names
        // without overwriting any already-present library-specific keys.
        if (t.refresh_token && !t.b2cRefreshToken) t.b2cRefreshToken = t.refresh_token;
        if (t.access_token && !t.b2cAccessToken) t.b2cAccessToken = t.access_token;
        // Normalize expires_in (string or number) to numeric expiresIn (seconds)
        if ((t.expires_in || t.expiresIn) && !t.expiresIn) {
            const v = t.expires_in || t.expiresIn;
            const n = Number(v);
            if (!Number.isNaN(n)) t.expiresIn = n;
        }

        // receivedAt may be an ISO string or a numeric timestamp; fall back to now
        const receivedAtMs = (t.receivedAt ? (isNaN(Number(t.receivedAt)) ? Date.parse(t.receivedAt) || Date.now() : Number(t.receivedAt)) : Date.now());

        const expiresAtMs = t.expiresIn ? (receivedAtMs + (Number(t.expiresIn) * 1000)) : null;
        return { ...t, receivedAtMs, expiresAtMs, expiresAt: expiresAtMs ? new Date(expiresAtMs).toISOString() : null };
    }

    /**
     * Determine if tokens are still valid considering the refresh skew.
     * @private
     * @param {Object} tokens Enriched token object
     * @returns {boolean}
     */
    _isStillValid(tokens) {
        if (!tokens?.expiresAtMs) return false;
        const skewMs = this.opts.refreshSkewSec * 1000;
        return Date.now() < (tokens.expiresAtMs - skewMs);
    }

    // Methods for on-disk persistence of tokens and sipClientId were removed.
    // Consumers must save and provide tokens and sipClientId explicitly.

    /**
     * Internal immediate refresh helper used during authenticate() when cached tokens are expired.
     * @private
     * @param {string} refreshToken Existing refresh token
     * @param {Object} [meta] Additional meta flags merged into callback meta
     * @returns {Promise<Object>} Updated enriched token object (also stored in `currentTokens`)
     */
    async _refreshNow(refreshToken, meta = {}) {
        if (!refreshToken) throw new Error('No refresh token provided');
        this._log('Performing immediate refresh (cached token expired)...');
        const includeLegrand = this.opts.legrand !== undefined ? this.opts.legrand : undefined;
        const refreshed = await this.proxy.refreshAccessToken(refreshToken, { includeLegrand });
        this._handleNewTokens(refreshed, { refresh: true, immediate: true, ...meta });
        return this.currentTokens;
    }

    /**
     * Force an immediate refresh using the current refresh token (throws if missing).
     * Useful before a long batch job or after receiving a 401.
    * Also triggers onTokenCreated callback and reschedules automatic refresh.
     * @returns {Promise<Object>} Enriched refreshed token object.
     * @throws {Error} If no refresh token present or refresh fails.
     * @example
     * await auth.forceRefresh();
     */
    async forceRefresh() {
        if (!this.currentTokens?.b2cRefreshToken) throw new Error('No refresh token available');
        this._log('Forcing immediate refresh...');
        const includeLegrand = this.opts.legrand !== undefined ? this.opts.legrand : undefined;
        const refreshed = await this.proxy.refreshAccessToken(this.currentTokens.b2cRefreshToken, { includeLegrand });
        this._handleNewTokens(refreshed, { refresh: true, forced: true });
        return this.currentTokens;
    }

    /**
     * Install process signal handlers (SIGINT/SIGTERM) that call shutdown().
     * Internal helper (idempotent).
     * @private
     */
    _installProcessHooks() {
        if (this._hooksInstalled) return;
        const handler = (sig) => {
            if (this._shutdownInProgress) return;
            this._shutdownInProgress = true;
            // Give shutdown up to 5s to complete, then force exit
            const forceMs = 5000;
            this._log(`Received ${sig} → attempting graceful shutdown (timeout ${forceMs}ms)`);
            const forceTimer = setTimeout(() => {
                this._log('Graceful shutdown timed out — forcing exit');
                try { process.exit(1); } catch (_) { /* ignore */ }
            }, forceMs);

            (async () => {
                try {
                    await this.shutdown();
                    clearTimeout(forceTimer);
                    try { process.exit(0); } catch (_) { /* ignore */ }
                } catch (e) {
                    clearTimeout(forceTimer);
                    this._log('Error during shutdown handler:', e && e.message);
                    try { process.exit(1); } catch (_) { /* ignore */ }
                }
            })();
        };
        try {
            process.once('SIGINT', () => handler('SIGINT'));
            process.once('SIGTERM', () => handler('SIGTERM'));
            this._hooksInstalled = true;
        } catch (_) {
            // Ignore (Windows prior to node 20 may not support SIGTERM fully)
        }
    }
}

module.exports = BticinoAuthentication;

/**
 * BTicino Proxy (renamed from BticinoDebugProxy)
 * Same functionality but with a controllable debug flag to silence logs by default.
 */
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs').promises;
// child_process.execSync removed from proxy (not used after refactor)
const http = require('http');
const https = require('https');
let selfsigned;
const B2C_BASE_DOMAIN = 'eliotclouduamprd.b2clogin.com';
const config = require('../config/config');
/**
 * BticinoProxy
 * Low-level reverse proxy that replicates the BTicino / Legrand mobile Azure AD B2C auth flow.
 * Responsibilities:
 *  - Reverse proxy B2C endpoints (policy based) and rewrite cookies for local debugging.
 *  - Intercept the custom-scheme redirect to capture the authorization code.
 *  - Optionally exchange the code for tokens (B2C + optional legacy Legrand token).
 *  - Remains silent unless instantiated with { debug: true }.
 *
 * Typical direct usage (generally prefer BticinoAuthentication):
 * @example
 * const BticinoProxy = require('./BticinoProxy');
 * const proxy = new BticinoProxy({ debug: true });
 * await proxy.start();
 * console.log('Auth URL:', proxy.generateAuthUrl());
 * // Open the URL in a browser, perform login; after redirect the code is available at proxy.capturedAuthCode
 */
class BticinoProxy {
  /**
   * Create a BticinoProxy instance.
   * @param {Object} [options]
   * @param {boolean} [options.debug=false] Enable debug logging
   * @param {string} [options.successPage] Optional HTML string to render after auth capture
   */
  constructor(options = {}) {
    this.debug = !!options.debug;
    this.app = express();
    this.server = null;
    // Allow passing a custom HTML success page (string). If provided, it will be used
    // to render the page shown after successful OAuth interception. The template may
    // include placeholders: {{code}}, {{state}}, {{stateValid}}, {{tokens}}.
    this.successPageTemplate = typeof options.successPage === 'string' ? options.successPage : null;
    // Allow overriding host/port via constructor options. If not provided, default to localhost:8080.
    let host = (typeof options.host === 'string' && options.host.length > 0) ? options.host : 'localhost';
    let port = (options.port !== undefined && options.port !== null) ? parseInt(options.port, 10) : 8080;
    if (!Number.isFinite(port) || port <= 0 || port > 65535) {
      this._warn(`Invalid port provided in constructor: '${options.port}' → using 8080`);
      port = 8080;
    }
    this.host = host;
    this.port = port;
    this.autoOpen = ['localhost', '127.0.0.1'].includes(this.host);
    // Build B2C configuration with the following precedence:
    // 1) explicit options.b2cConfig passed to the constructor
    // 2) centralized project config (`lib/config/config.js`)
    // Do NOT use hardcoded vendor defaults here; require callers to supply
    // the necessary values via config or options to avoid silent misconfiguration.
    const cfg = config || {};
    const defaultB2C = {
      tenant: cfg.B2C_TENANT,
      tenantId: cfg.B2C_TENANT_ID,
      policy: cfg.B2C_POLICY,
      clientId: cfg.B2C_CLIENT_ID,
      redirectUri: cfg.B2C_REDIRECT_URI,
      scope: cfg.B2C_SCOPE,
      resource: cfg.B2C_RESOURCE
    };
    // Merge options.b2cConfig on top of centralized config so callers can override any field
    this.b2cConfig = Object.assign({}, defaultB2C, options.b2cConfig || {});
    // Informative logs when using options or config (only in debug mode)
    if (this.debug) {
      if (options && options.b2cConfig) this._log('Using B2C settings from options.b2cConfig');
      else this._log('Using B2C settings from lib/config/config.js');
    }
    // Validate required configuration to avoid silent fallback to undefined values
    if (!this.b2cConfig.clientId || !this.b2cConfig.tenant) {
      throw new Error('Missing required B2C configuration: set via options.b2cConfig or lib/config/config.js (clientId, tenant)');
    }
    this.validStates = new Map();
    this.requestLog = [];
    this.capturedAuthCode = null;
    this.setup();
  }
  /**
   * Internal conditional logger.
   * @private
   */
  _log(...a) { if (this.debug) console.log(...a); }

  /**
   * Internal conditional warn logger.
   * @private
   */
  _warn(...a) { if (this.debug) console.warn(...a); }

  /**
   * Internal conditional error logger.
   * @private
   */
  _error(...a) { console.error(...a); }
  /**
   * Generate PKCE tuple (not currently required by observed mobile flow).
   * @returns {{codeVerifier:string,codeChallenge:string,codeChallengeMethod:'S256'}}
   */
  // generatePkce removed (not used in this library)
  /**
   * Internal setup of middlewares and proxy handler (idempotent for constructor usage).
   * Raw body capture + minimal logging + /oauth/callback + proxy middleware.
   * @private
   */
  setup() {
    this.app.use((req, res, next) => { if (['POST', 'PUT', 'PATCH'].includes(req.method)) { const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', () => { if (chunks.length) { req.rawBodyBuffer = Buffer.concat(chunks); req.rawBody = req.rawBodyBuffer.toString(); } next(); }); } else next(); });
    this.app.use((req, res, next) => { this.requestLog.push({ ts: Date.now(), m: req.method, u: req.url }); this._log(`${req.method} ${req.url}`); delete req.headers['x-forwarded-for']; delete req.headers['x-forwarded-proto']; delete req.headers['x-forwarded-host']; next(); });
    this.app.get('/', (req, res) => res.status(404).send('Minimal proxy mode: root UI removed.'));
    this.app.get('/oauth/callback', async (req, res) => { try { this._log('OAuth callback received!', req.query); const { code, state, error } = req.query; if (error) throw new Error(`OAuth error: ${error}`); if (!code) throw new Error('No authorization code received'); let stateValid = false; if (state && this.validStates.has(state)) { stateValid = true; this.validStates.delete(state); } this._log(stateValid ? 'State valid' : 'State missing/invalid'); this._log('Code:', code.substring(0, 30) + '...'); let tokens = null; try { tokens = await this.exchangeCodeForTokens(code); } catch (tokenErr) { this._error('Token exchange failed', tokenErr.message); } res.send(this.renderSuccessPage({ code, state, stateValid, tokens })); } catch (err) { this._error('OAuth callback error', err.message); res.status(500).send(`<html><body><h1>Auth Error</h1><pre>${err.message}</pre></body></html>`); } });
    this._log('Setting up B2C proxy middleware');
    const proxyOptions = {
      target: `https://${B2C_BASE_DOMAIN}`, changeOrigin: true, secure: false, logLevel: this.debug ? 'debug' : 'silent', followRedirects: false, cookieDomainRewrite: { '*': '' }, cookiePathRewrite: { '/': '/' }, onProxyReq: (proxyReq, req, res) => {
        this._log(`Proxying to B2C: ${req.method} ${req.url}`); proxyReq.setHeader('X-Debug-Proxy', 'BTicino-Proxy'); proxyReq.setHeader('User-Agent', 'Mozilla/5.0'); proxyReq.setHeader('Host', B2C_BASE_DOMAIN); if (proxyReq.getHeader('referer')) { const referer = proxyReq.getHeader('referer'); const localProxyPattern = new RegExp(`http://[^/]+:${this.port}/EliotClouduamprd\\.onmicrosoft\\.com`, 'g'); const fixedReferer = referer.replace(localProxyPattern, `https://${B2C_BASE_DOMAIN}/EliotClouduamprd.onmicrosoft.com`); proxyReq.setHeader('referer', fixedReferer); if (this.debug && fixedReferer !== referer) { this._log('Referer rewritten:', referer, '->', fixedReferer); } } if (proxyReq.getHeader('origin')) { const origin = proxyReq.getHeader('origin'); const localOriginPattern = new RegExp(`http://[^:]+:${this.port}`, 'g'); const fixedOrigin = origin.replace(localOriginPattern, `https://${B2C_BASE_DOMAIN}`); proxyReq.setHeader('origin', fixedOrigin); if (this.debug && fixedOrigin !== origin) { this._log('Origin rewritten:', origin, '->', fixedOrigin); } } if (req.method === 'POST') { this._log('POST -> raw forward'); if (this.debug) { this._log('POST Headers being sent to B2C:'); const headers = proxyReq.getHeaders(); Object.keys(headers).forEach(key => this._log(`  ${key}: ${headers[key]}`)); } if (req.rawBodyBuffer?.length) { proxyReq.setHeader('content-length', req.rawBodyBuffer.length); proxyReq.write(req.rawBodyBuffer); this._log(`RAW body ${req.rawBodyBuffer.length} bytes`); if (this.debug) this._log(`Body content: ${req.rawBodyBuffer.toString()}`); } }
      }, onProxyRes: (proxyRes, req, res) => { this._log(`${proxyRes.statusCode} ${req.url}`); if (proxyRes.headers['set-cookie']) { const cookies = Array.isArray(proxyRes.headers['set-cookie']) ? proxyRes.headers['set-cookie'] : [proxyRes.headers['set-cookie']]; proxyRes.headers['set-cookie'] = cookies.map(cookie => { let fixed = cookie.replace(/Domain=[^;]+;?\s*/gi, ''); fixed = fixed.replace(/;\s*Secure/gi, ''); fixed = fixed.replace(/;\s*SameSite=[^;]+/gi, ''); if (this.debug) this._log(`Cookie rewritten: ${cookie.substring(0, 80)}...`); return fixed; }); } if (this.debug && proxyRes.statusCode === 400) { this._log('400 Response headers:', proxyRes.headers); } if ([301, 302].includes(proxyRes.statusCode)) { const loc = proxyRes.headers.location; if (loc && loc.startsWith('com.legrandgroup.diy://oauth2redirect')) { const url = new URL(loc); const code = url.searchParams.get('code'); const state = url.searchParams.get('state'); if (code) { proxyRes.headers.location = `/oauth/callback?code=${code}&state=${state || ''}`; this.capturedAuthCode = { code, state, timestamp: new Date().toISOString(), originalUrl: loc }; this._log('Authorization code intercepted'); } } } }
      , onError: (err, req, res) => { this._error('Proxy error', err.message); res.status(500).send('<html><body>Proxy error</body></html>'); }
    };
    const bticinoProxy = createProxyMiddleware({ filter: (pathname) => pathname.startsWith('/EliotClouduamprd.onmicrosoft.com/'), ...proxyOptions });
    this._log('Creating B2C proxy middleware with filter and router');
    this.app.use(bticinoProxy);
    this._log('Applying B2C proxy to Express app');
  }
  /**
   * Exchange an authorization code for B2C tokens (no PKCE). Optionally fetch Legrand token.
   * @param {string} authCode Authorization code captured from redirect
   * @param {Object} [options] Additional options (reserved for future use)
   * @returns {Promise<Object>} Token result structure
   */
  async exchangeCodeForTokens(authCode, options = {}) {
    this._log('Exchanging authorization code for tokens');
    const tokenUrl = `https://${B2C_BASE_DOMAIN}/${this.b2cConfig.tenant}/oauth2/v2.0/token?p=${this.b2cConfig.policy}`;
    const data = {
      grant_type: 'authorization_code',
      client_id: this.b2cConfig.clientId,
      code: authCode,
      redirect_uri: this.b2cConfig.redirectUri,
      scope: this.b2cConfig.scope
    };
    const resp = await axios.post(tokenUrl, new URLSearchParams(data), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      validateStatus: s => true,
      timeout: 30000
    });
    if (resp.status !== 200) {
      throw new Error(`Token status ${resp.status}`);
    }
    const t = resp.data;
    const now = Date.now();
    return {
      b2cAccessToken: t.access_token,
      b2cRefreshToken: t.refresh_token || null,
      expiresIn: t.expires_in,
      tokenType: t.token_type || 'Bearer',
      receivedAt: new Date(now).toISOString(),
      expiresAt: t.expires_in ? new Date(now + t.expires_in * 1000).toISOString() : null
    };
  }
  /**
   * Refresh tokens using a refresh_token.
   * @param {string} refreshToken Existing B2C refresh token
   * @param {Object} [options] Additional options (reserved for future use)
   * @returns {Promise<Object>} Updated token structure
   */
  async refreshAccessToken(refreshToken, options = {}) {
    this._log('Refreshing access token');
    const tokenUrl = `https://${B2C_BASE_DOMAIN}/${this.b2cConfig.tenant}/oauth2/v2.0/token?p=${this.b2cConfig.policy}`;
    const body = {
      grant_type: 'refresh_token',
      client_id: this.b2cConfig.clientId,
      refresh_token: refreshToken,
      scope: this.b2cConfig.scope
    };
    const resp = await axios.post(tokenUrl, new URLSearchParams(body), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      validateStatus: s => true,
      timeout: 30000
    });
    if (resp.status !== 200) throw new Error('Refresh failed');
    const t = resp.data;
    const now = Date.now();
    return {
      b2cAccessToken: t.access_token,
      b2cRefreshToken: t.refresh_token || refreshToken,
      expiresIn: t.expires_in,
      tokenType: t.token_type || 'Bearer',
      receivedAt: new Date(now).toISOString(),
      expiresAt: t.expires_in ? new Date(now + t.expires_in * 1000).toISOString() : null
    };
  }

  /**
   * Save tokens to disk for debugging/inspection (async).
   * @param {Object} tokens Token object to save
   * @returns {Promise<void>}
   */
  // saveTokens removed (debug helper not used)

  /**
   * Start the proxy server. Resolves when listening. Automatically falls back
   * to HTTP if HTTPS generation fails.
   * @returns {Promise<void>}
   */
  async start() { return new Promise((resolve, reject) => { const useHttps = config.USE_HTTPS === '1'; const startServer = () => { const protocol = useHttps ? 'https' : 'http'; this._log(`🔍 BTicino Proxy running on ${protocol}://${this.host}:${this.port}`); resolve(); }; if (useHttps) { try { if (!selfsigned) selfsigned = require('selfsigned'); const attrs = [{ name: 'commonName', value: this.host }]; const pems = selfsigned.generate(attrs, { days: 1, algorithm: 'rsa', keySize: 2048 }); this.server = https.createServer({ key: pems.private, cert: pems.cert }, this.app).listen(this.port, this.host, startServer); } catch (e) { this._warn('HTTPS generation failed, fallback HTTP', e.message); this.server = this.app.listen(this.port, this.host, startServer); } } else { this.server = this.app.listen(this.port, this.host, startServer); } this.server.on('error', (err) => { if (err.code === 'EADDRINUSE') { this._warn(`Port ${this.port} busy, trying ${this.port + 1}`); this.port++; this.start().then(resolve).catch(reject); } else reject(err); }); }); }

  /**
   * Stop the proxy server if running.
   * @returns {void}
   */
  stop() { if (this.server) { this.server.close(); this._log('Proxy stopped'); } }

  /**
   * Open the proxy root in the system browser. Uses platform-specific
   * commands to open URLs.
   * @param {string} [protocol='http'] Protocol to use (http|https)
   */
  // openBrowser removed (library uses 'open' package where needed)
  /**
   * Render the success HTML page shown after the authorization code is intercepted.
   * If a custom template was provided via constructor option `successPage`, it will
   * be used and the following placeholders will be replaced: {{code}}, {{state}},
   * {{stateValid}} and {{tokens}} (tokens will be JSON-stringified).
   * Otherwise a small default HTML page is returned.
   * @param {{code?:string,state?:string,stateValid?:boolean,tokens?:Object}} args
   * @returns {string} HTML content
   */
  renderSuccessPage({ code, state, stateValid, tokens } = {}) {
    if (this.successPageTemplate) {
      let out = this.successPageTemplate;
      out = out.replace(/\{\{code\}\}/g, code || '');
      out = out.replace(/\{\{state\}\}/g, state || '');
      out = out.replace(/\{\{stateValid\}\}/g, String(!!stateValid));
      out = out.replace(/\{\{tokens\}\}/g, tokens ? JSON.stringify(tokens, null, 2) : '');
      return out;
    }
    return `<html><body><h1>Auth Code Captured</h1><pre>${code}</pre>${tokens ? '<p>Tokens obtained.</p>' : '<p>No tokens.</p>'}</body></html>`;
  }

  /**
   * Replace the success page template at runtime.
   * @param {string|null} html HTML template string or null to restore default
   */
  // setSuccessPage removed (success page template accepted via constructor)
}
module.exports = BticinoProxy;

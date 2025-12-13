/**
 * Bticino SIP client extracted from BticinoControls.js
 * Contains helper utilities and the `BticinoSipClient` class used to
 * perform SIP/TLS connections, REGISTER and MESSAGE requests to the
 * gateway. This module does not read certificates from disk; the caller
 * must provide client cert/key via the constructor `certs` parameter.
 */
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Utility: get local IP address
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip internal addresses and IPv6
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1'; // Fallback
}

// Utility: generate branch for SIP Via header
function generateBranch() {
  return 'z9hG4bK.' + crypto.randomBytes(8).toString('hex');
}

// Utility: generate Call-ID
function generateCallID() {
  return crypto.randomBytes(8).toString('hex');
}

// Utility: generate tag
function generateTag() {
  return crypto.randomBytes(8).toString('hex');
}

// Utility: calculate Digest MD5 response using HA1
function calculateDigestResponseWithHa1(ha1, method, uri, nonce, nc, cnonce, qop) {
  const ha2 = crypto.createHash('md5').update(`${method}:${uri}`).digest('hex');
  
  if (qop) {
    return crypto.createHash('md5')
      .update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
      .digest('hex');
  } else {
    return crypto.createHash('md5')
      .update(`${ha1}:${nonce}:${ha2}`)
      .digest('hex');
  }
}

// Utility: calculate HA1 = MD5(username:realm:password)
function calculateHa1(username, realm, password) {
  if (!username || !realm || !password) return null;
  const a1 = `${username}:${realm}:${password}`;
  return crypto.createHash('md5').update(a1).digest('hex');
}

// Build the JSON-RPC payload used to open the gate
function buildGateOpenPayload(gateId) {
  return JSON.stringify({
    id: Math.floor(Math.random() * 100000000).toString(),
    jsonrpc: '2.0',
    method: 'lock.setStatus',
    params: [{
      receiver: {
        plant: {
          coal: {
            id: gateId || null
          },
          id: null
        }
      },
      status: 'open'
    }]
  });
}

// Build a SIP MESSAGE request
function buildSipMessage(sipConfig, opts = {}) {
  const {
    method = 'MESSAGE',
    to = sipConfig && sipConfig.domain ? `sip:diy@${sipConfig.domain}` : 'sip:diy',
    from = sipConfig && sipConfig.domain && sipConfig.username ? `<sip:${sipConfig.username}@${sipConfig.domain}>` : '<sip:unknown>',
    tag = generateTag(),
    callId = generateCallID(),
    cseq = 20,
    branch = generateBranch(),
    body = '',
    contentType = 'text/plain',
    route = sipConfig && sipConfig.server ? `<sip:${sipConfig.server};transport=tls;lr>` : null,
    proxyAuth = null
  } = opts;

  const bodyLength = Buffer.byteLength(body, 'utf8');
  
  let message = `${method} ${to} SIP/2.0\r\n`;
  const localIP = (sipConfig && sipConfig.localIP) ? sipConfig.localIP : getLocalIP();
  const localPort = (sipConfig && sipConfig.localPort) ? sipConfig.localPort : 5060;
  message += `Via: SIP/2.0/TLS ${localIP}:${localPort};branch=${branch};rport\r\n`;
  message += `From: ${from};tag=${tag}\r\n`;
  message += `To: ${to}\r\n`;
  message += `CSeq: ${cseq} ${method}\r\n`;
  message += `Call-ID: ${callId}\r\n`;
  message += `Max-Forwards: 70\r\n`;
  if (route) message += `Route: ${route}\r\n`;
  message += `Supported: replaces, outbound, gruu, path\r\n`;
  message += `Date: ${new Date().toUTCString()}\r\n`;
  
  if (bodyLength > 0) {
    message += `Content-Type: ${contentType}\r\n`;
    message += `Content-Length: ${bodyLength}\r\n`;
  } else {
    message += `Content-Length: 0\r\n`;
  }
  
  const userAgent = (sipConfig && sipConfig.userAgent) ? sipConfig.userAgent : 'bticino-client/1.0';
  message += `User-Agent: ${userAgent}\r\n`;
  
  // Add Proxy-Authorization if present
  if (proxyAuth) {
    message += `Proxy-Authorization: ${proxyAuth}\r\n`;
  }
  
  message += `\r\n`;
  
  if (bodyLength > 0) {
    message += body;
  }
  
  return message;
}

// Build a SIP REGISTER request
function buildRegisterMessage(sipConfig, opts = {}) {
  const {
    branch = generateBranch(),
    callId = generateCallID(),
    tag = generateTag(),
    cseq = 1,
    expires = 600,
    proxyAuth = null
  } = opts;

  const localIP = (sipConfig && sipConfig.localIP) ? sipConfig.localIP : getLocalIP();
  const localPort = (sipConfig && sipConfig.localPort) ? sipConfig.localPort : 5060;
  const username = sipConfig && sipConfig.username ? sipConfig.username : 'unknown';
  const domain = sipConfig && sipConfig.domain ? sipConfig.domain : 'example.com';
  const userAgent = (sipConfig && sipConfig.userAgent) ? sipConfig.userAgent : 'bticino-client/1.0';

  const contact = `<sip:${username}@${localIP}:${localPort};transport=tls>`;

  let message = `REGISTER sip:${domain} SIP/2.0\r\n`;
  message += `Via: SIP/2.0/TLS ${localIP}:${localPort};branch=${branch};rport\r\n`;
  message += `From: <sip:${username}@${domain}>;tag=${tag}\r\n`;
  message += `To: <sip:${username}@${domain}>\r\n`;
  message += `Call-ID: ${callId}\r\n`;
  message += `CSeq: ${cseq} REGISTER\r\n`;
  message += `Contact: ${contact};expires=${expires}\r\n`;
  message += `Max-Forwards: 70\r\n`;
  message += `User-Agent: ${userAgent}\r\n`;
  message += `Supported: replaces, outbound, gruu, path\r\n`;
  
  if (proxyAuth) {
    message += `Proxy-Authorization: ${proxyAuth}\r\n`;
  }
  
  message += `Content-Length: 0\r\n\r\n`;
  
  return message;
}

// Simple parser to extract SIP response headers
function parseSipResponse(data) {
  const lines = data.toString().split('\r\n');
  const statusLine = lines[0];
  const headers = {};
  
  // Parse status
  const statusMatch = statusLine.match(/SIP\/2\.0 (\d+) (.+)/);
  if (statusMatch) {
    headers.statusCode = parseInt(statusMatch[1]);
    headers.statusText = statusMatch[2];
  }
  
  // Parse headers
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) break; // end of headers
    
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const name = line.substring(0, colonIndex).trim();
      const value = line.substring(colonIndex + 1).trim();
      headers[name.toLowerCase()] = value;
    }
  }
  
  return headers;
}

// Main class to manage SIP connection and messaging
class BticinoSipClient {
  /**
   * @param {Object} sipConfig - SIP configuration (server, port, domain, username, password, realm, localIP, localPort, userAgent)
   * @param {Object} deviceConfig - Device configuration (gateId, plantId, gatewayId)
   * @param {Object} [opts] - Optional flags (debug)
   * @param {Object} [certs] - { cert: string|Buffer, key: string|Buffer } client certificate and key for mTLS
   */
  /**
   * Create a SIP client instance.
   * @param {Object} sipConfig - SIP configuration (server, port, domain, username, password, realm, localIP, localPort, userAgent)
   * @param {string|null} gateId - Identifier of the gate device to control
   * @param {string|null} plantId - Plant identifier (optional)
   * @param {string|null} gatewayId - Gateway module identifier (optional)
   * @param {Object} [opts] - Options (e.g. `{ debug: true }`)
   * @param {Object} [certs] - Client certificate material: `{ cert: string|Buffer, key: string|Buffer }` for mTLS
   */
  constructor(sipConfig = {}, gateId = null, plantId = null, gatewayId = null, opts = {}, certs = {}) {
    this.sipConfig = Object.assign({}, sipConfig);
    this.gateId = gateId;
    this.plantId = plantId;
    this.gatewayId = gatewayId;
    this.opts = opts || {};
    this.certs = certs || {};
    this.socket = null;
    this.authenticated = false;
    this.authChallenge = null;
    this.registerTag = null;
    this.registerCallId = null;
    this.registerCSeq = 1;
    this._pendingResponse = null; // { resolve, reject, timer }
    // Logging helpers consistent with other modules
    this._log = (...a) => { if (this.opts && this.opts.debug) console.log(...a); };
    this._warn = (...a) => { if (this.opts && this.opts.debug) console.warn(...a); };
    this._error = (...a) => { if (this.opts && this.opts.debug) console.error(...a); };
  }

  connect() {
    return new Promise((resolve, reject) => {
      this._log(`Connecting to ${this.sipConfig.server}:${this.sipConfig.port}...`);
      
      // TLS options
      const tlsOptions = {
        host: this.sipConfig.server,
        port: this.sipConfig.port,
        rejectUnauthorized: false, // Accept self-signed certificates
        requestCert: false, // Do not request client certificate
      };

      // Client certificate/key MUST be provided via constructor certs parameter.
      // Do not read from disk here; caller must pass certs explicitly.
      if (this.certs && (this.certs.cert || this.certs.certPEM) && (this.certs.key || this.certs.privateKeyPem)) {
        tlsOptions.cert = this.certs.cert || this.certs.certPEM;
        tlsOptions.key = this.certs.key || this.certs.privateKeyPem;
        this._log('Using provided client certificate for mTLS');
      } else {
        this._error('ERROR: Client certificate/key not provided to BticinoSipClient');
        this._error('Caller must pass cert and key to the constructor');
        throw new Error('Client certificate/key not provided');
      }

      this.socket = tls.connect(tlsOptions, () => {
        this._log('TLS connection established');
        this._log('Cipher:', this.socket.getCipher().name);
        this._log('Protocol:', this.socket.getProtocol());
        resolve();
      });

      this.socket.on('data', (data) => {
        this.handleResponse(data);
      });

      this.socket.on('error', (err) => {
        this._error('Socket error:', err.message);
        reject(err);
      });

      this.socket.on('end', () => {
        this._log('Connection ended by server');
      });
    });
  }

  handleResponse(data) {
    const response = parseSipResponse(data);
    this._log(`\nSIP response: ${response.statusCode} ${response.statusText}`);
    
    // Handle 407 Proxy Authentication Required
    if (response.statusCode === 407) {
      this._log('Digest authentication required');
      
      // Extract parameters from Proxy-Authenticate header
      const authHeader = response['proxy-authenticate'];
      if (authHeader) {
        this._log('Proxy-Authenticate:', authHeader);
        
        // Parse Digest parameters
        const realm = authHeader.match(/realm="([^"]+)"/)?.[1];
        const nonce = authHeader.match(/nonce="([^"]+)"/)?.[1];
        const opaque = authHeader.match(/opaque="([^"]+)"/)?.[1];
        const algorithm = authHeader.match(/algorithm=(\w+)/)?.[1] || 'MD5';
        const qop = authHeader.match(/qop="([^"]+)"/)?.[1];
        
        this.authChallenge = { realm, nonce, opaque, algorithm, qop };
        this._log('Auth challenge:', this.authChallenge);
        
        // We have HA1 available; compute the response using HA1
        this._log('Using HA1 hash for authentication');
        
        // Resend the message with authentication
        this.sendAuthenticatedMessage();
      }
    }
    
    // Handle 200 OK
    if (response.statusCode === 200) {
      this._log('Message sent successfully');
      this.authenticated = true;
    }
    
    // Show full response for debugging
    this._log('Full response:');
    this._log(data.toString());
    // If there is a pending response promise and this is a final response (>=200), settle it
    try {
      // Treat 401/407 as auth-challenge responses that should NOT finalize the pending promise
      if (this._pendingResponse && typeof response.statusCode === 'number' && response.statusCode >= 200 && response.statusCode !== 401 && response.statusCode !== 407) {
        const pending = this._pendingResponse;
        this._pendingResponse = null;
        if (pending.timer) clearTimeout(pending.timer);
        if (response.statusCode === 200) {
          pending.resolve({ statusCode: 200, statusText: response.statusText, headers: response });
        } else {
          const err = new Error(`SIP request failed with status ${response.statusCode} ${response.statusText}`);
          err.code = response.statusCode;
          err.headers = response;
          pending.reject(err);
        }
      }
    } catch (e) {
      this._error('Error while settling pending SIP response promise:', e && e.message);
    }
  }

  sendAuthenticatedMessage() {
    if (!this.authChallenge) {
      this._error('No auth challenge available');
      return;
    }

    const { realm, nonce, opaque, qop } = this.authChallenge;
    const nc = '00000001';
    const cnonce = crypto.randomBytes(8).toString('hex');
    const uri = `sip:diy@${this.sipConfig.domain}`;
    const method = 'MESSAGE';
    const ha1 = calculateHa1(this.sipConfig.username, this.sipConfig.realm, this.sipConfig.password);

    this._log('HA1:', ha1);
    this._log('Realm:', realm);

    // Compute response using HA1
    const response = calculateDigestResponseWithHa1(
      ha1,
      method,
      uri,
      nonce,
      nc,
      cnonce,
      qop
    );
    
    const proxyAuth = `Digest realm="${realm}", nonce="${nonce}", algorithm=MD5, opaque="${opaque}", username="${this.sipConfig.username}", uri="${uri}", response="${response}", cnonce="${cnonce}", nc=${nc}, qop=${qop}`;
    
    this._log('Proxy-Authorization:', proxyAuth);
    
  const payload = buildGateOpenPayload(this.gateId);
    const finalMessage = buildSipMessage(this.sipConfig, { body: payload, contentType: 'text/plain', proxyAuth: proxyAuth });
    
    this.sendMessage(finalMessage);
  }

  sendMessage(message) {
    this._log('\nSending SIP message:');
    this._log('─'.repeat(80));
    this._log(message);
    this._log('─'.repeat(80));
    
    this.socket.write(message);
  }

  async register() {
    this._log('\nSending REGISTER...');
    
    this.registerTag = generateTag();
    this.registerCallId = generateCallID();
    
    const registerMsg = buildRegisterMessage(this.sipConfig, {
      tag: this.registerTag,
      callId: this.registerCallId,
      cseq: this.registerCSeq
    });
    
    this.sendMessage(registerMsg);
  }

  async sendGateOpenCommand() {
    this._log('\nSending gate open command...');
    
    const payload = buildGateOpenPayload(this.gateId);
    this._log('Payload:', payload);
    
    const messageMsg = buildSipMessage(this.sipConfig, {
      body: payload,
      contentType: 'text/plain'
    });
    
    this.sendMessage(messageMsg);

    // Create and return a promise that will resolve when a final SIP response is received.
    if (this._pendingResponse) {
      // If there's already a pending response, reject to avoid overlapping calls
      return Promise.reject(new Error('Another pending SIP request is in progress'));
    }

    return new Promise((resolve, reject) => {
      // Timeout in ms for waiting final response
      const TIMEOUT = (this.opts && this.opts.timeoutMs) ? this.opts.timeoutMs : 20000;
      const timer = setTimeout(() => {
        this._pendingResponse = null;
        const err = new Error('Timeout waiting for SIP response');
        err.code = 'ETIMEDOUT';
        reject(err);
      }, TIMEOUT);

      this._pendingResponse = { resolve, reject, timer };
    });
  }

  async disconnect() {
    if (this._closing) return;
    this._closing = true;

    this._log('Disconnecting SIP client...');

    // If there's a pending response promise, reject it so callers don't hang
    if (this._pendingResponse) {
      try {
        const pending = this._pendingResponse;
        this._pendingResponse = null;
        if (pending.timer) clearTimeout(pending.timer);
        const err = new Error('Connection closed');
        err.code = 'ECONNABORTED';
        pending.reject(err);
      } catch (e) {
        this._warn('Error while rejecting pending response during disconnect:', e && e.message ? e.message : e);
      }
    }

    return new Promise((resolve) => {
      try {
        // Remove listeners and destroy socket gracefully
        if (this.socket) {
          try { this.socket.removeAllListeners('data'); } catch (_) {}
          try { this.socket.removeAllListeners('error'); } catch (_) {}
          try { this.socket.removeAllListeners('end'); } catch (_) {}
        }

        // End the socket if possible
        try {
          if (this.socket && !this.socket.destroyed) {
            this.socket.end();
          }
        } catch (_) {}

        // Wait for 'close' event or fallback timeout
        const onClose = () => {
          cleanup();
          resolve();
        };

        const cleanup = () => {
          if (this._closeTimeout) { clearTimeout(this._closeTimeout); this._closeTimeout = null; }
        };

        if (this.socket && !this.socket.destroyed) {
          this.socket.once('close', onClose);
          // safety fallback
          this._closeTimeout = setTimeout(() => {
            try { this.socket.removeListener('close', onClose); } catch (_) {}
            try { this.socket.destroy(); } catch (_) {}
            resolve();
          }, 3000);
        } else {
          resolve();
        }
      } catch (e) {
        // best-effort resolve
        resolve();
      }
    });
  }
}

module.exports = {
  getLocalIP,
  generateBranch,
  generateCallID,
  generateTag,
  calculateDigestResponseWithHa1,
  calculateHa1,
  buildGateOpenPayload,
  buildSipMessage,
  buildRegisterMessage,
  parseSipResponse,
  BticinoSipClient
};

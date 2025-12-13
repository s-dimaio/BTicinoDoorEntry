/**
 * BTicino SIP Listener - Persistent SIP client for doorbell notifications
 * 
 * Establishes a persistent TLS connection to the BTicino SIP server and listens
 * for incoming INVITE requests (doorbell rings) and MESSAGE notifications.
 * 
 * Automatically handles:
 * - SIP REGISTER/re-register with digest authentication
 * - Keep-alive pings to maintain connection
 * - Automatic reconnection on disconnect
 * - Graceful certificate updates during active connections
 * 
 * @class BticinoSipListener
 * @extends EventEmitter
 * 
 * @param {Object} sipConfig - SIP configuration
 * @param {string} sipConfig.server - SIP server hostname
 * @param {number} sipConfig.port - SIP server port
 * @param {string} sipConfig.domain - SIP domain
 * @param {string} sipConfig.username - SIP username
 * @param {string} sipConfig.password - SIP password
 * @param {string} [sipConfig.realm] - Digest auth realm
 * @param {Object} certs - TLS certificates
 * @param {string} certs.certPEM - Certificate in PEM format
 * @param {string} certs.privateKeyPem - Private key in PEM format
 * @param {Object} [opts] - Options
 * @param {boolean} [opts.debug] - Enable debug logging
 * @param {boolean} [opts.keepAlive] - Enable keep-alive (default: true)
 * @param {boolean} [opts.autoReconnect] - Auto-reconnect on disconnect (default: true)
 * @param {number} [opts.keepAliveInterval] - Keep-alive interval in ms
 * @param {number} [opts.reconnectDelay] - Reconnect delay in ms
 * 
 * @emits connected - TLS connection established
 * @emits disconnected - Connection lost (may auto-reconnect)
 * @emits registered - SIP REGISTER successful
 * @emits invite - Incoming INVITE (doorbell ring): {timestamp, from, to, callId}
 * @emits message - Incoming MESSAGE: {from, to, body}
 * @emits certificatesUpdated - Certificates updated successfully
 * @emits certificateUpdateError - Failed to update certificates
 * @emits error - Error occurred: {message, code}
 */


const tls = require('tls');
const crypto = require('crypto');
const os = require('os');
const EventEmitter = require('events');
const config = require('../config/config');

// Default SIP configuration from central config
const DEFAULT_SIP_SERVER = config.SIP_SERVER;
const DEFAULT_SIP_PORT = config.SIP_PORT;
const DEFAULT_SIP_DOMAIN = config.SIP_DOMAIN;
const DEFAULT_KEEPALIVE_INTERVAL = config.SIP_KEEPALIVE_INTERVAL;
const DEFAULT_RECONNECT_DELAY = config.SIP_RECONNECT_DELAY;
const DEFAULT_REGISTER_EXPIRES = config.SIP_REGISTER_EXPIRES;

// ===== Utility Functions =====

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

function generateBranch() {
  return 'z9hG4bK.' + crypto.randomBytes(8).toString('hex');
}

function generateCallID() {
  return crypto.randomBytes(8).toString('hex');
}

function generateTag() {
  return crypto.randomBytes(8).toString('hex');
}

function calculateHa1(username, realm, password) {
  if (!username || !realm || !password) return null;
  return crypto.createHash('md5').update(`${username}:${realm}:${password}`).digest('hex');
}

function calculateDigestResponse(ha1, method, uri, nonce, nc, cnonce, qop) {
  const ha2 = crypto.createHash('md5').update(`${method}:${uri}`).digest('hex');
  
  if (qop) {
    return crypto.createHash('md5')
      .update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
      .digest('hex');
  }
  return crypto.createHash('md5').update(`${ha1}:${nonce}:${ha2}`).digest('hex');
}

// ===== SIP Message Builders =====

function buildRegisterMessage(sipConfig, opts = {}) {
  const {
    branch = generateBranch(),
    callId = generateCallID(),
    tag = generateTag(),
    cseq = 1,
    expires = DEFAULT_REGISTER_EXPIRES,
    proxyAuth = null
  } = opts;

  const localIP = sipConfig.localIP || getLocalIP();
  const localPort = sipConfig.localPort || 5060;
  const { username, domain, userAgent = 'BticinoSipListener/1.0' } = sipConfig;

  const contact = `<sip:${username}@${localIP}:${localPort};transport=tls>`;

  let msg = `REGISTER sip:${domain} SIP/2.0\r\n`;
  msg += `Via: SIP/2.0/TLS ${localIP}:${localPort};branch=${branch};rport\r\n`;
  msg += `From: <sip:${username}@${domain}>;tag=${tag}\r\n`;
  msg += `To: <sip:${username}@${domain}>\r\n`;
  msg += `Call-ID: ${callId}\r\n`;
  msg += `CSeq: ${cseq} REGISTER\r\n`;
  msg += `Contact: ${contact};expires=${expires}\r\n`;
  msg += `Max-Forwards: 70\r\n`;
  msg += `User-Agent: ${userAgent}\r\n`;
  msg += `Supported: replaces, outbound, gruu, path\r\n`;
  
  if (proxyAuth) {
    msg += `Proxy-Authorization: ${proxyAuth}\r\n`;
  }
  
  msg += `Content-Length: 0\r\n\r\n`;
  
  return msg;
}

function parseSipMessage(data) {
  const text = data.toString();
  const lines = text.split('\r\n');
  const firstLine = lines[0];
  
  const result = {
    raw: text,
    headers: {},
    body: ''
  };
  
  // Check if it's a request or response
  const responseMatch = firstLine.match(/^SIP\/2\.0 (\d+) (.+)$/);
  const requestMatch = firstLine.match(/^(\w+) (.+) SIP\/2\.0$/);
  
  if (responseMatch) {
    result.type = 'response';
    result.statusCode = parseInt(responseMatch[1]);
    result.statusText = responseMatch[2];
  } else if (requestMatch) {
    result.type = 'request';
    result.method = requestMatch[1];
    result.uri = requestMatch[2];
  } else {
    result.type = 'unknown';
  }
  
  // Parse headers
  let bodyStart = -1;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === '') {
      bodyStart = i + 1;
      break;
    }
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const name = line.substring(0, colonIndex).trim().toLowerCase();
      const value = line.substring(colonIndex + 1).trim();
      result.headers[name] = value;
    }
  }
  
  // Extract body
  if (bodyStart > 0 && bodyStart < lines.length) {
    result.body = lines.slice(bodyStart).join('\r\n');
  }
  
  return result;
}

function buildSipResponse(statusCode, statusText, originalMessage, opts = {}) {
  const { tag = generateTag() } = opts;
  
  let response = `SIP/2.0 ${statusCode} ${statusText}\r\n`;
  
  // Copy Via headers
  if (originalMessage.headers['via']) {
    response += `Via: ${originalMessage.headers['via']}\r\n`;
  }
  
  // Copy From
  if (originalMessage.headers['from']) {
    response += `From: ${originalMessage.headers['from']}\r\n`;
  }
  
  // Copy To (add tag if not present)
  if (originalMessage.headers['to']) {
    let to = originalMessage.headers['to'];
    if (!to.includes('tag=')) {
      to += `;tag=${tag}`;
    }
    response += `To: ${to}\r\n`;
  }
  
  // Copy Call-ID
  if (originalMessage.headers['call-id']) {
    response += `Call-ID: ${originalMessage.headers['call-id']}\r\n`;
  }
  
  // Copy CSeq
  if (originalMessage.headers['cseq']) {
    response += `CSeq: ${originalMessage.headers['cseq']}\r\n`;
  }
  
  response += `Content-Length: 0\r\n\r\n`;
  
  return response;
}

// ===== Main Listener Class =====

class BticinoSipListener extends EventEmitter {
  /**
   * Create a SIP listener instance for receiving incoming calls/messages.
   * 
   * @param {Object} sipConfig - SIP configuration
   * @param {string} [sipConfig.server] - SIP server hostname (default: from config.js)
   * @param {number} [sipConfig.port] - SIP server port (default: from config.js)
   * @param {string} [sipConfig.domain] - SIP domain (default: from config.js)
   * @param {string} sipConfig.username - SIP username
   * @param {string} sipConfig.password - SIP password
   * @param {string} [sipConfig.realm] - SIP realm (defaults to domain)
   * @param {string} [sipConfig.userAgent] - User agent string
   * @param {Object} certs - Client certificates for mTLS
   * @param {string} certs.certPEM - Client certificate PEM (or alias 'cert')
   * @param {string} certs.privateKeyPem - Private key PEM (or alias 'key')
   * @param {Object} [opts] - Options
   * @param {boolean} [opts.debug] - Enable debug logging
   * @param {boolean} [opts.keepAlive=true] - Re-register periodically
   * @param {boolean} [opts.autoReconnect=true] - Reconnect on disconnect
   * @param {number} [opts.keepAliveInterval] - Keep-alive interval (ms, default: from config.js)
   * @param {number} [opts.reconnectDelay] - Reconnect delay (ms, default: from config.js)
   */
  constructor(sipConfig, certs, opts = {}) {
    super();
    
    // Apply defaults from central config
    this.sipConfig = {
      server: DEFAULT_SIP_SERVER,
      port: DEFAULT_SIP_PORT,
      domain: DEFAULT_SIP_DOMAIN,
      ...sipConfig
    };
    
    // Support both naming conventions for certificates
    this.certs = {
      certPEM: certs.certPEM || certs.cert,
      privateKeyPem: certs.privateKeyPem || certs.key
    };
    
    this.opts = {
      debug: false,
      keepAlive: true,
      autoReconnect: true,
      keepAliveInterval: DEFAULT_KEEPALIVE_INTERVAL,
      reconnectDelay: DEFAULT_RECONNECT_DELAY,
      ...opts
    };
    
    // State
    this.socket = null;
    this.registered = false;
    this.authChallenge = null;
    this._closing = false;
    
    // REGISTER state
    this._registerTag = null;
    this._registerCallId = null;
    this._registerCSeq = 1;
    this._localTag = generateTag();
    
    // Timers
    this._keepAliveInterval = null;
    this._reconnectTimeout = null;
    
    // Logging
    this._log = (...args) => { if (this.opts.debug) console.log('[SipListener]', ...args); };
    this._warn = (...args) => { if (this.opts.debug) console.warn('[SipListener]', ...args); };
    this._error = (...args) => console.error('[SipListener]', ...args);
  }

  /**
   * Connect to the SIP server via TLS.
   * @returns {Promise<void>}
   */
  connect() {
    return new Promise((resolve, reject) => {
      if (this._closing) {
        return reject(new Error('Listener is closing'));
      }
      
      this._log(`Connecting to ${this.sipConfig.server}:${this.sipConfig.port}...`);
      
      const tlsOptions = {
        host: this.sipConfig.server,
        port: this.sipConfig.port,
        rejectUnauthorized: false,
        requestCert: false
      };

      // Client certificate for mTLS
      if (this.certs.certPEM && this.certs.privateKeyPem) {
        tlsOptions.cert = this.certs.certPEM;
        tlsOptions.key = this.certs.privateKeyPem;
        this._log('Using client certificate for mTLS');
      } else if (this.certs.cert && this.certs.key) {
        tlsOptions.cert = this.certs.cert;
        tlsOptions.key = this.certs.key;
        this._log('Using client certificate for mTLS');
      } else {
        return reject(new Error('Client certificate/key not provided'));
      }

      this.socket = tls.connect(tlsOptions, () => {
        this._log('TLS connection established');
        this._log('  Cipher:', this.socket.getCipher().name);
        this._log('  Protocol:', this.socket.getProtocol());
        this.emit('connected');
        resolve();
      });

      this.socket.on('data', (data) => this._handleData(data));
      
      this.socket.on('error', (err) => {
        this._error('Socket error:', err.message);
        this.emit('error', err);
        reject(err);
      });

      this.socket.on('end', () => {
        this._log('Connection ended by server');
      });

      this.socket.on('close', () => {
        this._log('Connection closed');
        this._stopKeepAlive();
        this.registered = false;
        this.emit('disconnected');
        
        if (this.opts.autoReconnect && !this._closing) {
          this._scheduleReconnect();
        }
      });
    });
  }

  /**
   * Send SIP REGISTER to the server.
   * @returns {Promise<void>}
   */
  async register() {
    this._log('Sending REGISTER...');
    
    this._registerTag = generateTag();
    this._registerCallId = generateCallID();
    this._registerCSeq = 1;
    
    const registerMsg = buildRegisterMessage(this.sipConfig, {
      tag: this._registerTag,
      callId: this._registerCallId,
      cseq: this._registerCSeq
    });
    
    this._sendRaw(registerMsg);
  }

  /**
   * Update certificates and gracefully restart the connection.
   * This will disconnect, update certs, and reconnect automatically.
   * 
   * @param {Object} newCerts - New certificates
   * @param {string} newCerts.cert - New certificate PEM
   * @param {string} newCerts.key - New private key PEM
   * @returns {Promise<void>}
   * @throws {Error} If certificates are invalid
   * 
   * @example
   * await listener.updateCertificates({
   *   cert: newCertPEM,
   *   key: newKeyPEM
   * });
   */
  async updateCertificates(newCerts) {
    if (!newCerts || typeof newCerts !== 'object') {
      throw new Error('Invalid newCerts: must be an object');
    }
    if (!newCerts.cert || typeof newCerts.cert !== 'string') {
      throw new Error('Invalid newCerts: missing or invalid cert');
    }
    if (!newCerts.key || typeof newCerts.key !== 'string') {
      throw new Error('Invalid newCerts: missing or invalid key');
    }

    this._log('Updating certificates and restarting connection...');
    
    // Store new certificates
    this.certs = {
      certPEM: newCerts.cert,
      privateKeyPem: newCerts.key
    };

    // If connected, perform graceful restart
    if (this.socket && !this.socket.destroyed) {
      const wasRegistered = this.registered;
      
      // Temporarily disable auto-reconnect to control the process
      const originalAutoReconnect = this.opts.autoReconnect;
      this.opts.autoReconnect = false;
      
      try {
        // Disconnect
        this._log('Disconnecting for certificate update...');
        await this.disconnect();
        
        // Small delay to ensure clean disconnection
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Reset closing flag to allow reconnection
        this._closing = false;
        
        // Re-enable auto-reconnect
        this.opts.autoReconnect = originalAutoReconnect;
        
        // Reconnect with new certificates
        this._log('Reconnecting with new certificates...');
        await this.connect();
        
        // Re-register if we were registered before
        if (wasRegistered) {
          this._log('Re-registering after certificate update...');
          await this.register();
        }
        
        this._log('Certificate update complete, connection restored');
        this.emit('certificatesUpdated', newCerts);
      } catch (err) {
        this._error('Certificate update failed:', err.message);
        this.emit('certificateUpdateError', err);
        throw err;
      }
    } else {
      this._log('Certificates updated (not connected)');
      this.emit('certificatesUpdated', newCerts);
    }
  }

  /**
   * Disconnect from the SIP server.
   * @returns {Promise<void>}
   */
  async disconnect() {
    if (this._closing) return;
    this._closing = true;
    
    this._log('Disconnecting...');
    this._stopKeepAlive();
    this._cancelReconnect();
    
    return new Promise((resolve) => {
      if (!this.socket || this.socket.destroyed) {
        return resolve();
      }
      
      const cleanup = () => {
        if (this._closeTimeout) {
          clearTimeout(this._closeTimeout);
          this._closeTimeout = null;
        }
      };
      
      this.socket.once('close', () => {
        cleanup();
        resolve();
      });
      
      // Safety timeout
      this._closeTimeout = setTimeout(() => {
        try { this.socket.destroy(); } catch (_) {}
        resolve();
      }, 3000);
      
      try {
        this.socket.end();
      } catch (_) {
        resolve();
      }
    });
  }

  // ===== Private Methods =====

  _handleData(data) {
    const message = parseSipMessage(data);
    
    this._log('Received:', message.type, message.method || message.statusCode);
    
    if (message.type === 'response') {
      this._handleResponse(message);
    } else if (message.type === 'request') {
      this._handleRequest(message);
    }
  }

  _handleResponse(message) {
    this._log(`Response: ${message.statusCode} ${message.statusText}`);
    
    // 401/407 - Authentication required
    if (message.statusCode === 401 || message.statusCode === 407) {
      const authHeader = message.headers['www-authenticate'] || message.headers['proxy-authenticate'];
      if (authHeader) {
        this.authChallenge = this._parseAuthChallenge(authHeader);
        this._log('Auth challenge received, sending authenticated REGISTER...');
        this._sendAuthenticatedRegister();
      }
      return;
    }
    
    // 200 OK for REGISTER
    if (message.statusCode === 200) {
      if (message.headers['cseq'] && message.headers['cseq'].includes('REGISTER')) {
        this._log('REGISTER successful');
        this.registered = true;
        this.emit('registered');
        
        if (this.opts.keepAlive) {
          this._startKeepAlive();
        }
      }
    }
  }

  _handleRequest(message) {
    this._log(`Request: ${message.method}`);
    
    switch (message.method) {
      case 'INVITE':
        this._handleInvite(message);
        break;
        
      case 'BYE':
      case 'CANCEL':
        this._sendResponse(200, 'OK', message);
        this._log(`${message.method} handled, sent 200 OK`);
        break;
        
      case 'OPTIONS':
        this._sendResponse(200, 'OK', message);
        this._log('OPTIONS ping, sent 200 OK');
        break;
        
      case 'MESSAGE':
        this._handleMessage(message);
        break;
        
      default:
        this._log(`Unhandled method: ${message.method}`);
    }
  }

  _handleInvite(message) {
    const callInfo = {
      method: 'INVITE',
      from: message.headers['from'],
      to: message.headers['to'],
      callId: message.headers['call-id'],
      timestamp: new Date().toISOString(),
      body: message.body,
      headers: message.headers,
      rawMessage: message.raw
    };
    
    // 🔔 Emit doorbell event!
    this.emit('invite', callInfo);
    
    // Send 180 Ringing
    this._sendResponse(180, 'Ringing', message);
    
    // After 2s, send 486 Busy Here (we're just listening, not answering)
    setTimeout(() => {
      this._sendResponse(486, 'Busy Here', message);
    }, 2000);
  }

  _handleMessage(message) {
    const msgInfo = {
      from: message.headers['from'],
      body: message.body,
      timestamp: new Date().toISOString(),
      headers: message.headers
    };
    
    this.emit('message', msgInfo);
    this._sendResponse(200, 'OK', message);
  }

  _sendResponse(statusCode, statusText, originalMessage) {
    const response = buildSipResponse(statusCode, statusText, originalMessage, { 
      tag: this._localTag 
    });
    this._sendRaw(response);
  }

  _sendRaw(message) {
    if (!this.socket || this.socket.destroyed) {
      this._error('Cannot send: socket not connected');
      return;
    }
    this._log('Sending:', message.split('\r\n')[0]);
    this.socket.write(message);
  }

  _sendAuthenticatedRegister() {
    if (!this.authChallenge) return;
    
    this._registerCSeq++;
    const { realm, nonce, opaque, qop } = this.authChallenge;
    const nc = '00000001';
    const cnonce = crypto.randomBytes(8).toString('hex');
    const uri = `sip:${this.sipConfig.domain}`;
    
    const ha1 = calculateHa1(
      this.sipConfig.username,
      this.sipConfig.realm || realm,
      this.sipConfig.password
    );
    
    const response = calculateDigestResponse(ha1, 'REGISTER', uri, nonce, nc, cnonce, qop);
    
    const proxyAuth = `Digest realm="${realm}", nonce="${nonce}", algorithm=MD5, ` +
      `opaque="${opaque}", username="${this.sipConfig.username}", uri="${uri}", ` +
      `response="${response}", cnonce="${cnonce}", nc=${nc}, qop=${qop}`;
    
    const registerMsg = buildRegisterMessage(this.sipConfig, {
      tag: this._registerTag,
      callId: this._registerCallId,
      cseq: this._registerCSeq,
      proxyAuth
    });
    
    this._sendRaw(registerMsg);
  }

  _parseAuthChallenge(header) {
    return {
      realm: header.match(/realm="([^"]+)"/)?.[1],
      nonce: header.match(/nonce="([^"]+)"/)?.[1],
      opaque: header.match(/opaque="([^"]+)"/)?.[1],
      algorithm: header.match(/algorithm=(\w+)/)?.[1] || 'MD5',
      qop: header.match(/qop="([^"]+)"/)?.[1]
    };
  }

  _startKeepAlive() {
    if (this._keepAliveInterval) return;
    
    this._keepAliveInterval = setInterval(() => {
      if (this.socket && !this.socket.destroyed && this.registered) {
        this._log('Keep-alive: re-registering...');
        this.register();
      }
    }, this.opts.keepAliveInterval);
    
    this._log(`Keep-alive started (${this.opts.keepAliveInterval / 1000}s interval)`);
  }

  _stopKeepAlive() {
    if (this._keepAliveInterval) {
      clearInterval(this._keepAliveInterval);
      this._keepAliveInterval = null;
      this._log('Keep-alive stopped');
    }
  }

  _scheduleReconnect() {
    if (this._reconnectTimeout || this._closing) return;
    
    this._log(`Reconnecting in ${this.opts.reconnectDelay / 1000}s...`);
    
    this._reconnectTimeout = setTimeout(async () => {
      this._reconnectTimeout = null;
      try {
        await this.connect();
        await this.register();
      } catch (err) {
        this._error('Reconnect failed:', err.message);
        this._scheduleReconnect();
      }
    }, this.opts.reconnectDelay);
  }

  _cancelReconnect() {
    if (this._reconnectTimeout) {
      clearTimeout(this._reconnectTimeout);
      this._reconnectTimeout = null;
    }
  }
}

module.exports = {
  BticinoSipListener,
  // Export utilities for testing
  parseSipMessage,
  buildSipResponse,
  buildRegisterMessage
};

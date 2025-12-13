/**
 * BTicino Gate Opener - SIP MESSAGE implementation
 *
 * High-level functions for opening gates/doors via SIP MESSAGE with JSON-RPC 2.0 payload.
 * Replicates the gate-open command used by the official Door Entry mobile app.
 *
 * Requirements:
 * - Valid TLS client certificate (from certificate provisioning)
 * - SIP credentials (username and password from device registration)
 * - Network access to the BTicino SIP server at vdesip.bs.iotleg.com:5228
 */


const fs = require('fs');
const path = require('path');
const config = require('../config/config');

// Extracted SIP client and helpers
const {
  getLocalIP,
  buildGateOpenPayload,
  buildSipMessage,
  calculateHa1,
  BticinoSipClient
} = require('./BticinoSipClient.js');

// BticinoSipClient and helpers were moved to lib/BticinoSipClient.js

/**
 * Open a gate or door using SIP MESSAGE with JSON-RPC 2.0 protocol.
 *
 * Sends a JSON-RPC command to activate a door opener (typically an electric gate/buzzer)
 * at a specified plant location. This function must be called after device registration
 * and certificate provisioning.
 *
 * Authentication is performed using mTLS (client certificate + private key) and SIP digest authentication.
 * The SIP MESSAGE payload contains a JSON-RPC 2.0 request to the door opening service.
 *
 * @async
 * @param {string} gateId - Device ID of the gate/door opener to activate
 * @param {string} plantId - Plant UUID where the gate is located
 * @param {string|Buffer} cert - TLS client certificate in PEM format
 * @param {string|Buffer} key - TLS private key in PEM format
 * @param {Object} sipAccount - SIP account details
 * @param {string} sipAccount.sipUri - SIP URI (e.g., "user_clientId@gateway.bs.iotleg.com")
 * @param {string} sipAccount.sipPassword - SIP password for digest authentication
 * @param {string} [sipAccount.domain] - SIP domain (extracted from sipUri if not provided)
 * @param {string} [sipAccount.username] - SIP username (extracted from sipUri if not provided)
 * @param {string} [sipAccount.userOid] - User OID for constructing SIP username
 * @param {string} [sipAccount.clientId] - Client ID for constructing SIP username
 * @param {Object} [opts] - Options
 * @param {boolean} [opts.debug] - Enable debug logging (default: false)
 * @param {number} [opts.timeout] - Connection timeout in milliseconds (default: 30000)
 * @returns {Promise<Object>} Server response containing operation result
 * @throws {Error} If connection fails, credentials are invalid, or door opening fails
 * 
 * @example
 * // Open a gate after device registration
 * const result = await openGate(
 *   'gate_123',           // gateId
 *   'plant_abc',          // plantId
 *   certPEM,              // certificate
 *   keyPEM,               // private key
 *   sipAccount,           // from device registration
 *   { debug: true }
 * );
 * console.log('Gate opened:', result);
 */
async function openGate(gateId, plantId, cert, key, sipAccount, opts = {}) {
  const _log = (...a) => console.log(...a);
  const _warn = (...a) => console.warn(...a);
  const _error = (...a) => console.error(...a);

  _log('BTicino Gate Opener - SIP Implementation\n');

  // Minimal validation: gateId required. gatewayId and plantId are optional
  // and may be derived from the provided `sipAccount` when possible.
  if (!gateId) throw new Error('gateId (first parameter) is required');

  // cert and key must be provided separately
  if (!cert || !key) {
    throw new Error('certificate and private key parameters are required');
  }

  if (!sipAccount || typeof sipAccount !== 'object') {
    throw new Error('sipAccount (fifth parameter) is required and must be an object');
  }

  // Build sipConfig from sipAccount
  const sipUri = sipAccount.sipUri || '';
  const domain = (sipUri.split('@')[1] || sipAccount.domain || '').trim();
  const server = config.SIP_SERVER;
  const port = config.SIP_PORT;
  const username = sipAccount.userOid ? `${sipAccount.userOid}_${sipAccount.clientId}` : (sipAccount.username || sipAccount.user);
  const password = sipAccount.sipPassword || sipAccount.password;
  const realm = domain || undefined;

  const sipConfig = {
    server,
    port,
    domain,
    username,
    password,
    realm,
    //localIP: getLocalIP(),
    //localPort: 5060,
    //userAgent: 'bticino-client/1.0'
  };

  let gatewayId;

  if (domain) {
    const maybe = domain.split('.bs.')[0];
    if (maybe) {
      gatewayId = maybe;
    }else{
      throw new Error('gatewayId is required and could not be derived from sipAccount data');
    }
  }else{
    throw new Error('domain is missing from sipAccount.sipUri; cannot derive gatewayId');
  }
  

  // Create client passing gateId, plantId, gatewayId directly
  const certsParam = { cert, key };
  const client = new BticinoSipClient(sipConfig, gateId, plantId, gatewayId, { debug: !!opts.debug }, certsParam);
  try {
    // Connect to the server
    await client.connect();

    // Wait a bit to observe responses
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Send the MESSAGE command directly (no REGISTER).
    // The server may reply with 407 if authentication is required.
    client._log('\nAttempting to send gate open command...');
    await client.sendGateOpenCommand();

    // Wait for response and authentication handling
    await new Promise(resolve => setTimeout(resolve, 5000));

  } catch (err) {
    _error('Error:', err && err.message ? err.message : err);
    _error(err && err.stack ? err.stack : err);
    // Re-throw so callers can handle errors programmatically
    throw err;
  } finally {
    // ALWAYS try to close the SIP client connection (best-effort)
    try {
      if (client && typeof client.disconnect === 'function') {
        // call and await disconnect; swallow secondary errors to avoid masking the original error
        await client.disconnect().catch(() => {});
        if (client._log) client._log('\nSIP client disconnected (finally)');
      }
    } catch (e) {
      // ignore
    }
  }
}

// (No direct-run behavior) This module exports functions only; callers must invoke `openGate` explicitly.

module.exports = { BticinoSipClient, buildGateOpenPayload, buildSipMessage, calculateHa1, openGate };

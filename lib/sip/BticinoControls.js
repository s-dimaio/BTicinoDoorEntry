/**
 * BTicino Gate Opener - SIP MESSAGE Implementation
 *
 * This script replicates the gate-open command used by the Door Entry app
 * by sending a SIP MESSAGE with a JSON-RPC 2.0 payload to the BTicino server.
 *
 * Requirements:
 * - TLS client certificate (extracted from the mobile app)
 * - SIP credentials (username/password or digest auth)
 * - TLS connection to the SIP server at vdesip.bs.iotleg.com:5228
 */

const fs = require('fs');
const path = require('path');

// Extracted SIP client and helpers
const {
  getLocalIP,
  buildGateOpenPayload,
  buildSipMessage,
  calculateHa1,
  BticinoSipClient
} = require('./BticinoSipClient.js');

// BticinoSipClient and helpers were moved to lib/BticinoSipClient.js

// Main
/**
 * Main runner for the SIP gate opener.
 *
 * New preferred signature:
 *   openGate(gateId, plantId, cert, key, sipAccount, opts)
 *
 * Where `sipAccount` is the full SIP account object (see `token/sip_account.json`).
 * The function constructs the `sipConfig` internally from the provided
 * `sipAccount` and the supplied identifiers.
 *
 * @param {string} gateId Identifier of the gate device to open
 * @param {string} plantId Plant identifier
 * @param {string|Buffer} cert Certificate PEM (string or Buffer)
 * @param {string|Buffer} key Private key PEM (string or Buffer)
 * @param {Object} sipAccount SIP account object (as returned by the API / token file)
 * @param {Object} [opts] Options (e.g. { debug: true })
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
  const server = 'vdesip.bs.iotleg.com';
  const port = 5228;
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

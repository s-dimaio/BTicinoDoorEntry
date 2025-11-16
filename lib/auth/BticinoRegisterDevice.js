// Lightweight module: no filesystem operations required here (sip id persistence removed;
// consumers/auth are responsible for storing sipClientId)
const BticinoCertificates = require('../certs/BticinoCertificates');
const EventEmitter = require('events');

/**
 * BticinoRegisterDevice
 * Run the "first connection" / device registration sequence observed in the
 * mobile app onboarding flow. This implementation performs the POSTs required
 * to register a device (no dry-run behavior). Callers must ensure they want
 * to perform server-side changes before invoking this function.
 *
 * @param {Object} auth BticinoAuthentication instance (must be authenticated)
 * @param {Object} api BticinoApiClient instance bound to the auth
 * @param {Object} [options]
 * @param {string} [options.plantId] Plant UUID to target (required if `gatewayId` not provided)
 * @param {string} [options.gatewayId] Gateway module UUID to target (optional; may be inferred from `plantId`)
 * @param {string} [options.clientName] Name under which the SIP device will be registered (used when creating a new SIP account)
 * @param {boolean} [options.force=false] kept for backward compatibility
 * @param {boolean} [options.forceCertificates=false] When true, force certificate provisioning even if registration didn't happen
 * @param {boolean} [options.debug=false] Enable extra logging
 * @param {EventEmitter} [options.emitter] Optional EventEmitter to receive 'registered' and 'certificatesCreated' events
 * @returns {Promise<Object>} Execution result summary
 */
async function BticinoRegisterDevice(auth, api, options = {}) {
  const opts = Object.assign({ force: false, debug: false }, options);
  // Use provided emitter or create one. Emit 'step', 'registered', 'certificatesCreated' events.
  const emitter = opts.emitter || new EventEmitter();

  // Logging helpers (match pattern used in BticinoAuthentication/BticinoProxy)
  const _tag = '[RegisterDevice]';
  /**
   * Conditional logger (internal).
   * @private
   */
  function _log(...a) { if (opts.debug) console.log(_tag, ...a); }

  /**
   * Conditional warn logger (internal).
   * @private
   */
  function _warn(...a) { if (opts.debug) console.warn(_tag, ...a); }

  /**
   * Internal error logger — always log errors to stderr.
   * Keeping a dedicated method allows consistent formatting and future hooks.
   * @private
   */
  function _error(...a) { console.error(_tag, ...a); }

  //const base = api.base || 'https://api.developer.legrand.com';
  // Minimal summary returned at the end
  let prov = null;

  // const appId = auth?.proxy?.b2cConfig?.clientId;
  // Note: ToU/Privacy/Consents calls intentionally omitted - not required for SIP registration

  let gatewayId = opts.gatewayId || null;
  let plantId = opts.plantId || null;

  // Track whether a new SIP registration was performed during this run
  let registrationHappened = false;

  if (gatewayId) {
    if (!plantId && Array.isArray(modules) && modules.length > 0) {
      const match = modules.find(m => m && (m.id === gatewayId || m.moduleId === gatewayId || m.gatewayId === gatewayId));
      if (match) plantId = match.plantId || match.plant_id || plantId;
    }
    if (!plantId) throw new Error('gatewayId provided but plantId is missing and could not be inferred');
  } else {
    // Require plantId and use API helper to obtain gateway module id
    if (!plantId) {
      throw new Error('plantId is required when gatewayId is not provided');
    }
    try {
      const gwFromApi = await api.getGatewayModuleId(plantId);
      if (!gwFromApi) {
        throw new Error(`No gateway module found for plantId ${plantId}`);
      }
      gatewayId = gwFromApi;
    } catch (e) {
      throw new Error(`Failed determining gatewayId via API: ${e && e.message ? e.message : e}`);
    }
  }

  _log('Gateway ID:', gatewayId);
  _log('Plant ID:', plantId);

  if (gatewayId) {
    // Fetch SIP accounts
    let sipAccounts = [];
    try {
      sipAccounts = await api.getSipAccounts(gatewayId) || [];
      _log('SIP accounts fetched...');
    } catch (err) {
      _error('Failed fetching SIP accounts:', err && err.message ? err.message : err);
      sipAccounts = [];
    }

    const sipClientId = (typeof api.getSipClientId === 'function') ? api.getSipClientId() : api.sipClientId;
    _log('Using SIP Client ID:', sipClientId);

    const existing = sipAccounts.find(acc => String(acc.clientId) === String(sipClientId));
    if (existing) {
      _log('SIP account with our clientId already exists, skipping registration');
    } else {
      // Always execute registration
      _log('Executing SIP account registration');
      try {
        const res = await api.registerSipAccount(gatewayId, { clientId: sipClientId, clientName: opts.clientName || 'first-connection' });
        // Persistence removed: do not save sipClientId to auth internals here.
        // Mark that registration happened for provisioning decision
        registrationHappened = true;
        // Emit registered event
        try {
          emitter.emit('registered', { gatewayId, sipClientId, result: res });
        } catch (e) {
          _error('Failed emitting registered event:', e && e.message);
        }
      } catch (err) {
        _error('RegisterSip failed:', err && err.message ? err.message : err);
        // Re-throw the error to propagate it to the caller
        throw new Error(`SIP registration failed: ${err && err.message ? err.message : err}`);
      }
    }
  } else {
    // missing gatewayId: nothing to do
  }

  //await safeStep('CACerts', async () => api.getCACertificates());
  _log('Fetching CA certificates step skipped...', (gatewayId && plantId));

  if (gatewayId && plantId) {
    try {
      // Try to fetch plant details from API to obtain ownerEmail/ownerId/name/type/country
      // Fetch plant info
      let plantInfo = null;
      try {
        plantInfo = await api.getPlant(plantId);
      } catch (err) {
        if (opts.debug) console.error('Failed fetching plant info:', err && err.message ? err.message : err);
      }
      // API may return { plant: { ... } } or the plant object directly
      if (plantInfo && plantInfo.plant) plantInfo = plantInfo.plant;
      if (plantInfo) {
        const sipClientId = (typeof api.getSipClientId === 'function') ? api.getSipClientId() : api.sipClientId;
        // Only provision certificate when a new SIP registration occurred OR when caller explicitly forces certificates
        // Use explicit per-call option `opts.forceCertificates` only.
        const shouldProvision = registrationHappened || (opts && opts.forceCertificates === true);
        if (!shouldProvision) {
          // skipping provisioning
          _log('Skipping certificate provisioning (no registration happened and forceCertificates not set)');
        } else {
          _log('Starting certificate provisioning for device', sipClientId);
          prov = await BticinoCertificates.provisionCertificate(api, {
            ownerId: plantInfo.ownerId,
            ownerEmail: plantInfo.ownerEmail,
            gatewayId: gatewayId,
            plantId: plantId,
            plantName: plantInfo.name,
            deviceId: sipClientId,
            type: plantInfo.type,
            country: plantInfo.country || 'it',
            debug: opts.debug
          });

          // prov contains { provRes, privateKeyPem, csr }
          // Emit certificatesCreated event with cert and private key so callers can persist them
          try {
            emitter.emit('certificatesCreated', { gatewayId, plantId, certPEM: prov.certPEM, privateKeyPem: prov.privateKeyPem, provRes: prov.provRes, csr: prov.csr, prov });
          } catch (_) { }
        }
      }


    } catch (e) {
      // provisioning failed; emit nothing here (caller can observe thrown error)
      throw e;
    }
  } else {
    // missing gatewayId or plantId: nothing to do
  }

  return { registrationHappened, provisioned: prov ? true : false, prov };
}

module.exports = { BticinoRegisterDevice };

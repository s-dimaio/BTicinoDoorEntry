const path = require('path');
const fs = require('fs');
const BticinoAuthentication = require('../lib/auth/BticinoAuthentication');

// Example: authenticate and persist tokens + sipClientId externally
// - Listens for 'tokenCreated' and saves tokens to examples/token_cache.json
// - Listens for 'deviceRegistered' and saves sipClientId to examples/sip_account.json

const EX_DIR = __dirname;
// Keep example artifacts inside examples/ for easy discovery
const TOKENS_PATH = path.join(EX_DIR, 'token_cache.json');
const SIP_PATH = path.join(EX_DIR, 'sip_account.json');
const CERT_BUNDLE_PATH = path.join(EX_DIR, 'client-certs.json');

function saveJson(filePath, payload) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8');
    console.log('Saved:', filePath);
  } catch (e) {
    console.error('Failed saving', filePath, e && e.message);
  }
}

function loadJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.warn('Failed loading', filePath, e && e.message);
    return null;
  }
}

async function main() {
  const initialTokens = loadJson(TOKENS_PATH);
  const existingSip = loadJson(SIP_PATH);
  const sipClientId = existingSip && existingSip.sipClientId ? String(existingSip.sipClientId) : undefined;

  const auth = new BticinoAuthentication({
    autoOpenBrowser: true,
    debug: true,
    initialTokens: initialTokens,
    sipClientId: sipClientId
  });

  // Persist tokens whenever the library emits them
  auth.on('tokenCreated', (tokens, meta) => {
    try {
      // tokens is an enriched token object; persist what you need
      saveJson(TOKENS_PATH, tokens);
      console.log('tokenCreated event — tokens saved. meta=', meta || null);
    } catch (e) { console.error('tokenCreated handler error:', e && e.message); }
  });

  // Persist sipClientId and any SIP account info when device registration completes
  auth.on('deviceRegistered', async (payload) => {
    try {
      if (!payload) return;
      // The payload typically contains sipClientId and other registration metadata
      const out = { storedAt: new Date().toISOString(), payload };
      saveJson(SIP_PATH, out);
      console.log('deviceRegistered event — sip account saved to', SIP_PATH);
    } catch (e) { console.error('deviceRegistered handler error:', e && e.message); }
  });

  // Persist certificates created by the register-device sequence into the examples/ folder (JSON bundle)
  auth.on('certificatesCreated', (info) => {
    try {
      // Support both old payload shape (top-level `certPEM`/`privateKeyPem`)
      // and the new shape where the full provisioning object is under `info.prov`.
      const prov = (info && info.prov) ? info.prov : info;
      if (!prov) return;
      const certPEM = prov.certPEM || prov.cert || null;
      const privateKeyPem = prov.privateKeyPem || prov.privateKey || null;
      if (!certPEM || !privateKeyPem) return;
      // Save a JSON bundle inside examples/ using the previous keys `cert` and `key`
      const bundle = { cert: certPEM, key: privateKeyPem };
      fs.writeFileSync(CERT_BUNDLE_PATH, JSON.stringify(bundle, null, 2), 'utf8');
      console.log('certificatesCreated — saved JSON bundle to examples/');
    } catch (e) { console.error('certificatesCreated handler error:', e && e.message); }
  });

  // Start the auth flow (this will attempt to use initial tokens, otherwise open browser)
  try {
    const { tokens } = await auth.authenticate();
    if (tokens) console.log('Authentication finished. Token expiresAt:', tokens.expiresAt);

    // Example: create API client and optionally run registerDevice()
    const api = auth.createApiClient({ debug: true });
    const plants = await api.getPlants();
    const plant = Array.isArray(plants) && plants.length > 0 ? plants[0] : null;
    const plantId = plant ? (plant.id || plant.plantId || null) : null;

    // Choose synchronous or asynchronous registration
    // Synchronous (await completion):
    try {
      console.log('Starting synchronous registerDevice() (awaiting result)...');
      const res = await auth.registerDevice({ plantId, debug: true, async: false });
      console.log('registerDevice result:', res);
    } catch (e) {
      console.error('registerDevice (sync) failed:', e && e.message);
    }

    // Asynchronous (fire-and-forget):
    try {
      console.log('Starting asynchronous registerDevice() (background)...');
      const p = auth.registerDevice({ plantId, debug: true, async: true });
      // Optionally observe the promise
      p.then(r => console.log('Background registerDevice finished:', r)).catch(err => console.error('Background registerDevice error:', err && err.message));
    } catch (e) {
      console.error('registerDevice (async) start failed:', e && e.message);
    }
  } catch (e) {
    console.error('Authentication failed:', e && e.message);
  }
}

if (require.main === module) main().catch(err => console.error(err && err.stack));

module.exports = { main };

const path = require('path');
const fs = require('fs');
const BticinoAuthentication = require('../lib/auth/BticinoAuthentication');
const BticinoControls = require('../lib/sip/BticinoControls');

// Example: start from saved tokens, sip account and certificate bundle and open a gate
// Expects the following files to exist in the examples/ folder:
// - examples/token_cache.json
// - examples/sip_account.json
// - examples/client-certs.json  (or client-cert.pem + client-key.pem)

const TOKENS_PATH = path.join(__dirname, 'token_cache.json');
const SIP_PATH = path.join(__dirname, 'sip_account.json');
const CERT_BUNDLE_PATH = path.join(__dirname, 'client-certs.json');
const CERT_PEM_PATH = path.join(__dirname, 'client-cert.pem');
const KEY_PEM_PATH = path.join(__dirname, 'client-key.pem');

function loadJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) { return null; }
}

function loadCertBundle() {
  if (!fs.existsSync(CERT_BUNDLE_PATH)) return null;
  try {
    const raw = fs.readFileSync(CERT_BUNDLE_PATH, 'utf8');
    const data = JSON.parse(raw);
    if (data && data.cert && data.key) return { cert: data.cert, key: data.key };
  } catch (e) { /* ignore */ }
  return null;
}

async function main() {
  const tokens = loadJson(TOKENS_PATH);
  const sipAccountRaw = loadJson(SIP_PATH);
  const certs = loadCertBundle();

  if (!tokens) return console.error('Token file not found at', TOKENS_PATH);
  if (!sipAccountRaw) return console.error('SIP account file not found at', SIP_PATH);
  if (!certs) return console.error('Certificate bundle not found. Expected JSON bundle or PEM files under ./certs');

  // sipAccount may be stored as { payload } or direct; try to be tolerant
  const sipAccount = sipAccountRaw.result || sipAccountRaw.payload || sipAccountRaw || null;
  if (!sipAccount) return console.error('Could not derive SIP account object from', SIP_PATH);

  // If possible, get plantId from the saved SIP account, otherwise user must edit below
  const plantId = sipAccount.plantId || sipAccount.plant || null;
  const gateId = sipAccount.gateId || sipAccount.gate || null;

  const auth = new BticinoAuthentication({
    autoOpenBrowser: false,
    debug: false,
    initialTokens: tokens,
    sipClientId: sipAccount.clientId || sipAccount.sipClientId || null
  });

  // Ensure token refresh scheduling and internal state are initialized
  try {
    const { tokens: liveTokens } = await auth.authenticate();
    console.log('Authenticated using saved tokens; expiresAt =', liveTokens && liveTokens.expiresAt);
  } catch (e) {
    console.error('Failed to initialize authentication with saved tokens:', e && e.message);
    return;
  }

  // Use plantId/gateId from SIP account where available. If not present, edit variables below.
  const chosenPlantId = plantId || '<PUT_YOUR_PLANT_ID_HERE>';
  const chosenGateId = gateId || '<PUT_YOUR_GATE_ID_HERE>';

  console.log('Attempting to open gate', chosenGateId, 'for plant', chosenPlantId);

  try {
    await BticinoControls.openGate(chosenGateId, chosenPlantId, certs.cert, certs.key, sipAccount, { debug: false });
    console.log('✅ Gate opened successfully');
  } catch (err) {
    console.error('❌ Failed to open gate:', err && err.message ? err.message : err);
  }
}

if (require.main === module) main().catch(err => console.error(err && err.stack));

module.exports = { main };

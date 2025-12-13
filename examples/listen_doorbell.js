/**
 * Example: Simple Doorbell Listener (Integrated Version)
 * 
 * Demonstrates how to set up a persistent SIP listener for doorbell notifications
 * using the integrated factory method (createSipListener) in BticinoAuthentication.
 * 
 * This example shows:
 * - Loading saved authentication tokens and credentials
 * - Creating a SIP listener through the factory method
 * - Handling doorbell events (INVITE)
 * - Managing connection lifecycle and error recovery
 * - Automatic certificate refresh without service interruption
 * 
 * Prerequisites:
 * 1. Run examples/auth_and_save.js first to generate credential files
 * 2. These files must exist in examples/ directory:
 *    - token_cache.json      (OAuth tokens)
 *    - sip_account.json      (SIP credentials)
 *    - client-certs.json     (TLS certificates)
 * 
 * All events are centralized through the auth object using the 'sip:' prefix,
 * providing a unified event interface for the application.
 * 
 * Run with: node examples/listen_doorbell.js
 * (Press Ctrl+C to exit)
 */


const fs = require('fs');
const path = require('path');
const { BticinoAuthentication } = require('../index');

// File paths
const TOKEN_CACHE = path.join(__dirname, 'token_cache.json');
const SIP_ACCOUNT = path.join(__dirname, 'sip_account.json');
const CERTS = path.join(__dirname, 'client-certs.json');

async function main() {
  console.log('🔔 BTicino Doorbell Listener (Integrated)\n');

  // 1. Check files exist
  if (!fs.existsSync(TOKEN_CACHE) || !fs.existsSync(SIP_ACCOUNT) || !fs.existsSync(CERTS)) {
    console.error('❌ Missing credential files!');
    console.log('Run: node examples/auth_and_save.js\n');
    process.exit(1);
  }

  // 2. Load credentials
  console.log('📂 Loading credentials...');
  const tokens = JSON.parse(fs.readFileSync(TOKEN_CACHE));
  let sipAccount = JSON.parse(fs.readFileSync(SIP_ACCOUNT));
  const certs = JSON.parse(fs.readFileSync(CERTS));
  
  // Handle both direct format and wrapped format from auth_and_save.js
  if (sipAccount.payload && sipAccount.payload.result) {
    sipAccount = {
      ...sipAccount.payload.result,
      plantId: sipAccount.payload.plantId || sipAccount.payload.result.plantId,
      gatewayId: sipAccount.payload.gatewayId
    };
  }
  console.log('✅ Loaded:', sipAccount.sipUri);

  // 3. Initialize authentication
  console.log('\n🔐 Authenticating...');
  const auth = new BticinoAuthentication({
    initialTokens: tokens,
    sipClientId: sipAccount.clientId,
    debug: false
  });

  await auth.authenticate();
  console.log('✅ Authenticated');

  // 4. Check if listener already exists (prevent duplications)
  let listener;
  if (auth.hasSipListener()) {
    console.log('\n📞 Listener already exists - reusing...');
    listener = auth.getSipListener();
    
    // Check if it's already connected
    if (auth.isSipListenerConnected()) {
      console.log('✅ Listener is already connected and registered');
      console.log('🎧 Listening for doorbell... (Ctrl+C to exit)\n');
    } else {
      console.log('⚠️  Listener exists but not connected - reconnecting...');
      await listener.connect();
      await listener.register();
    }
  } else {
    // 5. Create listener using factory method (integrated!)
    console.log('\n📞 Creating new SIP listener...');
    listener = auth.createSipListener(sipAccount, certs, {
      debug: true,  // Enable debug to see what's happening
      keepAlive: true,
      autoReconnect: true
    });
  }

  // 6. Event handlers - all SIP events are forwarded through auth with 'sip:' prefix
  // (only set up once, even if listener already existed)
  auth.removeAllListeners('sip:connected');
  auth.removeAllListeners('sip:registered');
  auth.removeAllListeners('sip:invite');
  auth.removeAllListeners('sip:disconnected');
  auth.removeAllListeners('sip:error');
  auth.removeAllListeners('sip:certificatesUpdated');
  auth.removeAllListeners('sip:certificateUpdateError');
  
  auth.on('sip:connected', () => console.log('✅ Connected to SIP server'));
  auth.on('sip:registered', () => {
    console.log('✅ Registered\n');
    console.log('🎧 Listening for doorbell... (Ctrl+C to exit)\n');
  });

  auth.on('sip:invite', (callInfo) => {
    console.log('\n🔔 ═══════════════════════════════════');
    console.log('🔔 DOORBELL PRESSED!');
    console.log('🔔 ═══════════════════════════════════');
    console.log('Time:', callInfo.timestamp);
    console.log('From:', callInfo.from);
    console.log('');
  });

  auth.on('sip:disconnected', () => console.warn('⚠️  Disconnected (will auto-reconnect)'));
  auth.on('sip:error', (err) => console.error('❌ Error:', err.message));

  // Certificate lifecycle events (automatic graceful restart)
  auth.on('sip:certificatesUpdated', (newCerts) => {
    console.log('🔄 Certificates updated automatically - listener restarted');
    // Optionally save new certificates to disk
    // fs.writeFileSync(CERTS, JSON.stringify({ cert: newCerts.cert, key: newCerts.key }, null, 2));
  });

  auth.on('sip:certificateUpdateError', (err) => {
    console.error('❌ Certificate update failed:', err.message);
    console.error('   Manual restart may be required');
  });

  // 7. Connect (only if we just created a new listener)
  if (!listener.socket) {
    console.log('🚀 Starting listener...');
    await listener.connect();
    await listener.register();
  }

  // 8. Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('\n\n👋 Shutting down...');
    await listener.disconnect();
    await auth.shutdown();
    console.log('✅ Bye!\n');
    process.exit(0);
  });
}

main().catch(err => {
  console.error('❌ Fatal error:', err.message);
  process.exit(1);
});

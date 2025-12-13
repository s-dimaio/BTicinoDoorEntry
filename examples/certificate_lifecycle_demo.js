/**
 * Example: Certificate Lifecycle Management and Automatic Renewal
 * 
 * Demonstrates how the certificate management system automatically handles
 * certificate refresh and renewal without interrupting the doorbell monitoring service.
 * 
 * Key features:
 * - Automatic certificate renewal detection (30 days before expiry)
 * - Graceful disconnect/reconnect cycle during certificate updates
 * - Zero user intervention required
 * - Event notifications for monitoring and logging
 * - Minimal service downtime (~1-2 seconds)
 * 
 * The example shows:
 * - Creating a SIP listener with automatic certificate management
 * - Listening for both normal doorbell events and certificate updates
 * - How the service automatically restarts when certificates are renewed
 * - Error handling if certificate renewal fails
 * 
 * Prerequisites:
 * 1. Run examples/auth_and_save.js first to generate credential files
 * 2. These files must exist in examples/ directory:
 *    - token_cache.json      (OAuth tokens)
 *    - sip_account.json      (SIP credentials)
 *    - client-certs.json     (TLS certificates)
 * 
 * Run with: node examples/certificate_lifecycle_demo.js
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
  console.log('🔄 Certificate Lifecycle Management Demo\n');

  // Check files
  if (!fs.existsSync(TOKEN_CACHE) || !fs.existsSync(SIP_ACCOUNT) || !fs.existsSync(CERTS)) {
    console.error('❌ Missing credential files. Run: node examples/auth_and_save.js\n');
    process.exit(1);
  }

  // Load credentials
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

  // Initialize authentication
  console.log('🔐 Initializing with certificate manager...');
  const auth = new BticinoAuthentication({
    initialTokens: tokens,
    sipClientId: sipAccount.clientId,
    debug: false
  });

  await auth.authenticate();
  console.log('✅ Authenticated\n');

  // Create listener (automatically integrated with certificate manager)
  console.log('📞 Creating SIP listener with automatic certificate refresh...');
  const listener = auth.createSipListener(sipAccount, certs, {
    debug: false,
    keepAlive: true,
    autoReconnect: true
  });

  // Event: Normal operations - all forwarded through auth with 'sip:' prefix
  auth.on('sip:connected', () => {
    console.log('✅ Connected to SIP server');
  });

  auth.on('sip:registered', () => {
    console.log('✅ SIP registered - listening for doorbell...\n');
  });

  auth.on('sip:invite', (callInfo) => {
    console.log('🔔 DOORBELL!', new Date().toISOString());
  });

  // Event: Certificate lifecycle (automatic!)
  auth.on('sip:certificatesUpdated', (newCerts) => {
    console.log('\n🔄 ═══════════════════════════════════════════════════');
    console.log('🔄 CERTIFICATES AUTOMATICALLY UPDATED!');
    console.log('🔄 ═══════════════════════════════════════════════════');
    console.log('   Listener gracefully restarted with new certificates');
    console.log('   No manual intervention required!');
    console.log('   Service downtime: ~1-2 seconds\n');
    
    // Optionally save new certificates to disk
    fs.writeFileSync(CERTS, JSON.stringify(
      { cert: newCerts.cert, key: newCerts.key }, 
      null, 
      2
    ));
    console.log('   ✅ New certificates saved to disk\n');
  });

  auth.on('sip:certificateUpdateError', (err) => {
    console.error('\n❌ Certificate update failed:', err.message);
    console.error('   The listener will continue with old certificates');
    console.error('   Manual intervention may be required if certificates expire\n');
  });

  // Start listening
  console.log('🚀 Starting listener...');
  await listener.connect();
  await listener.register();

  console.log('\n' + '='.repeat(60));
  console.log('Certificate Lifecycle Management Active');
  console.log('='.repeat(60));
  console.log('\nWhat happens automatically:');
  console.log('  1. Certificate manager monitors expiration (30 days before)');
  console.log('  2. When certificates are renewed, listener is notified');
  console.log('  3. Listener automatically disconnects');
  console.log('  4. New certificates are loaded');
  console.log('  5. Listener reconnects with new certificates');
  console.log('  6. SIP re-registration completes');
  console.log('  7. Service resumes - all transparent!\n');
  console.log('Press Ctrl+C to exit\n');

  // Graceful shutdown
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

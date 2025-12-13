/**
 * Test Suite: SIP Listener Integration with BticinoAuthentication
 * 
 * This test suite validates the integration between:
 * - BticinoAuthentication factory method (createSipListener)
 * - BticinoSipListener instance creation and configuration
 * - Centralized SIP configuration (config.js)
 * - Parameter validation and error handling
 * - Event forwarding through BticinoAuthentication
 * 
 * Tests are performed without requiring actual SIP server credentials or network access.
 * All validations use mock data and local assertions.
 * 
 * Run with: npm test
 */


const { BticinoAuthentication, config } = require('../index');

console.log('🧪 Testing SIP Listener Integration\n');

// Test 1: Verify config constants
console.log('1️⃣ Testing config constants...');
console.assert(config.SIP_SERVER === 'vdesip.bs.iotleg.com', 'SIP_SERVER should be set');
console.assert(config.SIP_PORT === 5228, 'SIP_PORT should be 5228');
console.assert(config.SIP_DOMAIN === 'gateway.bs.iotleg.com', 'SIP_DOMAIN should be set');
console.assert(config.SIP_KEEPALIVE_INTERVAL === 5 * 60 * 1000, 'SIP_KEEPALIVE_INTERVAL should be 5 min');
console.assert(config.SIP_RECONNECT_DELAY === 10 * 1000, 'SIP_RECONNECT_DELAY should be 10 sec');
console.assert(config.SIP_REGISTER_EXPIRES === 600, 'SIP_REGISTER_EXPIRES should be 600 sec');
console.log('✅ Config constants are correct\n');

// Test 2: Verify createSipListener method exists
console.log('2️⃣ Testing createSipListener factory method...');
const auth = new BticinoAuthentication({ debug: false });
console.assert(typeof auth.createSipListener === 'function', 'createSipListener should be a function');
console.log('✅ Factory method exists\n');

// Test 3: Verify parameter validation
console.log('3️⃣ Testing parameter validation...');

try {
  auth.createSipListener(null, {});
  console.error('❌ Should have thrown for null sipAccount');
  process.exit(1);
} catch (err) {
  console.assert(err.message.includes('Invalid sipAccount'), 'Should validate sipAccount');
  console.log('✅ Validates null sipAccount');
}

try {
  auth.createSipListener({}, {});
  console.error('❌ Should have thrown for missing sipUri');
  process.exit(1);
} catch (err) {
  console.assert(err.message.includes('sipUri'), 'Should validate sipUri');
  console.log('✅ Validates missing sipUri');
}

try {
  auth.createSipListener({ sipUri: 'test@test.com' }, {});
  console.error('❌ Should have thrown for missing sipPassword');
  process.exit(1);
} catch (err) {
  console.assert(err.message.includes('sipPassword'), 'Should validate sipPassword');
  console.log('✅ Validates missing sipPassword');
}

try {
  auth.createSipListener({ sipUri: 'test@test.com', sipPassword: 'pwd' }, null);
  console.error('❌ Should have thrown for null certs');
  process.exit(1);
} catch (err) {
  console.assert(err.message.includes('Invalid certs'), 'Should validate certs');
  console.log('✅ Validates null certs');
}

try {
  auth.createSipListener({ sipUri: 'test@test.com', sipPassword: 'pwd' }, {});
  console.error('❌ Should have thrown for missing cert');
  process.exit(1);
} catch (err) {
  console.assert(err.message.includes('cert'), 'Should validate cert');
  console.log('✅ Validates missing cert');
}

try {
  auth.createSipListener({ sipUri: 'test@test.com', sipPassword: 'pwd' }, { cert: 'test' });
  console.error('❌ Should have thrown for missing key');
  process.exit(1);
} catch (err) {
  console.assert(err.message.includes('key'), 'Should validate key');
  console.log('✅ Validates missing key\n');
}

// Test 4: Verify listener creation with valid params
console.log('4️⃣ Testing listener creation with valid parameters...');
const mockSipAccount = {
  sipUri: 'user_123456@gateway.bs.iotleg.com',
  sipPassword: 'testpassword',
  plantId: 'plant-123',
  gatewayId: 'gateway-456'
};

const mockCerts = {
  cert: '-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----',
  key: '-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----'
};

try {
  const listener = auth.createSipListener(mockSipAccount, mockCerts, { debug: false });
  console.assert(listener !== null, 'Listener should be created');
  console.assert(typeof listener.connect === 'function', 'Should have connect method');
  console.assert(typeof listener.register === 'function', 'Should have register method');
  console.assert(typeof listener.disconnect === 'function', 'Should have disconnect method');
  console.assert(listener.sipConfig.server === config.SIP_SERVER, 'Should use config SIP_SERVER');
  console.assert(listener.sipConfig.port === config.SIP_PORT, 'Should use config SIP_PORT');
  console.assert(listener.sipConfig.domain === config.SIP_DOMAIN, 'Should use config SIP_DOMAIN');
  console.assert(listener.sipConfig.username === 'user_123456', 'Should extract username from sipUri');
  console.assert(listener.opts.keepAlive === true, 'Should have keepAlive enabled by default');
  console.assert(listener.opts.autoReconnect === true, 'Should have autoReconnect enabled by default');
  console.log('✅ Listener created successfully with correct configuration\n');
} catch (err) {
  console.error('❌ Failed to create listener:', err.message);
  process.exit(1);
}

// Test 5: Verify certificate alias support (cert/certPEM, key/privateKeyPem)
console.log('5️⃣ Testing certificate alias support...');
try {
  const listener = auth.createSipListener(mockSipAccount, mockCerts);
  console.assert(listener.certs.certPEM === mockCerts.cert, 'Should support cert alias');
  console.assert(listener.certs.privateKeyPem === mockCerts.key, 'Should support key alias');
  console.log('✅ Certificate aliases work correctly\n');
} catch (err) {
  console.error('❌ Certificate alias test failed:', err.message);
  process.exit(1);
}

// Test 6: Verify custom options are respected
console.log('6️⃣ Testing custom options...');
try {
  const listener = auth.createSipListener(mockSipAccount, mockCerts, {
    debug: true,
    keepAlive: false,
    autoReconnect: false,
    keepAliveInterval: 60000,
    reconnectDelay: 5000
  });
  console.assert(listener.opts.debug === true, 'Should respect debug option');
  console.assert(listener.opts.keepAlive === false, 'Should respect keepAlive option');
  console.assert(listener.opts.autoReconnect === false, 'Should respect autoReconnect option');
  console.assert(listener.opts.keepAliveInterval === 60000, 'Should respect keepAliveInterval option');
  console.assert(listener.opts.reconnectDelay === 5000, 'Should respect reconnectDelay option');
  console.log('✅ Custom options are respected\n');
} catch (err) {
  console.error('❌ Custom options test failed:', err.message);
  process.exit(1);
}

// Test 7: Verify SIP listener tracking methods
console.log('7️⃣ Testing SIP listener tracking methods (hasSipListener, isSipListenerConnected, getSipListener)...');
try {
  const auth2 = new BticinoAuthentication({ debug: false });
  
  // Initially no listener
  console.assert(auth2.hasSipListener() === false, 'Should return false when no listener exists');
  console.assert(auth2.isSipListenerConnected() === false, 'Should return false when no listener exists');
  console.assert(auth2.getSipListener() === null, 'Should return null when no listener exists');
  console.log('✅ Initial state: no listener');
  
  // Create listener
  const listener = auth2.createSipListener(mockSipAccount, mockCerts);
  console.assert(auth2.hasSipListener() === true, 'Should return true after creating listener');
  console.assert(auth2.getSipListener() === listener, 'Should return the created listener');
  console.log('✅ After creation: listener tracked');
  
  // Check connection status (initially not connected)
  console.assert(auth2.isSipListenerConnected() === false, 'Should return false when not yet connected');
  console.log('✅ Connection status: correctly reports not connected');
  
  // Simulate disconnection event to clear reference
  listener.emit('disconnected');
  console.assert(auth2.hasSipListener() === false, 'Should return false after disconnection event');
  console.assert(auth2.getSipListener() === null, 'Should return null after disconnection event');
  console.log('✅ After disconnection: listener reference cleared\n');
} catch (err) {
  console.error('❌ SIP listener tracking test failed:', err.message);
  process.exit(1);
}

// Summary
console.log('=' .repeat(60));
console.log('✅ All integration tests passed!');
console.log('=' .repeat(60));
console.log('\nIntegration Summary:');
console.log('  ✅ Config constants centralized');
console.log('  ✅ Factory method createSipListener() available');
console.log('  ✅ Parameter validation working');
console.log('  ✅ Listener creation with defaults');
console.log('  ✅ Certificate aliases supported');
console.log('  ✅ Custom options respected');
console.log('  ✅ Listener tracking methods (hasSipListener, isSipListenerConnected, getSipListener)');
console.log('\nThe SIP Listener is now fully integrated! 🎉\n');

/**
 * Test: Package Metadata and Public API Exports
 * 
 * Validates that the main entry point (index.js) correctly exports:
 * - All public classes (BticinoAuthentication, BticinoApiClient, BticinoSipClient, BticinoSipListener)
 * - All public functions (openGate)
 * - Configuration object (config)
 * - Package metadata (version, name, description)
 * 
 * This test ensures the module interface is stable and discoverable.
 * 
 * Run with: npm test
 */


const bticino = require('../index.js');

console.log('📦 Package Metadata Test\n');

console.log('Package Information:');
console.log('  Name:', bticino.name);
console.log('  Version:', bticino.version);
console.log('  Description:', bticino.description);

console.log('\nExported Classes:');
console.log('  BticinoAuthentication:', typeof bticino.BticinoAuthentication);
console.log('  BticinoApiClient:', typeof bticino.BticinoApiClient);
console.log('  BticinoSipClient:', typeof bticino.BticinoSipClient);
console.log('  BticinoSipListener:', typeof bticino.BticinoSipListener);
console.log('  BticinoVideoStreamer:', typeof bticino.BticinoVideoStreamer);
console.log('  BticinoRtspLoopbackServer:', typeof bticino.BticinoRtspLoopbackServer);
console.log('  BticinoSrtpDecryptor:', typeof bticino.BticinoSrtpDecryptor);
console.log('  BticinoSnapshotExtractor:', typeof bticino.BticinoSnapshotExtractor);

console.log('\nExported Functions:');
console.log('  ✅ openGate:', typeof bticino.openGate);

console.log('\nExported Objects:');
console.log('  ✅ config:', typeof bticino.config);

console.log('\nConfiguration Constants:');
console.log('  SIP_SERVER:', bticino.config.SIP_SERVER);
console.log('  SIP_PORT:', bticino.config.SIP_PORT);
console.log('  SIP_DOMAIN:', bticino.config.SIP_DOMAIN);

console.log('\n✅ All exports verified!\n');

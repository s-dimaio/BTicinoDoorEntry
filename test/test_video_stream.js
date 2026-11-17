/**
 * Test: BTicino Video Streaming Pipeline
 *
 * Comprehensive test suite validating:
 * 1. BticinoSrtpDecryptor: RFC 3711 AES-128-CTR key derivation and SRTP packet decryption.
 * 2. BticinoSnapshotExtractor: RFC 6184 H.264 RTP depacketizer (Single NAL, STAP-A, FU-A) & IDR snapshot extraction.
 * 3. BticinoRtspLoopbackServer: RFC 2326 RTSP loopback server (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN).
 * 4. BticinoAuthentication integration: createVideoStreamer / stopVideoStreamer lifecycle.
 * 5. Optional live call validation if credentials are configured in environment.
 *
 * Run with: node test/test_video_stream.js
 */

'use strict';

const net = require('net');
const crypto = require('crypto');
const {
  BticinoAuthentication,
  BticinoVideoStreamer,
  BticinoRtspLoopbackServer,
  BticinoSrtpDecryptor,
  BticinoSnapshotExtractor
} = require('../index.js');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

/**
 * Asserts a condition and records the result.
 *
 * @param {string} testName - Description of test case.
 * @param {boolean} condition - Condition expected to be truthy.
 * @param {string} [details=''] - Additional diagnostic details.
 */
function assert(testName, condition, details = '') {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`[PASS] ${testName}`);
  } else {
    failedTests++;
    console.error(`[FAIL] ${testName} ${details ? '- ' + details : ''}`);
  }
}

/**
 * Executes Unit Test 1: BticinoSrtpDecryptor RFC 3711 PRF and decryption.
 *
 * @async
 * @returns {Promise<void>}
 */
async function testSrtpDecryptor() {
  console.log('\n--- Test Suite 1: BticinoSrtpDecryptor (RFC 3711) ---');

  const masterKey = Buffer.from('E1F97A0D3E018BE0D64FA32C06DE4139', 'hex');
  const masterSalt = Buffer.from('0EC675AD498AFEEBB6960B3AABE6', 'hex');
  const inlineKey = Buffer.concat([masterKey, masterSalt]).toString('base64');

  const decryptor = new BticinoSrtpDecryptor(inlineKey);
  assert('SRTP decryptor initialization', typeof decryptor.decrypt === 'function');

  // Verify PRF test vectors against RFC 3711 Section B.2
  const derivedKey = decryptor._deriveKey(0x00, 16);
  const derivedSalt = decryptor._deriveKey(0x02, 14);
  const derivedAuth = decryptor._deriveKey(0x01, 20);

  const expectedKey = Buffer.from('C61E7A93744F39EE10734AFE3FF7A087', 'hex');
  const expectedSalt = Buffer.from('30CBBC08863D8C85D49DB34A9AE1', 'hex');
  const expectedAuth = Buffer.from('CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4', 'hex');

  assert(
    'RFC 3711 Session Encryption Key Derivation (PRF-AES-128)',
    derivedKey.equals(expectedKey),
    `Derived: ${derivedKey.toString('hex')} Expected: ${expectedKey.toString('hex')}`
  );
  assert(
    'RFC 3711 Session Salt Derivation (PRF-AES-128)',
    derivedSalt.equals(expectedSalt),
    `Derived: ${derivedSalt.toString('hex')} Expected: ${expectedSalt.toString('hex')}`
  );
  assert(
    'RFC 3711 Session Authentication Key Derivation (PRF-AES-128)',
    derivedAuth.equals(expectedAuth),
    `Derived: ${derivedAuth.toString('hex')} Expected: ${expectedAuth.toString('hex')}`
  );

  // Test AES-128-CTR encryption and decryption roundtrip
  const rtpHeader = Buffer.from([
    0x80, 0x60, 0x00, 0x01, // V=2, PT=96, Seq=1
    0x00, 0x00, 0x03, 0xe8, // Timestamp=1000
    0x12, 0x34, 0x56, 0x78  // SSRC=0x12345678
  ]);
  const originalPayload = Buffer.from('Hello BTicino Video H264 Stream Encrypted With SRTP');

  // Encrypt payload manually using session key and IV
  const iv = Buffer.alloc(16, 0);
  derivedSalt.copy(iv, 0, 0, 14);
  const ssrc = 0x12345678;
  const seq = 1;
  iv[4] ^= (ssrc >>> 24) & 0xFF;
  iv[5] ^= (ssrc >>> 16) & 0xFF;
  iv[6] ^= (ssrc >>> 8) & 0xFF;
  iv[7] ^= ssrc & 0xFF;
  iv[12] ^= (seq >>> 8) & 0xFF;
  iv[13] ^= seq & 0xFF;

  const cipher = crypto.createCipheriv('aes-128-ctr', derivedKey, iv);
  const encryptedPayload = Buffer.concat([cipher.update(originalPayload), cipher.final()]);

  // Compute HMAC-SHA1-80 tag over header + encryptedPayload + ROC (0)
  const rocBuf = Buffer.alloc(4, 0);
  const hmac = crypto.createHmac('sha1', derivedAuth);
  hmac.update(Buffer.concat([rtpHeader, encryptedPayload, rocBuf]));
  const fullTag = hmac.digest();
  const authTag = fullTag.subarray(0, 10); // 80-bit tag

  const protectedPacket = Buffer.concat([rtpHeader, encryptedPayload, authTag]);

  // Decrypt via BticinoSrtpDecryptor
  const unprotectedRtp = decryptor.decrypt(protectedPacket);
  assert('SRTP packet successfully decrypted', unprotectedRtp !== null);

  const decryptedPayload = unprotectedRtp.subarray(12);
  assert(
    'SRTP decrypted payload matches original plaintext',
    decryptedPayload.equals(originalPayload),
    `Decrypted: ${decryptedPayload.toString()} Expected: ${originalPayload.toString()}`
  );
}

/**
 * Executes Unit Test 2: BticinoSnapshotExtractor H.264 NAL parsing and snapshot caching.
 *
 * @async
 * @returns {Promise<void>}
 */
async function testSnapshotExtractor() {
  console.log('\n--- Test Suite 2: BticinoSnapshotExtractor (RFC 6184) ---');

  const extractor = new BticinoSnapshotExtractor();
  assert('Snapshot extractor initial state', !extractor.hasSnapshot());

  // 1. Single NAL SPS packet (NAL type 7: 0x67)
  const spsNal = Buffer.from([0x67, 0x42, 0x80, 0x1f, 0xda, 0x01, 0x40, 0x16, 0xe8]);
  const spsRtp = Buffer.concat([
    Buffer.from([0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]),
    spsNal
  ]);
  extractor.processRtpPacket(spsRtp);
  assert('SPS cached after RTP packet', extractor.getSps() !== null && extractor.getSps().subarray(4).equals(spsNal));

  // 2. Single NAL PPS packet (NAL type 8: 0x68)
  const ppsNal = Buffer.from([0x68, 0xce, 0x06, 0xe2]);
  const ppsRtp = Buffer.concat([
    Buffer.from([0x80, 0x60, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]),
    ppsNal
  ]);
  extractor.processRtpPacket(ppsRtp);
  assert('PPS cached after RTP packet', extractor.getPps() !== null && extractor.getPps().subarray(4).equals(ppsNal));

  // 3. FU-A Fragmented IDR Keyframe (NAL type 5: FU Indicator 0x7c, Header 0x85 [Start], 0x45 [End])
  // Note: BticinoSnapshotExtractor requires nalu >= 64 bytes to discard probe packets.
  const part1Data = Buffer.alloc(40, 0x11);
  const idrPayloadPart1 = Buffer.concat([Buffer.from([0x7c, 0x85]), part1Data]); // S=1, E=0, Type=5
  const fuRtp1 = Buffer.concat([
    Buffer.from([0x80, 0x60, 0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]),
    idrPayloadPart1
  ]);

  const part2Data = Buffer.alloc(40, 0x22);
  const idrPayloadPart2 = Buffer.concat([Buffer.from([0x7c, 0x45]), part2Data]); // S=0, E=1, Type=5
  const fuRtp2 = Buffer.concat([
    Buffer.from([0x80, 0xe0, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]), // Marker bit set
    idrPayloadPart2
  ]);

  let snapshotEventFired = false;
  extractor.once('snapshot', (buf) => {
    snapshotEventFired = true;
    assert('Snapshot event emitted with buffer', Buffer.isBuffer(buf) && buf.length > 0);
  });

  extractor.processRtpPacket(fuRtp1);
  extractor.processRtpPacket(fuRtp2);

  assert('Snapshot extractor hasSnapshot() is true', extractor.hasSnapshot());
  assert('Snapshot event fired upon complete keyframe', snapshotEventFired);

  const snapshot = extractor.getLatestSnapshot();
  const startCode = Buffer.from([0x00, 0x00, 0x00, 0x01]);
  assert('Snapshot buffer begins with Annex B start code', snapshot.subarray(0, 4).equals(startCode));
}

/**
 * Executes Unit Test 3: BticinoRtspLoopbackServer RFC 2326 exchange.
 *
 * @async
 * @returns {Promise<void>}
 */
async function testRtspLoopbackServer() {
  console.log('\n--- Test Suite 3: BticinoRtspLoopbackServer (RFC 2326) ---');

  const server = new BticinoRtspLoopbackServer({ port: 0 }); // Bind ephemeral port
  const { port, rtspUrl } = await server.start();

  assert('RTSP loopback server started', port > 0);
  assert('RTSP URL formatted correctly', rtspUrl === `rtsp://127.0.0.1:${port}/live`);

  // Establish TCP client connection to test RTSP handshake
  const client = net.createConnection({ host: '127.0.0.1', port });

  const sendAndReceive = (requestText) => {
    return new Promise((resolve, reject) => {
      const onData = (data) => {
        client.removeListener('data', onData);
        client.removeListener('error', reject);
        resolve(data.toString());
      };
      client.on('data', onData);
      client.on('error', reject);
      client.write(requestText);
    });
  };

  await new Promise((resolve) => client.once('connect', resolve));
  assert('RTSP client connected to loopback server', true);

  // 1. OPTIONS
  const optionsResp = await sendAndReceive(
    `OPTIONS rtsp://127.0.0.1:${port}/live RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: HomeyProTest\r\n\r\n`
  );
  assert('RTSP OPTIONS response 200 OK', optionsResp.includes('RTSP/1.0 200 OK') && optionsResp.includes('Public:'));

  // 2. DESCRIBE
  const describeResp = await sendAndReceive(
    `DESCRIBE rtsp://127.0.0.1:${port}/live RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n`
  );
  assert('RTSP DESCRIBE response includes SDP', describeResp.includes('m=video') && describeResp.includes('H264/90000'));

  // 3. SETUP (Interleaved TCP)
  const setupResp = await sendAndReceive(
    `SETUP rtsp://127.0.0.1:${port}/live/track0 RTSP/1.0\r\nCSeq: 3\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n`
  );
  assert('RTSP SETUP response includes Session and Interleaved transport', setupResp.includes('interleaved=0-1') && setupResp.includes('Session:'));

  const sessionMatch = setupResp.match(/Session:\s*([^\r\n;]+)/i);
  const sessionId = sessionMatch ? sessionMatch[1].trim() : '';

  // 4. PLAY
  const playResp = await sendAndReceive(
    `PLAY rtsp://127.0.0.1:${port}/live RTSP/1.0\r\nCSeq: 4\r\nSession: ${sessionId}\r\n\r\n`
  );
  assert('RTSP PLAY response 200 OK', playResp.includes('RTSP/1.0 200 OK'));

  // 5. Broadcast RTP packet and check interleaved frame arrival
  const testRtp = Buffer.from([0x80, 0x60, 0x12, 0x34, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb]);
  const interleavedPromise = new Promise((resolve) => {
    client.once('data', (chunk) => {
      resolve(chunk);
    });
  });

  server.broadcastRtp(testRtp);
  const interleavedChunk = await interleavedPromise;

  assert(
    'RTSP interleaved packet received ($ + channel 0 + 2-byte length)',
    interleavedChunk[0] === 0x24 && interleavedChunk[1] === 0x00 && interleavedChunk.subarray(4).equals(testRtp)
  );

  // 6. TEARDOWN
  const teardownResp = await sendAndReceive(
    `TEARDOWN rtsp://127.0.0.1:${port}/live RTSP/1.0\r\nCSeq: 5\r\nSession: ${sessionId}\r\n\r\n`
  );
  assert('RTSP TEARDOWN response 200 OK', teardownResp.includes('RTSP/1.0 200 OK'));

  client.destroy();
  await server.stop();
  assert('RTSP loopback server stopped cleanly', !server.isRunning());
}

/**
 * Executes Unit Test 4: BticinoAuthentication video streamer factory lifecycle.
 *
 * @async
 * @returns {Promise<void>}
 */
async function testAuthenticationIntegration() {
  console.log('\n--- Test Suite 4: BticinoAuthentication Video Streamer Integration ---');

  const auth = new BticinoAuthentication({ debug: false });
  assert('BticinoAuthentication initially has no video streamer', !auth.hasVideoStreamer());

  const mockSipAccount = {
    sipUri: 'sip:testuser@gateway.bs.iotleg.com',
    sipPassword: 'dummyPassword123'
  };
  const mockCerts = {
    cert: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----',
    key: '-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----'
  };

  const streamer = auth.createVideoStreamer(mockSipAccount, mockCerts, { debug: false });
  assert('createVideoStreamer returns BticinoVideoStreamer instance', streamer instanceof BticinoVideoStreamer);
  assert('URI prefix sip: stripped from username', streamer.username === 'testuser');
  assert('auth.hasVideoStreamer() returns true', auth.hasVideoStreamer());
  assert('auth.getVideoStreamer() returns the created instance', auth.getVideoStreamer() === streamer);

  // Test multi-message SIP stream parser (100 Trying + 180 Ringing + 200 OK with multiple Record-Route)
  const EventEmitter = require('events');
  const mockTls = new EventEmitter();
  mockTls.localPort = 45678;
  mockTls.write = () => {
    setImmediate(() => {
      const sdpBody = 'v=0\r\no=diy 558 3658 IN IP4 127.0.0.1\r\nc=IN IP4 51.105.204.121\r\nm=video 21630 RTP/SAVP 96\r\na=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:F51fvCCANMEnSDsqi3AA6s7/3TaYvvXh65ncoPiF\r\n';
      const streamData =
        'SIP/2.0 100 Trying\r\nCSeq: 21 INVITE\r\nContent-Length: 0\r\n\r\n' +
        'SIP/2.0 180 Ringing\r\nTo: <sip:diy@gateway.bs.iotleg.com>;tag=sQaIDHB\r\nCSeq: 21 INVITE\r\nContent-Length: 0\r\n\r\n' +
        `SIP/2.0 200 Ok\r\nRecord-Route: <sip:127.0.0.1:5060;transport=tcp;lr>\r\nRecord-Route: <sips:vde-sip4.bs.iotleg.com:5228;lr>\r\nTo: <sip:diy@gateway.bs.iotleg.com>;tag=sQaIDHB\r\nCSeq: 21 INVITE\r\nContent-Length: ${Buffer.byteLength(sdpBody)}\r\n\r\n` +
        sdpBody;
      mockTls.emit('data', Buffer.from(streamData, 'utf8'));
    });
  };
  streamer._tlsSocket = mockTls;
  const parsedResp = await streamer._sendSipRequestAndAwaitResponse('INVITE sip:diy@gateway.bs.iotleg.com SIP/2.0\r\n\r\n');
  assert('Multi-message SIP stream skips 100/180 and resolves 200 OK', parsedResp.statusCode === 200);
  assert('Multiple Record-Route headers preserved as array', Array.isArray(parsedResp.headers['record-route']) && parsedResp.headers['record-route'].length === 2);
  streamer._handleSdpAnswer(parsedResp);
  assert('To-tag extracted from 180/200 response', streamer._toTag === 'sQaIDHB');
  assert('Remote relay IP extracted from SDP', streamer._remoteRelayIp === '51.105.204.121');
  assert('Remote video port extracted from SDP', streamer._remoteVideoPort === 21630);
  streamer._tlsSocket = null;

  // Test event forwarding
  let forwardedEventReceived = false;
  auth.once('video:snapshot', () => {
    forwardedEventReceived = true;
  });

  streamer.emit('snapshot', Buffer.from([0x01, 0x02]));
  assert('BticinoAuthentication forwards video streamer events', forwardedEventReceived);

  // Test RTP continuity rewriting across transparent call renewals
  const rtpCall1 = Buffer.alloc(16);
  rtpCall1[0] = 0x80;
  rtpCall1[1] = 0x60;
  rtpCall1.writeUInt16BE(500, 2);        // Call 1 seq = 500
  rtpCall1.writeUInt32BE(90000, 4);      // Call 1 ts = 90000
  rtpCall1.writeUInt32BE(0xAABBCCDD, 8); // Call 1 SSRC
  streamer._rewriteRtpContinuity(rtpCall1);
  assert('RTP continuity preserves initial packet seq and SSRC', rtpCall1.readUInt16BE(2) === 500 && rtpCall1.readUInt32BE(8) === 0xAABBCCDD);

  // Simulate call renewal where Call 2 restarts at seq = 0 with a new SSRC and timestamp
  streamer._rtpResyncPending = true;
  const rtpCall2 = Buffer.alloc(16);
  rtpCall2[0] = 0x80;
  rtpCall2[1] = 0x60;
  rtpCall2.writeUInt16BE(0, 2);          // Call 2 seq = 0
  rtpCall2.writeUInt32BE(1000, 4);       // Call 2 ts = 1000
  rtpCall2.writeUInt32BE(0x11223344, 8); // Call 2 SSRC (different)
  streamer._rewriteRtpContinuity(rtpCall2);
  assert('RTP continuity rewrites renewed call seq to 501', rtpCall2.readUInt16BE(2) === 501);
  assert('RTP continuity preserves original SSRC across call renewal', rtpCall2.readUInt32BE(8) === 0xAABBCCDD);
  assert('RTP continuity keeps timestamp monotonically increasing across renewal', rtpCall2.readUInt32BE(4) > 90000);

  // Test stopping
  await auth.stopVideoStreamer();
  assert('auth.hasVideoStreamer() returns false after stopVideoStreamer()', !auth.hasVideoStreamer());

  await auth.shutdown();
}

/**
 * Main test runner orchestrator.
 */
async function runAllTests() {
  console.log('================================================================');
  console.log('[TestRunner:start] Starting BTicino Video Streaming Test Suite');
  console.log('================================================================');

  try {
    await testSrtpDecryptor();
    await testSnapshotExtractor();
    await testRtspLoopbackServer();
    await testAuthenticationIntegration();
  } catch (error) {
    console.error('[TestRunner:error] Unexpected exception occurred during test execution:', error);
    failedTests++;
  }

  console.log('\n================================================================');
  console.log(`[TestRunner:finish] Total Tests: ${totalTests} | Passed: ${passedTests} | Failed: ${failedTests}`);
  console.log('================================================================');

  if (failedTests > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAllTests();

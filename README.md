# BTicino Door Entry

A reverse-engineered Node.js library and complete implementation for controlling BTicino / Legrand Door Entry intercom systems, receiving real-time doorbell and missed-call notifications via SIP/TLS, streaming live H.264 video via SRTP/RTSP, and extracting JPEG snapshots.

## Features

- **Azure AD B2C Authentication**: Complete OAuth2 flow with automatic token refresh and local reverse proxy
- **Automatic Certificate Refresh**: Client mTLS certificates renewed automatically before expiry (30-day skew)
- **Graceful Certificate Restart**: SIP listener automatically restarts with new certificates without service interruption
- **Persistent Doorbell Listener**: Receive real-time doorbell ring, answered, missed call, and call-ended events via SIP/TLS with automatic reconnection
- **Live Video Streaming Pipeline**: High-level video streamer orchestrating SIP video INVITE, SRTP payload decryption, and local RTSP loopback serving
- **SRTP Decryption (RFC 3711)**: AES-128-CTR and HMAC-SHA1-80 decryption for encrypted video RTP packets
- **On-Demand & Live JPEG Snapshot Extraction**: RFC 6184 H.264 NAL depacketizer with WebAssembly H.264 decoding and JPEG encoding
- **Local RTSP Loopback Server (RFC 2326)**: Interleaved TCP/UDP streaming server compatible with Homey Pro (`createVideoRTSP`), VLC, and FFmpeg
- **RTP Stream Continuity**: Seamless sequence number and timestamp continuity across transparent SIP video call renewals
- **Gate / Lock Control**: Ephemeral SIP/TLS client for sending JSON-RPC `lock.setStatus` commands
- **Device Registration & Provisioning**: Automated onboarding flow generating ECC P-256 keys and X.509 CSR with SIP URI SAN
- **Developer API Wrapper**: Axios REST client for BTicino/Legrand Eliot developer endpoints
- **Comprehensive Mock Test Suite**: Automated unit and integration tests running in-memory with zero external credentials required

## Project Structure

```text
.
├── lib/
│   ├── api/
│   │   └── BticinoApiClient.js         # REST API wrapper (plants, modules, SIP accounts)
│   ├── auth/
│   │   ├── BticinoAuthentication.js    # High-level auth orchestrator with SIP & video factory
│   │   ├── BticinoProxy.js             # Local reverse proxy for OAuth callback
│   │   └── BticinoRegisterDevice.js    # Device onboarding & CSR provisioning flow
│   ├── certs/
│   │   ├── BticinoCertificates.js      # ECC P-256 keypair & X.509 CSR generation
│   │   └── BticinoCertificateManager.js # Automated certificate lifecycle & renewal
│   ├── sip/
│   │   ├── BticinoSipClient.js         # Low-level SIP/TLS client (ephemeral connections)
│   │   ├── BticinoSipListener.js       # Persistent SIP listener for doorbell notifications
│   │   └── BticinoControls.js          # High-level gate open helper (openGate)
│   ├── video/
│   │   ├── BticinoVideoStreamer.js     # Video call lifecycle, SIP negotiation & RTP continuity
│   │   ├── BticinoRtspLoopbackServer.js # Local RFC 2326 RTSP loopback server
│   │   ├── BticinoSrtpDecryptor.js     # RFC 3711 AES-128-CTR SRTP packet decryptor
│   │   └── BticinoSnapshotExtractor.js # RFC 6184 H.264 depacketizer & JPEG converter
│   └── config/
│       └── config.js                   # Centralized configuration (SIP, OAuth, API)
├── examples/
│   ├── auth_and_save.js                # Complete auth + registration example
│   ├── open_from_saved.js              # Open gate using saved credentials
│   ├── listen_doorbell.js              # Persistent doorbell listener
│   └── certificate_lifecycle_demo.js   # Certificate auto-refresh demo
├── test/
│   ├── sip_listener_integration.js     # SIP integration & event routing tests
│   ├── certificate_lifecycle.js        # Certificate lifecycle & renewal tests
│   ├── test_snapshot_jpeg.js           # YUV420 to JPEG encoding unit tests
│   ├── test_video_stream.js            # SRTP, RTSP, and video pipeline integration tests
│   └── package_exports.js              # Package public API validation
├── index.js                            # Main package entry point and exports
└── package.json
```

## Installation

Install directly from GitHub:

```bash
npm install git+https://github.com/s-dimaio/BTicinoDoorEntry.git
```

Or install by package name if published in your registry:

```bash
npm install bticino-door-entry
```

## Requirements

- Node.js >= 16
- Legrand / BTicino user account
- BTicino Door Entry system (EasyKit, Classe 100X, or compatible)

## Quick Start

### 1. First Time Setup (Authentication & Registration)

```javascript
const { BticinoAuthentication } = require('bticino-door-entry');

const auth = new BticinoAuthentication({
  debug: true
});

// Listen for tokens
auth.on('tokenCreated', (tokens) => {
  console.log('Tokens received:', tokens);
});

// Listen for device registration
auth.on('deviceRegistered', (payload) => {
  console.log('SIP Account registered:', payload);
});

// Listen for certificates
auth.on('certificatesCreated', (info) => {
  console.log('Certificates provisioned:', info);
});

// Start interactive authentication
const { tokens } = await auth.authenticate();

// Create API client
const api = auth.createApiClient({ debug: true });
const plants = await api.getPlants();

// Register device (provisions SIP account + mTLS certificates)
await auth.registerDevice({
  plantId: plants[0].id,
  debug: true
});
```

---

### 2. Listen for Doorbell Notifications

```javascript
const { BticinoAuthentication } = require('bticino-door-entry');

const auth = new BticinoAuthentication({
  initialTokens: savedTokens,
  debug: false
});

await auth.authenticate();

// Create persistent SIP listener
const listener = auth.createSipListener(sipAccount, certs, {
  keepAlive: true,
  autoReconnect: true
});

// Listen for doorbell events
auth.on('sip:invite', (callInfo) => {
  console.log('Doorbell pressed!', callInfo.timestamp, 'from:', callInfo.from);
});

auth.on('sip:callMissed', (callInfo) => {
  console.log('Doorbell call missed:', callInfo.reason);
});

auth.on('sip:callAnswered', (callInfo) => {
  console.log('Doorbell call answered on another unit');
});

auth.on('sip:connected', () => console.log('Connected to SIP server'));
auth.on('sip:registered', () => console.log('Listening for doorbell...'));
auth.on('sip:disconnected', () => console.warn('Disconnected (auto-reconnecting)'));

// Connect and register
await listener.connect();
await listener.register();
```

---

### 3. Open Gate with Saved Credentials

```javascript
const { openGate } = require('bticino-door-entry');

await openGate(
  gateId,
  plantId,
  certs.cert,
  certs.key,
  sipAccount,
  { debug: true }
);
```

---

### 4. Live Video Streaming & On-Demand Snapshots

```javascript
const { BticinoAuthentication } = require('bticino-door-entry');

const auth = new BticinoAuthentication({ initialTokens: savedTokens });
await auth.authenticate();
auth.setSipAccount(sipAccount);
auth.setCertificates(certs.cert, certs.key);

// Option A: Capture a single on-demand JPEG snapshot (ephemeral or reusing active stream)
const jpegBuffer = await auth.captureCameraSnapshot(cameraModuleId, {
  cameraIndex: 1,
  forceFresh: true,
  timeoutMs: 15000
});

// Option B: Start a persistent live RTSP stream
const streamer = auth.createVideoStreamer(sipAccount, certs, {
  debug: false
});

auth.on('video:keyframe', (keyframeBuf) => {
  console.log('New H.264 keyframe received:', keyframeBuf.length, 'bytes');
});

auth.on('video:jpeg', (jpegBuf) => {
  console.log('New JPEG snapshot ready:', jpegBuf.length, 'bytes');
});

// Start video stream session on local RTSP loopback server
const { rtspUrl } = await streamer.startStream(cameraModuleId, { cameraIndex: 1 });
console.log('Local RTSP stream available at:', rtspUrl);

// Retrieve latest cached snapshot at any time
if (streamer.hasJpegSnapshot()) {
  const latestJpeg = streamer.getLatestJpegSnapshot();
}

// Stop video session when done
await streamer.stopStream();
```

---

## API Reference

### BticinoAuthentication

Main authentication orchestrator managing OAuth2 tokens, certificate renewals, and factory methods.

**Constructor Options:**
- `debug` (boolean): Enable debug logging (default: `false`)
- `initialTokens` (Object): Previously saved tokens (default: `null`)
- `proxyHost` (string): Proxy host for OAuth callback (default: `localhost`)
- `proxyPort` (number): Proxy port for OAuth callback (default: `8080`)
- `autoRefresh` (boolean): Enable automatic token refresh (default: `true`)
- `refreshSkewSec` (number): Seconds before token expiry to trigger refresh (default: `60`)
- `certificateRenewalSkewSec` (number): Seconds before cert expiry to renew (default: `2592000` = 30 days)
- `unrefRefreshTimer` (boolean): Allow process exit with pending timers (default: `true`)
- `installExitHooks` (boolean): Install SIGINT/SIGTERM handlers for cleanup (default: `false`)
- `forceLogin` (boolean): Force re-login with `prompt=login` (default: `false`)
- `timeoutMs` (number): Login timeout in milliseconds (default: `180000`)
- `autoStopOnAuth` (boolean): Stop proxy after auth code capture (default: `true`)
- `successPage` (string|null): Custom HTML for OAuth callback success page (default: `null`)

**Methods:**
- `authenticate()`: Start authentication flow. Returns `Promise<{ tokens }>`
- `setInitialTokens(tokens)`: Set tokens after construction (accepts Object or JSON string)
- `ensureStarted()`: Ensure proxy is started (idempotent). Returns `Promise`
- `prepareLoginUrl()`: Generate login URL without starting flow. Returns `{ state, url, fullUrl }`
- `waitForAuthorizationCode(state)`: Poll for auth code from callback. Returns `Promise<{ code, state }>`
- `forceRefresh()`: Force token refresh immediately. Returns `Promise<{ tokens }>`
- `registerDevice(options)`: Register device and provision certificates. Options: `{ plantId, gatewayId, clientName, sipClientId, forceCertificates, async, debug }`. Returns `Promise<result>`
- `provisionCertificates(options)`: Force certificate provisioning for existing device. Returns `Promise<certs>`
- `createApiClient(options)`: Create API client instance. Returns `BticinoApiClient`
- `createSipListener(sipAccount, certs, opts)`: Create persistent SIP listener for doorbell notifications. Returns `BticinoSipListener`
- `hasSipListener()`: Check if a SIP listener has been created. Returns `boolean`
- `isSipListenerConnected()`: Check if SIP listener is connected and registered. Returns `boolean`
- `getSipListener()`: Get current SIP listener instance or `null`. Returns `BticinoSipListener|null`
- `setSipAccount(sipAccount)`: Store SIP account credentials on the orchestrator
- `getSipAccount()`: Retrieve stored SIP account credentials or `null`
- `createVideoStreamer(sipAccount, certs, opts)`: Create video streamer instance for live camera feeds and snapshots. Returns `BticinoVideoStreamer`
- `hasVideoStreamer()`: Check if a video streamer instance exists. Returns `boolean`
- `getVideoStreamer()`: Get current video streamer instance or `null`. Returns `BticinoVideoStreamer|null`
- `stopVideoStreamer()`: Stop and dispose the current video streamer. Returns `Promise<void>`
- `captureCameraSnapshot(cameraId, options)`: Capture a single JPEG snapshot (reusing active stream if matching, or spawning an ephemeral session). Returns `Promise<Buffer>`
- `setCertificates(certPEM, privateKeyPem, renewalParams, meta)`: Set certificates and schedule auto-renewal. Returns `enrichedCerts`
- `getCurrentCertificates()`: Get current certificates with metadata. Returns `enrichedCerts|null`
- `forceRenewCertificates(overrideParams)`: Force immediate certificate renewal. Returns `Promise<enrichedCerts>`
- `stop()`: Stop proxy server and cleanup
- `shutdown()`: Graceful shutdown (stops proxy, listener, streamer, and clears timers)
- `dispose()`: Alias for `shutdown()`

**Events:**
- `loginUrlCreated`: Emitted when interactive login is required: `{ state, loginUrl, url }`
- `tokenCreated`: Emitted when tokens are obtained: `(tokens, meta)`
- `tokenRefreshed`: Emitted on token refresh: `(tokens, meta)`
- `deviceRegistered`: Emitted when device registration completes: `(result)`
- `certificatesCreated`: Emitted when certificates are provisioned: `(certs, meta)`
- `certificatesRefreshed`: Emitted when certificates are renewed: `(certs, meta)`
- `sip:connected`: SIP listener connected to server
- `sip:disconnected`: SIP listener disconnected (may auto-reconnect)
- `sip:registered`: Initial or reconnected SIP REGISTER successful
- `sip:keepalive`: Periodic keep-alive confirmed by server
- `sip:invite`: Incoming doorbell call: `{ timestamp, from, to, callId }`
- `sip:callMissed`: Doorbell call ended unanswered: `callContext`
- `sip:callAnswered`: Doorbell call answered by another device: `callContext`
- `sip:callEnded`: SIP call terminated by server: `{ method, ... }`
- `sip:message`: Incoming SIP MESSAGE: `{ from, to, body }`
- `sip:certificatesUpdated`: Listener restarted with new certificates
- `sip:certificateUpdateError`: Failed to update listener certificates
- `sip:error`: SIP listener error: `{ message, code }`
- `video:keyframe`: Raw Annex-B H.264 IDR keyframe received: `(keyframeBuffer)`
- `video:snapshot`: Alias for `video:keyframe`: `(keyframeBuffer)`
- `video:jpeg`: Encoded JPEG snapshot ready: `(jpegBuffer)`
- `video:rtp`: Decrypted plaintext RTP packet: `(rtpPacket)`
- `video:stopped`: Video session terminated
- `video:streamStopped`: Alias for `video:stopped`
- `video:error`: Video streaming error: `(error)`

---

### BticinoVideoStreamer

High-level video streaming orchestrator.

**Methods:**
- `startStream(cameraId, opts)`: Negotiate SIP video INVITE, start SRTP decryption, and launch RTSP loopback server. Returns `Promise<{ rtspUrl, cameraId, cameraIndex, port }>`
- `stopStream()`: Send SIP BYE, terminate UDP/TLS sockets, and stop RTSP server. Returns `Promise<void>`
- `captureSingleSnapshot(cameraId, options)`: Capture an on-demand JPEG snapshot from the specified camera and channel. Returns `Promise<Buffer>`
- `hasSnapshot()`: Check if at least one H.264 video keyframe is cached. Returns `boolean`
- `hasJpegSnapshot()`: Check if at least one JPEG snapshot is cached. Returns `boolean`
- `getLatestSnapshot()`: Retrieve raw Annex-B H.264 keyframe buffer. Returns `Buffer|null`
- `getLatestJpegSnapshot()`: Retrieve encoded JPEG image buffer. Returns `Buffer|null`

---

### BticinoSnapshotExtractor

RFC 6184 RTP H.264 depacketizer with WebAssembly-based H.264 decoding and JPEG encoding.

**Methods:**
- `processRtpPacket(rtpPacket)`: Process decrypted plaintext RTP packet and assemble NAL units
- `convertKeyframeToJpeg(keyframeBuffer, quality)`: Decode Annex-B keyframe into JPEG buffer. Returns `Buffer|null`
- `hasSnapshot()`: Check if an Annex-B keyframe is available. Returns `boolean`
- `hasJpegSnapshot()`: Check if a JPEG snapshot is available. Returns `boolean`
- `getLatestKeyframe()`: Return Annex-B Buffer or `null`
- `getLatestSnapshot()`: Alias for `getLatestKeyframe()`. Returns Annex-B Buffer or `null`
- `getLatestJpegSnapshot()`: Return JPEG Buffer or `null`
- `getSps()`: Return cached SPS NAL unit buffer or `null`
- `getPps()`: Return cached PPS NAL unit buffer or `null`
- `reset()`: Clear internal parameter sets (SPS/PPS) and cached frames

---

### BticinoRtspLoopbackServer

Lightweight RFC 2326 RTSP server providing interleaved TCP and UDP RTP streaming.

**Methods:**
- `start()`: Bind TCP port (default: `0` for ephemeral) and start listening. Returns `Promise<{ port, url, rtspUrl }>`
- `setParameterSets(sps, pps)`: Store H.264 SPS/PPS NAL units for `sprop-parameter-sets` SDP negotiation
- `sendRtpPacket(rtpPacket)`: Send RTP packet to all active playing RTSP sessions
- `broadcastRtp(rtpPacket)`: Alias for `sendRtpPacket(rtpPacket)`
- `getActiveSessionCount()`: Return number of active playing RTSP client sessions
- `isRunning()`: Check server status. Returns `boolean`
- `stop()`: Close active client connections and shutdown TCP server. Returns `Promise<void>`

---

### BticinoSrtpDecryptor

RFC 3711 SRTP decryption engine.

**Methods:**
- `decrypt(packet)`: Decrypt encrypted SRTP packet payload using AES-128-CTR and strip authentication tag. Returns `Buffer|null`

---

### BticinoControls

High-level actuation helper.

**Methods:**
- `openGate(gateId, plantId, certPEM, keyPEM, sipAccount, opts)`: Open lock or pedestrian gate via ephemeral SIP TLS socket. Returns `Promise<void>`

---

## Running Tests

The library includes an automated test suite that runs completely in-memory using mock data and RFC test vectors. **No network connection or real credentials are required.**

Run the complete test suite:
```bash
npm test
```

Run specific test suites:
```bash
# SIP listener & event integration tests
npm run test:integration

# Certificate auto-renewal & graceful restart tests
npm run test:lifecycle

# YUV420 to JPEG conversion tests
npm run test:snapshot

# SRTP, RTSP loopback, and streaming pipeline tests
npm run test:video

# Public package export integrity validation
npm run test:exports
```

---

## Security Considerations

- **Never commit** real tokens, SIP passwords, private keys, certificates, or device/plant dumps to version control.
- `.gitignore` excludes `certs/`, `token/`, `json/`, `examples/*.json`, `.env*`, `*.pem`, `*.key`, `*.crt`, `*.log`, and manual credentialed test scripts.
- Client certificates use mutual TLS (mTLS) with ECC P-256 keys to communicate with BTicino cloud infrastructure.
- All automated tests in `test/` use mocked cryptographic vectors and dummy credentials.

## License

MIT

## Author

**Simone Di Maio** — [GitHub](https://github.com/s-dimaio)

## Disclaimer

This project is an independent open-source library and is not affiliated with, maintained, or endorsed by BTicino or Legrand.

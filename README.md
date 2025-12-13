# BTicino Door Entry 

A reverse-engineered Node.js library and example implementation for controlling BTicino Door Entry gate openers via cloud API and SIP protocol.

## Features

- **Azure AD B2C Authentication**: Complete OAuth2 flow with automatic token refresh
- **Automatic Certificate Refresh**: Certificates are renewed automatically before expiry (30-day skew)
- **Graceful Certificate Restart**: SIP listener automatically restarts with new certificates without service interruption
- **Persistent Doorbell Listener**: Receive real-time doorbell notifications via SIP/TLS with automatic reconnection
- **Local Debug Proxy**: Intercept and debug the authentication flow
- **Device Registration**: Automated first-connection device registration sequence
- **Certificate Provisioning**: Generate and provision client certificates for mTLS
- **SIP Client**: Full SIP/TLS implementation for gate control commands and doorbell events
- **API Client**: Wrapper for BTicino/Legrand Developer API endpoints
- **Token Management**: Automatic token refresh and persistence
- **Event-Driven Architecture**: Centralized events for tokens, registration, certificates, and doorbell notifications
- **Centralized Configuration**: All SIP and authentication constants in one place

## Project Structure

```
.
├── lib/
│   ├── auth/
│   │   ├── BticinoAuthentication.js    # High-level auth orchestrator with SIP factory
│   │   ├── BticinoProxy.js             # Local debug proxy for OAuth
│   │   └── BticinoRegisterDevice.js    # Device registration flow
│   ├── api/
│   │   └── BticinoApiClient.js         # API wrapper
│   ├── certs/
│   │   ├── BticinoCertificates.js      # Certificate generation & provisioning
│   │   └── BticinoCertificateManager.js # Automatic certificate renewal
│   ├── sip/
│   │   ├── BticinoSipClient.js         # SIP/TLS client (ephemeral connections)
│   │   ├── BticinoSipListener.js       # Persistent SIP listener for doorbell
│   │   └── BticinoControls.js          # High-level gate control
│   └── config/
│       └── config.js                    # Centralized configuration (SIP, OAuth, API)
├── examples/
│   ├── auth_and_save.js                # Complete auth + registration example
│   ├── open_from_saved.js              # Open gate using saved credentials
│   ├── listen_doorbell.js              # Persistent doorbell listener
│   └── certificate_lifecycle_demo.js   # Certificate auto-refresh demo
├── test/
│   ├── sip_listener_integration.js     # Integration tests
│   ├── certificate_lifecycle.js        # Certificate lifecycle tests
│   └── package_exports.js              # Package API validation
├── index.js                             # Main entry point with exports
└── package.json
```

## Installation

```bash
npm install
```

## Requirements

- Node.js >= 16
- BTicino/Legrand account
- Access to a BTicino gate opener device

## Quick Start

### 1. First Time Setup (Authentication & Registration)

```javascript
const BticinoAuthentication = require('./lib/auth/BticinoAuthentication');

const auth = new BticinoAuthentication({
  autoOpenBrowser: true,
  debug: true
});

// Listen for token events
auth.on('tokenCreated', (tokens) => {
  console.log('Tokens received:', tokens);
  // Save tokens to disk
});

// Listen for device registration
auth.on('deviceRegistered', (payload) => {
  console.log('Device registered:', payload);
  // Save SIP account details
});

// Listen for certificates
auth.on('certificatesCreated', (info) => {
  console.log('Certificates created');
  // Save cert and key to disk
});

// Start authentication
const { tokens } = await auth.authenticate();

// Create API client
const api = auth.createApiClient({ debug: true });

// Get plants
const plants = await api.getPlants();

// Register device (creates SIP account + certificates)
await auth.registerDevice({ 
  plantId: plants[0].id,
  debug: true 
});
```

### 2. Listen for Doorbell Notifications

```javascript
const { BticinoAuthentication } = require('bticino-door-entry');

// Load saved data
const tokens = require('./token/token_cache.json');
const sipAccount = require('./token/sip_account.json');
const certs = require('./certs/client-certs.json');

// Initialize auth with saved tokens
const auth = new BticinoAuthentication({
  initialTokens: tokens,
  sipClientId: sipAccount.clientId,
  debug: false
});

await auth.authenticate();

// Create persistent SIP listener (integrated!)
const listener = auth.createSipListener(sipAccount, certs, {
  debug: false,
  keepAlive: true,
  autoReconnect: true
});

// All SIP events are forwarded through auth with 'sip:' prefix
auth.on('sip:connected', () => console.log('Connected to SIP server'));
auth.on('sip:registered', () => console.log('Listening for doorbell...'));

auth.on('sip:invite', (callInfo) => {
  console.log('🔔 DOORBELL PRESSED!');
  console.log('Time:', callInfo.timestamp);
  console.log('From:', callInfo.from);
});

auth.on('sip:disconnected', () => console.warn('Disconnected (auto-reconnecting)'));
auth.on('sip:error', (err) => console.error('Error:', err.message));

// Certificate lifecycle (automatic graceful restart)
auth.on('sip:certificatesUpdated', (newCerts) => {
  console.log('Certificates updated - listener restarted automatically');
  // Optionally save new certificates to disk
});

// Connect and register
await listener.connect();
await listener.register();

// The example also shows how to prevent listener duplications:
// See examples/listen_doorbell.js for complete implementation with
// hasSipListener(), isSipListenerConnected(), and getSipListener()
```

### 3. Open Gate with Saved Credentials

```javascript
const { openGate } = require('bticino-door-entry');

// Load saved data
const sipAccount = require('./token/sip_account.json');
const certs = require('./certs/client-certs.json');

// Open gate
await openGate(
  gateId,
  plantId,
  certs.cert,
  certs.key,
  sipAccount,
  { debug: true }
);
```

## API Reference

### BticinoAuthentication

Main authentication orchestrator.

**Constructor Options:**
- `autoOpenBrowser` (boolean): Auto-open browser for login (default: false)
- `debug` (boolean): Enable debug logging (default: false)
- `initialTokens` (Object): Previously saved tokens (default: null)
- `proxyHost` (string): Proxy host for OAuth callback (default: localhost)
- `proxyPort` (number): Proxy port for OAuth callback (default: 8080)
- `autoRefresh` (boolean): Enable automatic token refresh (default: true)
- `refreshSkewSec` (number): Seconds before token expiry to trigger refresh (default: 60)
- `certificateRenewalSkewSec` (number): Seconds before cert expiry to renew (default: 2592000 = 30 days)
- `unrefRefreshTimer` (boolean): Allow process exit with pending timers (default: true)
- `installExitHooks` (boolean): Install SIGINT/SIGTERM handlers for cleanup (default: false)
- `forceLogin` (boolean): Force re-login with prompt=login (default: false)
- `timeoutMs` (number): Login timeout in milliseconds (default: 180000)
- `autoStopOnAuth` (boolean): Stop proxy after auth code capture (default: true)
- `successPage` (string|null): Custom HTML for OAuth callback success page (default: null)

**Methods:**
- `authenticate()`: Start authentication flow. Returns `Promise<{ tokens }>`
- `setInitialTokens(tokens)`: Set tokens after construction (accepts Object or JSON string)
- `ensureStarted()`: Ensure proxy is started (idempotent, safe to call multiple times). Returns `Promise`
- `prepareLoginUrl()`: Generate login URL without starting flow. Returns `{ state, url, fullUrl }`
- `waitForAuthorizationCode(state)`: Poll for auth code from callback. Returns `Promise<{ code, state }>`
- `forceRefresh()`: Force token refresh immediately. Returns `Promise<{ tokens }>`
- `registerDevice(options)`: Register device and provision certificates. Returns `Promise<result>`
- `provisionCertificates(options)`: Force certificate provisioning for existing device. Returns `Promise<certs>`
- `createApiClient(options)`: Create API client instance. Returns `BticinoApiClient`
- `createSipListener(sipAccount, certs, opts)`: **NEW** Create persistent SIP listener for doorbell notifications with automatic certificate refresh. Returns `BticinoSipListener`
- `hasSipListener()`: **NEW** Check if a SIP listener has been created (useful to prevent duplications). Returns `boolean`
- `isSipListenerConnected()`: **NEW** Check if SIP listener is connected and registered (ready to receive calls). Returns `boolean`
- `getSipListener()`: **NEW** Get current SIP listener instance or `null` if none exists. Returns `BticinoSipListener|null`
- `setCertificates(certPEM, privateKeyPem, renewalParams, meta)`: Set certificates and schedule auto-renewal. Returns `enrichedCerts`
- `getCurrentCertificates()`: Get current certificates with metadata. Returns `enrichedCerts|null`
- `forceRenewCertificates(overrideParams)`: Force immediate certificate renewal. Returns `Promise<enrichedCerts>`
- `stop()`: Stop proxy server and cleanup
- `shutdown()`: Graceful shutdown (stops proxy, clears timers, shuts down certificate manager)
- `dispose()`: Alias for `shutdown()`

**Events:**
- `loginUrlCreated`: Emitted when interactive login required. Payload: `{ state, loginUrl, url }`
- `tokenCreated`: Emitted when tokens obtained (initial or refresh). Payload: `(tokens, meta)` where `meta = { refresh?: true, scheduled?: true, immediate?: true }`
- `tokenRefreshed`: Emitted ONLY on token refresh (not on initial login). Payload: `(tokens, meta)`
- `deviceRegistered`: Emitted when device registration completes. Payload: `(result)`
- `certificatesCreated`: Emitted when certificates provisioned. Payload: `(certs, meta)` where `meta = { initial?: true, renewal?: true, forced?: true, scheduled?: true }`
- `certificatesRefreshed`: Emitted ONLY when certificates renewed (scheduled or forced). Payload: `(certs, meta)` where `meta = { renewal: true, forced?: true, scheduled?: true }`
- **`sip:connected`**: **NEW** SIP listener connected to server
- **`sip:disconnected`**: **NEW** SIP listener disconnected (may auto-reconnect)
- **`sip:registered`**: **NEW** SIP REGISTER successful
- **`sip:invite`**: **NEW** Incoming doorbell notification. Payload: `{ timestamp, from, to, callId }`
- **`sip:message`**: **NEW** Incoming SIP MESSAGE. Payload: `{ from, to, body }`
- **`sip:certificatesUpdated`**: **NEW** Listener certificates updated (graceful restart completed)
- **`sip:certificateUpdateError`**: **NEW** Failed to update listener certificates
- **`sip:error`**: **NEW** SIP listener error. Payload: `{ message, code }`

### BticinoApiClient

API wrapper for BTicino/Legrand endpoints.

**Constructor Options:**
- `sipClientId` (string): SIP client identifier (generated if not provided)
- `debug` (boolean): Enable debug logging (default: false)
- `subscriptionKey` (string): Override default API subscription key
- `timeoutMs` (number): Request timeout in milliseconds (default: 30000)

**Methods:**
- `getSipClientId()`: Get current SIP client identifier. Returns `string`
- `getPlants()`: List user plants. Returns `Promise<Array>`
- `getPlant(plantId)`: Get plant details. Returns `Promise<Object>`
- `getModules(plantId)`: List modules/devices. Returns `Promise<Array>`
- `getGatewayModuleId(plantId)`: Find gateway module ID. Returns `Promise<string>`
- `getSipAccounts(gatewayId)`: Get SIP accounts for gateway. Returns `Promise<Array>`
- `getCurrentSipAccount(gatewayId)`: Get current user's SIP account. Returns `Promise<Object>`
- `registerSipAccount(gatewayId, options)`: Register new SIP account. Returns `Promise<Object>`
- `provisionClientCertificate(requestBody)`: Provision client certificate. Returns `Promise<Object>`

### registerDevice(options)

Register device and provision certificates.

**Options:**
- `plantId` (string): Plant UUID to target (required if `gatewayId` not provided)
- `gatewayId` (string): Gateway module UUID (optional, inferred from plantId if omitted)
- `clientName` (string): Custom name for SIP account registration (default: "first-connection")
- `forceCertificates` (boolean): Force certificate provisioning even without new SIP registration (default: false)
- `debug` (boolean): Enable verbose logging for registration flow (default: false)
- `emitter` (EventEmitter): Optional custom event emitter (default: internal emitter forwarded to auth)

**Returns:** `Promise<{ sipAccount, certificates }>`

**Example:**
```javascript
const result = await auth.registerDevice({ 
  plantId: plants[0].id,
  clientName: 'My Smart Lock',
  debug: true 
});

console.log('SIP Account:', result.sipAccount);
console.log('Certificates:', result.certificates);
```

### createSipListener(sipAccount, certs, opts)

**NEW** Factory method in `BticinoAuthentication` to create persistent SIP listener for doorbell notifications.

**Parameters:**
- `sipAccount` (Object): SIP account from `deviceRegistered` event or saved data
  - `sipUri` (string): SIP URI (e.g., "user_clientId@gateway.bs.iotleg.com")
  - `sipPassword` (string): SIP password
  - `plantId` (string): Plant ID
  - `gatewayId` (string, optional): Gateway ID
- `certs` (Object): Certificates from `certificatesCreated` event or saved data
  - `cert` (string): Certificate PEM string
  - `key` (string): Private key PEM string
- `opts` (Object, optional): Listener options
  - `debug` (boolean): Enable debug logging (inherits from auth if not specified)
  - `keepAlive` (boolean): Re-register periodically (default: true)
  - `autoReconnect` (boolean): Reconnect on disconnect (default: true)
  - `keepAliveInterval` (number): Keep-alive interval in ms (default: from config)
  - `reconnectDelay` (number): Reconnect delay in ms (default: from config)

**Returns:** `BticinoSipListener` - Configured listener instance

**Features:**
- Automatic event forwarding through `auth` with `sip:` prefix
- Integrated with certificate manager for graceful restart on certificate renewal
- Automatic validation of sipAccount and certificates
- Uses centralized SIP configuration from `config.js`

**Example:**
```javascript
const listener = auth.createSipListener(sipAccount, certs, { debug: true });

auth.on('sip:invite', (callInfo) => {
  console.log('🔔 Doorbell!', callInfo);
});

await listener.connect();
await listener.register();
```

### BticinoSipListener

**NEW** Persistent SIP listener for receiving doorbell notifications.

**Constructor:**
```javascript
new BticinoSipListener(sipConfig, certs, opts)
```

**Methods:**
- `connect()`: Establish persistent TLS connection. Returns `Promise<void>`
- `register()`: Send SIP REGISTER with digest auth. Returns `Promise<void>`
- `disconnect()`: Gracefully close connection. Returns `Promise<void>`
- `updateCertificates(newCerts)`: **NEW** Update certificates with graceful restart (disconnect, update, reconnect). Returns `Promise<void>`

**Events:**
- `connected`: TLS connection established
- `disconnected`: Connection lost (may auto-reconnect if enabled)
- `registered`: SIP REGISTER successful
- `invite`: Incoming INVITE (doorbell). Payload: `{ timestamp, from, to, callId }`
- `message`: Incoming MESSAGE. Payload: `{ from, to, body }`
- `certificatesUpdated`: Certificates updated successfully with graceful restart
- `certificateUpdateError`: Failed to update certificates
- `error`: Error occurred. Payload: `{ message, code }`

**Note:** When using `auth.createSipListener()`, all events are automatically forwarded through the `auth` object with `sip:` prefix for centralized event handling.

### BticinoControls

High-level gate control.

**Methods:**
- `openGate(gateId, plantId, cert, key, sipAccount, opts)`: Open gate

### BticinoSipClient

Low-level SIP client for custom implementations (ephemeral connections).

**Constructor:**
```javascript
new BticinoSipClient(sipConfig, gateId, plantId, gatewayId, opts, certs)
```

**Methods:**
- `connect()`: Establish TLS connection
- `register()`: Send SIP REGISTER
- `sendGateOpenCommand()`: Send gate open MESSAGE
- `disconnect()`: Close connection


```

## Data Persistence

The library uses the following file structure for persistence:

```
token/
  ├── token_cache.json      # OAuth tokens
  └── sip_account.json      # SIP credentials

certs/
  └── client-certs.json     # Client certificate bundle
```

**Token Format:**
```json
{
  "b2cAccessToken": "eyJhbG...",
  "b2cRefreshToken": "eyJraW...",
  "expiresIn": 3600,
  "receivedAt": 1234567890000,
  "expiresAt": 1234571490000
}
```

**SIP Account Format:**
```json
{
  "sipId": "e5228bc0-...",
  "sipUri": "user_clientId@gateway.bs.iotleg.com",
  "clientId": "130325245365814065359",
  "clientName": "Node.js Gate Opener",
  "username": "user@example.com",
  "userOid": "be372a9a-...",
  "sipPassword": "jk3Z2470",
  "appId": null,
  "plantId": "e914f49e-...",
  "gatewayId": "318cc3ea-...",
  "ownerId": "be372a9a-...",
  "ownerEmail": "user@example.com"
}
```

**Certificate Bundle Format:**
```json
{
  "cert": "-----BEGIN CERTIFICATE-----\n...",
  "key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

## Doorbell Notifications (Persistent Listener)

The library includes a **persistent SIP listener** for receiving real-time doorbell notifications:

**Key Features:**
- **Persistent Connection**: Maintains long-lived TLS connection to SIP server
- **Automatic Reconnection**: Reconnects automatically if connection drops
- **Keep-Alive**: Periodic re-registration to maintain SIP session
- **Event-Driven**: Emits events for doorbell rings, connection status, and errors
- **Graceful Certificate Updates**: Automatically restarts with new certificates during renewal
- **Centralized Events**: All events forwarded through `auth` object with `sip:` prefix

**Basic Usage:**

```javascript
const auth = new BticinoAuthentication({ initialTokens: savedTokens });
await auth.authenticate();

// Create listener using factory method (automatically integrated!)
const listener = auth.createSipListener(sipAccount, certs);

// Listen for doorbell events through auth (centralized)
auth.on('sip:invite', (callInfo) => {
  console.log('🔔 Doorbell pressed!');
  console.log('Time:', callInfo.timestamp);
  console.log('From:', callInfo.from);
});

auth.on('sip:connected', () => console.log('Listener connected'));
auth.on('sip:registered', () => console.log('Listening for doorbell...'));

// Start listening
await listener.connect();
await listener.register();
```

## Certificate Automatic Refresh with Graceful Restart

The library includes **automatic certificate renewal with graceful restart** for the SIP listener:

- **Default Renewal Skew**: 30 days before expiry (2,592,000 seconds)
- **Automatic Scheduling**: Calculates and schedules renewal before expiration
- **Polling Strategy**: Weekly background checks (every 7 days) to detect when renewal is due
- **Event-Driven**: Emits `certificatesRefreshed` event when renewed
- **Transparent**: Works in background without consumer intervention
- **Production-Ready**: Uses polling instead of setTimeout to handle long certificate lifetimes (~8 months)
- **Graceful Restart**: When using `createSipListener()`, the listener automatically restarts with new certificates
- **Service Continuity**: Minimal downtime (~1-2 seconds) during certificate update

**Basic Usage:**

```javascript
// Load certificates at startup
const certs = loadCertificatesFromDisk();
const sipAccount = loadSipAccountFromDisk();

if (certs && sipAccount) {
  // Initialize certificate manager with renewal params
  auth.setCertificates(certs.cert, certs.key, {
    ownerId: sipAccount.ownerId,
    ownerEmail: sipAccount.ownerEmail,
    deviceId: sipAccount.sipClientId,
    plantId: sipAccount.plantId,
    gatewayId: sipAccount.gatewayId
  });
}

// Create listener - will automatically update certificates when renewed
const listener = auth.createSipListener(sipAccount, certs);

// Listen for automatic certificate updates (graceful restart)
auth.on('sip:certificatesUpdated', (newCerts) => {
  console.log('Listener restarted with new certificates automatically!');
  console.log('New expiry:', newCerts.expiresAt);
  saveCertificatesToDisk(newCerts.cert, newCerts.key);
});

// Also listen for certificate manager renewals
auth.on('certificatesRefreshed', (certs, meta) => {
  console.log('Certificates auto-renewed!');
  console.log('New expiry:', certs.expiresAt);
  // Listener will automatically receive new certs and restart
});

// Force manual renewal if needed
await auth.forceRenewCertificates();
```


## Examples

### Complete Flow Example

See `examples/auth_and_save.js` for a complete example showing:
1. Authentication with token persistence
2. Device registration with event handling
3. Certificate provisioning
4. Data persistence to disk

### Doorbell Listener Example

See `examples/listen_doorbell.js` for a persistent doorbell listener showing:
1. Loading saved credentials from disk
2. Creating integrated SIP listener with factory method
3. Handling doorbell events with centralized event pattern
4. Automatic certificate refresh with graceful restart
5. Graceful shutdown handling

### Certificate Lifecycle Demo

See `examples/certificate_lifecycle_demo.js` for automatic certificate management:
1. Automatic certificate renewal detection (30 days before expiry)
2. Graceful listener restart with new certificates
3. Zero-downtime certificate updates
4. Event monitoring for certificate lifecycle

### Reusing Saved Credentials

See `examples/open_from_saved.js` for opening a gate using previously saved:
- Tokens
- SIP account
- Certificates

## Architecture

### Authentication Flow

1. **Proxy Start**: Local proxy starts on configured host/port
2. **Browser Login**: User completes Azure AD B2C login in browser
3. **Code Capture**: Proxy intercepts redirect and captures auth code
4. **Token Exchange**: Exchange code for access + refresh tokens
5. **Token Refresh**: Automatic scheduled refresh before expiry

### Device Registration Flow

1. **API Discovery**: Fetch plants and modules
2. **Gateway Selection**: Identify gateway module
3. **SIP Registration**: Register new SIP account with server
4. **Key Generation**: Generate ECC P-256 keypair
5. **CSR Creation**: Create Certificate Signing Request with SAN
6. **Certificate Provision**: Submit CSR and receive signed certificate
7. **Event Emission**: Emit events with credentials for persistence

### Gate Control Flow

1. **TLS Connection**: Establish mTLS connection to SIP server
2. **SIP REGISTER**: Register with SIP server using digest auth
3. **SIP MESSAGE**: Send JSON-RPC gate open command
4. **Response Handling**: Parse SIP responses and confirm success

## Debugging

Enable debug mode for verbose logging:

```javascript
const auth = new BticinoAuthentication({ debug: true });
const api = auth.createApiClient({ debug: true });

await BticinoControls.openGate(
  gateId, plantId, cert, key, sipAccount, 
  { debug: true }
);
```

Debug output includes:
- HTTP requests/responses
- SIP messages (REGISTER, MESSAGE)
- TLS connection details
- Token refresh scheduling
- Certificate provisioning steps

## Security Considerations

- **Never commit** tokens, SIP passwords, or private keys to version control
- Store certificates securely with appropriate file permissions
- Use environment variables for sensitive configuration
- Tokens are automatically refreshed; avoid manual refresh unless needed
- Client certificates use mTLS for secure SIP communication

## Limitations

- Requires active BTicino/Legrand cloud account
- Gate must be connected to cloud service
- SIP credentials expire and may require re-registration
- Certificates may need renewal (check expiration dates)

## Troubleshooting

### "No SIP account found"
Run device registration to create SIP account:
```javascript
await auth.registerDevice({ plantId, debug: true });
```

### "Certificate or key not found"
Certificates are created during device registration. Listen for `certificatesCreated` event and persist to disk.

### "401 Unauthorized" on API calls
Token expired. Force refresh:
```javascript
await auth.forceRefresh();
```

### "SIP authentication failed"
Check SIP password in saved account matches server. May need to re-register device.

## License

MIT

## Disclaimer

This project is not affiliated with or endorsed by BTicino or Legrand. Use at your own risk. The author is not responsible for any damage or unauthorized access resulting from the use of this software.

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

## Acknowledgments

- BTicino/Legrand for their cloud infrastructure
- The Node.js community for excellent libraries
- PKI.js for pure JavaScript certificate handling

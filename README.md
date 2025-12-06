# BTicino Door Entry 

A reverse-engineered Node.js library and example implementation for controlling BTicino Door Entry gate openers via cloud API and SIP protocol.

## Features

- **Azure AD B2C Authentication**: Complete OAuth2 flow with automatic token refresh
- **Automatic Certificate Refresh**: Certificates are renewed automatically before expiry (30-day skew)
- **Local Debug Proxy**: Intercept and debug the authentication flow
- **Device Registration**: Automated first-connection device registration sequence
- **Certificate Provisioning**: Generate and provision client certificates for mTLS
- **SIP Client**: Full SIP/TLS implementation for gate control commands
- **API Client**: Wrapper for BTicino/Legrand Developer API endpoints
- **Token Management**: Automatic token refresh and persistence
- **Event-Driven Architecture**: Emit events for tokens, registration, and certificates

## Project Structure

```
.
├── lib/
│   ├── auth/
│   │   ├── BticinoAuthentication.js    # High-level auth orchestrator
│   │   ├── BticinoProxy.js             # Local debug proxy for OAuth
│   │   └── BticinoRegisterDevice.js    # Device registration flow
│   ├── api/
│   │   └── BticinoApiClient.js         # API wrapper
│   ├── certs/
│   │   ├── BticinoCertificates.js      # Certificate generation & provisioning
│   │   └── BticinoCertificateManager.js # Automatic certificate renewal
│   ├── sip/
│   │   ├── BticinoSipClient.js         # SIP/TLS client
│   │   └── BticinoControls.js          # High-level gate control
│   └── config/
│       └── config.js                    # Centralized configuration
├── examples/
│   ├── auth_and_save.js                # Complete auth + registration example
│   └── open_from_saved.js              # Open gate using saved credentials
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

### 2. Open Gate with Saved Credentials

```javascript
const BticinoControls = require('./lib/sip/BticinoControls');

// Load saved data
const tokens = require('./token/token_cache.json');
const sipAccount = require('./token/sip_account.json');
const certs = require('./certs/client-certs.json');

// Initialize auth with saved tokens
const auth = new BticinoAuthentication({
  autoOpenBrowser: false,
  initialTokens: tokens
});

await auth.authenticate();

// Create API client with saved SIP client ID
const api = auth.createApiClient({ 
  sipClientId: sipAccount.clientId 
});

// Open gate
await BticinoControls.openGate(
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

### BticinoControls

High-level gate control.

**Methods:**
- `openGate(gateId, plantId, cert, key, sipAccount, opts)`: Open gate

### BticinoSipClient

Low-level SIP client for custom implementations.

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

## Certificate Automatic Refresh

The library now includes **automatic certificate renewal** that works exactly like token refresh:

- **Default Renewal Skew**: 30 days before expiry (2,592,000 seconds)
- **Automatic Scheduling**: Calculates and schedules renewal before expiration
- **Polling Strategy**: Weekly background checks (every 7 days) to detect when renewal is due
- **Event-Driven**: Emits `certificatesRefreshed` event when renewed
- **Transparent**: Works in background without consumer intervention
- **Production-Ready**: Uses polling instead of setTimeout to handle long certificate lifetimes (~8 months)

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

// Listen for automatic renewals
auth.on('certificatesRefreshed', (certs, meta) => {
  console.log('Certificates auto-renewed!');
  console.log('New expiry:', certs.expiresAt);
  saveCertificatesToDisk(certs.certPEM, certs.privateKeyPem);
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

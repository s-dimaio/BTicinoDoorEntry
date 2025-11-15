// Centralized configuration file (migrated from project root .env)
// Sensitive values are intentionally left blank. Edit as needed.
// NOTE: Several formerly-present constants (proxy/host/port and some
// Legrand-specific flags) were removed because the codebase accepts
// proxy host/port via constructor/options and these values were not
// referenced anywhere else. Consumers should pass host/port through
// constructors or environment variables as required.
module.exports = {
  // B2C / OAuth settings
  B2C_TENANT: 'EliotClouduamprd.onmicrosoft.com',
  B2C_TENANT_ID: '199686b5-bef4-4960-8786-7a6b1888fee3',
  B2C_POLICY: 'B2C_1_DoorEliot-DIY-SignUporSignIn',
  B2C_CLIENT_ID: '032e1c93-4c8f-4618-9a9c-0355059678cf',
  B2C_REDIRECT_URI: 'com.legrandgroup.diy://oauth2redirect',
  B2C_SCOPE: 'https://EliotClouduamprd.onmicrosoft.com/security/access.full offline_access openid',
  B2C_RESOURCE: '290cc4ed-9790-44f7-b79c-07895c93e179',

  // Toggle HTTPS for the internal proxy (string '1' mirrors previous .env semantics)
  USE_HTTPS: '0',

  // API subscription key used for Legrand developer API requests. Override in this file
  // if you have a different key to use in your environment.
  SUBSCRIPTION_KEY: 'f36968e522bf4ec3877fa491109d3d14'
};

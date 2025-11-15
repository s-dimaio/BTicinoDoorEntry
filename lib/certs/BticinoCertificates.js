const crypto = require('crypto');

// Logging is controlled per-call via the `opts.debug` flag passed to
// `provisionCertificate`. This avoids a module-level debug flag and allows
// consumers to control verbosity at call time.


/**
 * Create a Certificate Signing Request (CSR) using pure JavaScript (PKI.js).
 * @param {string} privateKeyPEM Private key in PKCS#8 PEM format
 * @param {Array<{name:string,value:string}>} subject Array of subject attributes, e.g. [{name:'commonName',value:'...'}]
 * @param {string} sipUri SIP URI to include in the Subject Alternative Name (SAN)
 * @returns {Promise<string>} CSR encoded as base64 (DER)
 * @throws {Error} If key import or signing fails
 */
async function createCSR(privateKeyPEM, subject, sipUri, opts = {}) {
  const pkijs = require('pkijs');
  const asn1js = require('asn1js');
  const { Crypto } = require('@peculiar/webcrypto');
  const pvutils = require('pvutils');
  const debug = !!opts.debug;
  const _log = (...args) => { if (debug) console.log('[Certificates]', ...args); };
  const _error = (...args) => { console.error('[Certificates]', ...args); };

  // Setup crypto provider (mitigation for pkijs.setEngine deprecation)
  // Create a WebCrypto instance and expose it on `globalThis.crypto` so PKI.js
  // can use it without relying on the deprecated `setEngine` call. If
  // `pkijs.setEngine` is still present (older pkijs versions), call it as a
  // fallback for compatibility.
  const webcrypto = new Crypto();
  if (typeof globalThis !== 'undefined' && !globalThis.crypto) {
    globalThis.crypto = webcrypto;
  }

  const cryptoEngine = new pkijs.CryptoEngine({
    name: 'peculiar-webcrypto',
    crypto: webcrypto,
    subtle: webcrypto.subtle
  });

  if (typeof pkijs.setEngine === 'function') {
    pkijs.setEngine('peculiar-webcrypto', webcrypto, cryptoEngine);
  }

  _log('createCSR: importing private key');
  // Import the private key (PKCS#8 DER buffer)
  const keyData = Buffer.from(
    privateKeyPEM
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s/g, ''),
    'base64'
  );

  const privateKey = await webcrypto.subtle.importKey(
    'pkcs8',
    keyData,
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign']
  );
  _log('createCSR: private key imported');

  // Create the CSR object
  const pkcs10 = new pkijs.CertificationRequest();

  // IMPORTANT: Subject must be built so each AttributeTypeAndValue is in its own
  // SET. Subject is a SEQUENCE of RelativeDistinguishedName, each RDN is a SET
  // of AttributeTypeAndValue. To get separate RDNs (CN=..., OU=...) each
  // AttributeTypeAndValue must be in a separate SET.

  const attrMapping = {
    'commonName': '2.5.4.3',
    'organizationalUnitName': '2.5.4.11',
    'organizationName': '2.5.4.10',
    'localityName': '2.5.4.7',
    'stateOrProvinceName': '2.5.4.8',
    'countryName': '2.5.4.6',
    'emailAddress': '1.2.840.113549.1.9.1'
  };

  // Build the subject manually using typesAndValues with separate RDNs
  pkcs10.subject.typesAndValues = [];

  subject.forEach(attr => {
    const oid = attrMapping[attr.name];
    if (oid) {
      pkcs10.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
          type: oid,
          value: new asn1js.PrintableString({ value: attr.value })
        })
      );
    }
  });

  // WORKAROUND: PKI.js groups all AttributeTypeAndValue into a single RDN by
  // default. Override the serialization to create one SET per AttributeTypeAndValue.
  pkcs10.subject.toSchema = function () {
    // Create a SEQUENCE of SETs, where each SET contains a single AttributeTypeAndValue
    const rdnSequence = [];

    for (const attr of this.typesAndValues) {
      rdnSequence.push(
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: attr.type }),
                attr.value
              ]
            })
          ]
        })
      );
    }

    return new asn1js.Sequence({
      value: rdnSequence
    });
  };

  // Add Subject Alternative Name (SAN)
  const altNames = new pkijs.GeneralNames({
    names: [
      new pkijs.GeneralName({
        type: 6, // uniformResourceIdentifier
        value: sipUri
      })
    ]
  });

  pkcs10.attributes = [
    new pkijs.Attribute({
      type: '1.2.840.113549.1.9.14', // Extension Request
      values: [
        new pkijs.Extensions({
          extensions: [
            new pkijs.Extension({
              extnID: '2.5.29.17', // Subject Alternative Name
              critical: false,
              extnValue: altNames.toSchema().toBER(false)
            })
          ]
        }).toSchema()
      ]
    })
  ];

  // Sign the CSR
  await pkcs10.subjectPublicKeyInfo.importKey(privateKey);
  _log('createCSR: signing CSR');
  await pkcs10.sign(privateKey, 'SHA-256');

  // Export to DER and convert to base64
  const csrDER = pkcs10.toSchema(true).toBER(false);
  const csrBase64 = pvutils.toBase64(pvutils.arrayBufferToString(csrDER));
  _log('createCSR: CSR created, length=', csrBase64.length);

  return csrBase64;
}

/**
 * Provision a client certificate by generating a keypair, creating a CSR and
 * calling the API. The function returns the provisioning response, the
 * generated PEM certificate and the private key PEM so callers can persist
 * them as needed.
 *
 * @param {Object} api API client instance exposing `provisionClientCertificate(request)`
 * @param {Object} [opts] Options for provisioning
 * @param {string} opts.ownerId Owner user id (UUID) - required
 * @param {string} [opts.ownerEmail] Optional owner email used in CSR subject
 * @param {string} opts.gatewayId Gateway UUID - required
 * @param {string} opts.plantId Plant UUID - required
 * @param {string} [opts.plantName] Optional plant display name
 * @param {string} [opts.deviceId] Optional device id to use as CSR Common Name (CN)
 * @param {string} [opts.type] Optional plant/device type forwarded to API
 * @param {string} [opts.country] Optional country code forwarded to API
 * @param {boolean} [opts.debug] Enable verbose debug logging for this call
 * @returns {Promise<Object>} Resolves with an object: `{ provRes, certPEM, privateKeyPem, csr }`
 * @throws {Error} If required parameters are missing or the provisioning API call fails
 */
async function provisionCertificate(api, opts = {}) {
  const {
    ownerId,
    ownerEmail,
    gatewayId,
    plantId,
    plantName,
    deviceId,
    type,
    country,
    debug = false
  } = opts;

  if (!ownerId) throw new Error('ownerId is required for provisioning');
  if (!gatewayId) throw new Error('gatewayId is required for provisioning');
  if (!plantId) throw new Error('plantId is required for provisioning');

  // Per-call debug helpers (do not rely on module-level state)
  const _debug = !!debug;
  const _log = (...args) => { if (_debug) console.log('[Certificates]', ...args); };
  const _error = (...args) => { console.error('[Certificates]', ...args); };

  _log('Starting certificate provisioning with options=', opts);
  _log(`Plant: ${plantName} (${plantId})\n`);

  // 3. Genera coppia di chiavi ECC P-256
  _log('3. Generating ECC P-256 key pair...');
  const { privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',  // P-256
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  _log('Keys generated');
  _log(' - Algorithm: ECC P-256 (prime256v1)');
  _log(' - Private key length:', privateKey.length, 'bytes');
  _log('\n');

  // 4. Crea Certificate Signing Request (CSR)
  _log('4. Creating CSR...');

  // Subject for the CSR (as in the app)
  const subject = [
    { name: 'commonName', value: deviceId },
    { name: 'organizationalUnitName', value: 'DIY' },
    { name: 'organizationName', value: 'LEGRAND' },
    { name: 'localityName', value: 'Paris' },
    { name: 'stateOrProvinceName', value: 'France' },
    { name: 'countryName', value: 'FR' },
    { name: 'emailAddress', value: ownerEmail }
  ];

  // SAN (Subject Alternative Name) - SIP URI
  const sipUri = `sip:${ownerId}_${deviceId}@${gatewayId}.bs.iotleg.com`;

  // Create CSR using pure JavaScript (async) — pass debug flag
  const csr = await createCSR(privateKey, subject, sipUri, { debug });
  _log('CSR created');
  _log(' - Subject CN:', deviceId);
  _log(' - SIP URI:', sipUri);
  _log(' - CSR length:', csr.length, 'bytes\n');

  // 5. Send provisioning request to server
  _log('5. Sending provisioning request to server...');

  const requestBody = {
    csr: csr,
    sender: {
      addressType: "addressLocation",
      plant: {
        _gatewayDbIdx: -1,
        country: country,
        dbIdx: -1,
        id: plantId,
        name: plantName,
        ownerEmail: ownerEmail,
        ownerId: ownerId,
        type: type
      },
      system: "information"
    },
    template: "sipuser-DIY"
  };

  _log('Request body prepared, sending to API...', requestBody);

  try {
    const response = await api.provisionClientCertificate(requestBody);

    _log('Certificate received from server');
    _log(' - Status: 201 Created');
    _log(' - Cert length:', response.cert.length, 'bytes\n');

    // Build PEM encoded certificate (not saved to disk here)
    const certPEM = '-----BEGIN CERTIFICATE-----\n' +
      response.cert.match(/.{1,64}/g).join('\n') +
      '\n-----END CERTIFICATE-----';

    // 7. Verifica certificato (in-memory)
    _log('\n7. Verifying certificate...');
    const cert = new crypto.X509Certificate(certPEM);

    _log(' - Subject:', cert.subject);
    _log(' - Issuer:', cert.issuer);
    _log(' - Valid from:', cert.validFrom);
    _log(' - Valid to:', cert.validTo);
    _log(' - Serial:', cert.serialNumber);

    _log('\n PROVISIONING COMPLETED SUCCESSFULLY (in-memory)');
    _log('Certificate is ready to be used (returned to caller for persistence)');

    // Return everything to the caller so persistence can be handled externally
    return {
      provRes: response,
      certPEM,
      privateKeyPem: privateKey,
      csr
    };

  } catch (error) {
    _error('Error during provisioning:', error.message);
    if (error.response) {
      _error('Status:', error.response.status);
      _error('Data:', error.response.data);
    }
    throw error;
  }
}

module.exports = { provisionCertificate, createCSR };

/**
 * BTicino Door Entry - Main Package Entry Point
 * 
 * Complete Node.js implementation for BTicino Legrand door entry systems.
 * Provides OAuth2 authentication, REST API client, and SIP protocol support
 * for receiving doorbell notifications and opening gates.
 * 
 * @module bticino-door-entry
 * @version See package.json
 * 
 * @example Basic authentication flow
 * const { BticinoAuthentication } = require('bticino-door-entry');
 * 
 * const auth = new BticinoAuthentication({ debug: true });
 * const result = await auth.authenticate();  // Interactive login
 * console.log('Token:', result.tokens.b2cAccessToken);
 * 
 * @example Create doorbell listener
 * const { BticinoAuthentication } = require('bticino-door-entry');
 * 
 * const auth = new BticinoAuthentication({ initialTokens: savedTokens });
 * await auth.authenticate();
 * 
 * const listener = auth.createSipListener(sipAccount, certificates);
 * listener.on('invite', (callInfo) => {
 *   console.log('🔔 Doorbell!', callInfo.timestamp);
 * });
 * 
 * await listener.connect();
 * await listener.register();
 * 
 * @example Open a gate
 * const { openGate } = require('bticino-door-entry');
 * 
 * await openGate(
 *   'gate_device_id',
 *   'plant_uuid',
 *   certificatePEM,
 *   privateKeyPEM,
 *   sipAccount
 * );
 */

const BticinoAuthentication = require('./lib/auth/BticinoAuthentication');
const BticinoApiClient = require('./lib/api/BticinoApiClient');
const { BticinoSipClient, openGate } = require('./lib/sip/BticinoControls');
const { BticinoSipListener } = require('./lib/sip/BticinoSipListener');
const BticinoVideoStreamer = require('./lib/video/BticinoVideoStreamer');
const BticinoRtspLoopbackServer = require('./lib/video/BticinoRtspLoopbackServer');
const BticinoSrtpDecryptor = require('./lib/video/BticinoSrtpDecryptor');
const BticinoSnapshotExtractor = require('./lib/video/BticinoSnapshotExtractor');
const config = require('./lib/config/config');

// Package metadata
const { version, name, description } = require('./package.json');

module.exports = {
  // ===== Authentication & API =====
  
  /** Main authentication orchestrator for OAuth2 flow */
  BticinoAuthentication,
  
  /** API client for REST endpoints */
  BticinoApiClient,
  
  // ===== SIP Communication =====
  
  /** SIP client for sending commands (ephemeral connections) */
  BticinoSipClient,
  
  /** SIP listener for receiving doorbell notifications (persistent connection) */
  BticinoSipListener,
  
  /** High-level helper function to open gate */
  openGate,
  
  // ===== Video Streaming & Decryption =====

  /** High-level video streamer orchestrating SIP INVITE, SRTP decryption, and RTSP loopback */
  BticinoVideoStreamer,

  /** RFC 2326 RTSP loopback streaming server for Homey createVideoRTSP */
  BticinoRtspLoopbackServer,

  /** RFC 3711 AES_CM_128_HMAC_SHA1_80 SRTP packet decryptor */
  BticinoSrtpDecryptor,

  /** RFC 6184 H.264 RTP depacketizer and IDR keyframe snapshot extractor */
  BticinoSnapshotExtractor,
  
  // ===== Configuration =====
  
  /** Centralized configuration constants */
  config,
  
  // ===== Metadata =====
  
  /** Package version */
  version,
  
  /** Package name */
  name,
  
  /** Package description */
  description
};

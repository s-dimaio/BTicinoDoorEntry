/**
 * BticinoVideoStreamer
 *
 * High-level video streamer that coordinates the complete BTicino Door Entry video pipeline:
 * 1. Establishes mTLS SIP connection to Legrand Flexisip (vdesip.bs.iotleg.com:5228) or local gateway.
 * 2. Initiates SIP INVITE / Digest auth / re-INVITE with custom `a=DEVADDR:<cameraId>` SDP attribute.
 * 3. Negotiates SDES-SRTP media parameters (AES_CM_128_HMAC_SHA1_80) and performs UDP hole-punching.
 * 4. Decrypts incoming SRTP H.264 video packets in real-time via BticinoSrtpDecryptor.
 * 5. Serves live H.264 video via BticinoRtspLoopbackServer (rtsp://127.0.0.1:<port>/live) to Homey Pro.
 * 6. Extracts H.264 IDR keyframe snapshots via BticinoSnapshotExtractor.
 *
 * @module BticinoVideoStreamer
 */

'use strict';

const tls = require('tls');
const dgram = require('dgram');
const crypto = require('crypto');
const EventEmitter = require('events');
const os = require('os');

const BticinoSrtpDecryptor = require('./BticinoSrtpDecryptor');
const BticinoRtspLoopbackServer = require('./BticinoRtspLoopbackServer');
const BticinoSnapshotExtractor = require('./BticinoSnapshotExtractor');
const config = require('../config/config');

class BticinoVideoStreamer extends EventEmitter {
  /**
   * Initializes the video streamer with SIP account credentials and TLS client certificates.
   *
   * @public
   * @constructor
   * @param {Object} sipAccount - SIP account details obtained from BticinoApiClient/device registration.
   * @param {string} sipAccount.sipUri - User SIP URI (e.g. user_clientId@gateway.bs.iotleg.com).
   * @param {string} sipAccount.sipPassword - SIP password for Digest authentication.
   * @param {string} [sipAccount.deviceId] - Gateway device UUID.
   * @param {Object} certs - TLS client certificates for mTLS authentication.
   * @param {string|Buffer} certs.cert - Certificate in PEM format (or certPEM).
   * @param {string|Buffer} certs.key - Private key in PEM format (or privateKeyPem).
   * @param {Object} [opts={}] - Configuration options.
   * @param {string} [opts.server] - SIP server host (defaults to vdesip.bs.iotleg.com).
   * @param {number} [opts.port] - SIP server port (defaults to 5228).
   * @param {string} [opts.localGatewayIp] - Optional LAN IP of the physical gateway for local routing.
   * @param {boolean} [opts.debug=false] - Enables verbose debug logging.
   *
   * @example
   * const streamer = new BticinoVideoStreamer(sipAccount, certs, { debug: true });
   * const { rtspUrl } = await streamer.startStream('00000000-0000-0000-0000-000000000000');
   * console.log('Live stream available at:', rtspUrl);
   */
  constructor(sipAccount, certs, opts = {}) {
    super();

    if (!sipAccount || !sipAccount.sipUri || !sipAccount.sipPassword) {
      throw new Error('[BticinoVideoStreamer:constructor] Invalid sipAccount: sipUri and sipPassword are required');
    }

    const certPEM = (certs && (certs.cert || certs.certPEM));
    const keyPEM = (certs && (certs.key || certs.privateKeyPem));
    if (!certPEM || !keyPEM) {
      throw new Error('[BticinoVideoStreamer:constructor] Client certificates (cert and key in PEM format) are required');
    }

    this.sipAccount = sipAccount;
    this.certs = { cert: certPEM, key: keyPEM };
    this.opts = Object.assign({
      server: config.SIP_SERVER || 'vdesip.bs.iotleg.com',
      port: config.SIP_PORT || 5228,
      localGatewayIp: null,
      debug: false,
      // Maximum number of transparent call renewals (each call lasts ~30s on the gateway side)
      maxAutoRestarts: 20,
      // Experimental: proactively send an in-dialog re-INVITE (does not extend the gateway timer)
      reInviteKeepAlive: false,
      // Grace period in milliseconds to stop the SIP stream after all RTSP clients disconnect
      idleTimeoutMs: 2000
    }, opts);

    this._log = (...args) => { if (this.opts.debug) console.log('[BticinoVideoStreamer]', ...args); };
    this._error = (...args) => { console.error('[BticinoVideoStreamer]', ...args); };

    // Parse SIP URI components (strip optional sip:/sips: prefix)
    const cleanSipUri = String(this.sipAccount.sipUri).replace(/^sips?:/i, '').trim();
    const uriParts = cleanSipUri.split('@');
    this.username = uriParts[0].trim();
    this.domain = (uriParts[1] || '').trim();
    this.gatewayId = this.domain.split('.')[0] || this.sipAccount.deviceId || '';

    // Sub-components
    this.rtspServer = new BticinoRtspLoopbackServer({ debug: this.opts.debug });
    this.snapshotExtractor = new BticinoSnapshotExtractor({ debug: this.opts.debug });
    this.srtpDecryptor = null;

    // Networking state
    this._tlsSocket = null;
    this._udpVideoSocket = null;
    this._localVideoPort = 0;
    this._remoteRelayIp = null;
    this._remoteVideoPort = 0;
    this._negotiatedVideoPt = 96;

    // Client crypto keys offered in initial SDP
    this._clientMasterKey = crypto.randomBytes(16);
    this._clientMasterSalt = crypto.randomBytes(14);
    this._clientInlineKey = Buffer.concat([this._clientMasterKey, this._clientMasterSalt]).toString('base64');

    // SIP Call State
    this._callId = crypto.randomBytes(8).toString('hex');
    this._fromTag = crypto.randomBytes(8).toString('hex');
    this._toTag = null;
    this._cseq = 20;
    this._routeSet = [];
    this._activeCameraId = null;
    this._activeCameraIndex = 1;
    this._activeStream = false;
    this._keepAliveTimer = null;
    this._lastAuthHeader = null;
    this._nonceCount = 0;

    // Transparent call renewal state: the gateway terminates every video call after ~30 seconds
    this._restarting = false;
    this._autoRestartCount = 0;
    this._remoteTargetUri = null;

    // RTP continuity state (keeps seq / timestamp / SSRC monotonic across renewed calls)
    this._rtpState = null;
    this._rtpResyncPending = false;

    // Forward snapshot keyframe event
    this.snapshotExtractor.on('keyframe', (keyframeBuffer) => {
      // Publish cached SPS/PPS (without Annex-B start codes) to the RTSP server for sprop-parameter-sets in DESCRIBE
      const sps = this.snapshotExtractor.getSps();
      const pps = this.snapshotExtractor.getPps();
      if (sps && pps) {
        this.rtspServer.setParameterSets(sps.slice(4), pps.slice(4));
      }
      this.emit('keyframe', keyframeBuffer);
      this.emit('snapshot', keyframeBuffer);
    });

    // Forward decoded JPEG snapshot event
    this.snapshotExtractor.on('jpeg', (jpegBuffer) => {
      this.emit('jpeg', jpegBuffer);
    });

    // Auto-stop stream when all RTSP clients disconnect
    this._idleTimer = null;
    this.rtspServer.on('idle', () => {
      const idleTimeoutMs = typeof this.opts.idleTimeoutMs === 'number' ? this.opts.idleTimeoutMs : 2000;
      this._log(`[BticinoVideoStreamer] RTSP server became idle, starting ${Math.round(idleTimeoutMs / 1000)}s shutdown timer...`);
      if (this._idleTimer) clearTimeout(this._idleTimer);
      this._idleTimer = setTimeout(() => {
        if (this._activeStream && this.rtspServer.getActiveSessionCount() === 0) {
          this._log('[BticinoVideoStreamer] Idle timeout elapsed with 0 active clients, stopping stream...');
          this.stopStream().catch((err) => {
            this._log('[BticinoVideoStreamer] Error stopping idle stream:', err.message);
          });
        }
      }, idleTimeoutMs);
      if (this._idleTimer.unref) this._idleTimer.unref();
    });

    this.rtspServer.on('play', () => {
      if (this._idleTimer) {
        this._log('[BticinoVideoStreamer] RTSP client active (PLAY), cancelling idle shutdown timer');
        clearTimeout(this._idleTimer);
        this._idleTimer = null;
      }
    });
  }

  /**
   * Starts live video streaming for a specific camera module ID and channel index.
   * Initializes the local RTSP loopback server, performs SIP call negotiation,
   * switches to secondary camera via in-dialog re-INVITE if requested,
   * starts SRTP decryption and returns the RTSP loopback URL.
   *
   * @public
   * @async
   * @param {string} [cameraId=null] - Optional camera module ID (e.g. '00000000-0000-0000-0000-000000000000' or '00000000..._cam2').
   * @param {Object|number} [opts={}] - Optional configuration object or camera index number.
   * @param {number} [opts.cameraIndex=1] - Video channel index (1 = Main outdoor camera, 2 = Secondary/additional camera).
   * @returns {Promise<{rtspUrl: string, cameraId: string, cameraIndex: number, port: number}>} Stream details.
   *
   * @example
   * const stream = await streamer.startStream('00000000-0000-0000-0000-000000000000', { cameraIndex: 2 });
   * console.log('Connect RTSP player to:', stream.rtspUrl);
   */
  async startStream(cameraId = null, opts = {}) {
    if (this._idleTimer) {
      clearTimeout(this._idleTimer);
      this._idleTimer = null;
    }

    // Resolve cameraIndex (1-based, default 1)
    let cameraIndex = 1;
    if (typeof opts === 'number') {
      cameraIndex = opts;
    } else if (opts && typeof opts.cameraIndex === 'number') {
      cameraIndex = opts.cameraIndex;
    } else if (typeof cameraId === 'string' && /_cam(\d+)$/.test(cameraId)) {
      cameraIndex = parseInt(cameraId.match(/_cam(\d+)$/)[1], 10);
    }
    const cleanCameraId = cameraId ? String(cameraId).replace(/_cam\d+$/, '').trim() : null;

    if (this._activeStream) {
      const now = Date.now();
      const isStalled = !this._restarting &&
        this._receivedUdpCount > 0 &&
        this._lastRtpPacketTimestamp &&
        (now - this._lastRtpPacketTimestamp) > 4000;

      const sameCamera = this._activeCameraId === cleanCameraId && this._activeCameraIndex === cameraIndex;

      if (isStalled || !sameCamera) {
        this._log(`[BticinoVideoStreamer:startStream] Detected existing ${isStalled ? 'stalled' : 'different'} stream, restarting...`);
        await this.stopStream();
      } else {
        return {
          rtspUrl: `rtsp://127.0.0.1:${this.rtspServer._boundPort}/live`,
          cameraId: this._activeCameraId,
          cameraIndex: this._activeCameraIndex,
          port: this.rtspServer._boundPort
        };
      }
    }

    this._activeCameraId = cleanCameraId;
    this._activeCameraIndex = cameraIndex;
    this._autoRestartCount = 0;
    this._restarting = false;
    this._rtpState = null;
    this._rtpResyncPending = false;
    this._resetDialogState();
    this._log(`[BticinoVideoStreamer:startStream] Starting video stream for camera: ${cleanCameraId || 'default'} (index: ${cameraIndex})`);

    // 1. Start RTSP loopback server
    const { port, url: rtspUrl } = await this.rtspServer.start();

    try {
      // 2. Bind local UDP socket for receiving RTP video
      await this._bindLocalUdpSocket();

      // 3. Connect TLS socket and negotiate SIP call (with automatic retry on 486 Busy here).
      // The initial INVITE must ALWAYS carry a=DEVADDR:<cameraId> to activate the External Unit on the 2-wire bus.
      const maxDialAttempts = (opts && typeof opts.maxDialAttempts === 'number') ? opts.maxDialAttempts : 6;
      const retryDelayMs = (opts && typeof opts.retryDelayMs === 'number') ? opts.retryDelayMs : 1500;
      await this._dialWithRetry(cleanCameraId, maxDialAttempts, retryDelayMs);
      this._activeStream = true;

      // 4. If secondary camera requested (channel index > 1), wait 1000ms for 2-wire bus latch and switch via re-INVITE
      // with custom session SDP attributes a=DEVADDR:<cameraId> and a=CAMERASLIDING:2 (matching CallManager.cycle in official app)
      if (this._activeCameraIndex > 1) {
        this._log(`[BticinoVideoStreamer:startStream] Camera index ${this._activeCameraIndex} requested (> 1), waiting 1000ms before re-INVITE with CAMERASLIDING...`);
        await new Promise((r) => setTimeout(r, 1000));
        await this._sendReInvite(cleanCameraId, '2');
      }
    } catch (err) {
      // Clean up partially opened resources if initial dial fails
      await this._teardownResources();
      throw err;
    }

    this._activeStream = true;
    this._startRtpKeepAlive();

    this._log('[BticinoVideoStreamer:startStream] Video streaming pipeline active at:', rtspUrl);
    return { rtspUrl, cameraId: this._activeCameraId, cameraIndex: this._activeCameraIndex, port };
  }

  /**
   * Connects TLS and negotiates the SIP INVITE call, retrying automatically if the gateway
   * temporarily returns 486 Busy here / 480 Temporarily Unavailable / 503 Service Unavailable
   * (e.g. while the 2-wire bus is still releasing a previous call).
   *
   * @private
   * @async
   * @param {string|null} cameraId - Target camera module UUID.
   * @param {number} [maxAttempts=6] - Maximum number of dial attempts.
   * @param {number} [retryDelayMs=1500] - Delay in milliseconds between retry attempts.
   * @returns {Promise<void>}
   */
  async _dialWithRetry(cameraId, maxAttempts = 6, retryDelayMs = 1500) {
    let lastErr = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        if (attempt > 1) {
          this._resetDialogState();
        }
        await this._connectTls();
        await this._negotiateSipCall(cameraId);
        return;
      } catch (err) {
        lastErr = err;
        this._detachDialogSipListener();
        if (this._tlsSocket) {
          const sock = this._tlsSocket;
          this._tlsSocket = null;
          try { sock.destroy(); } catch (_) {}
        }

        const isBusyOrTransient = err && (
          err.sipStatusCode === 486 ||
          err.sipStatusCode === 480 ||
          err.sipStatusCode === 481 ||
          err.sipStatusCode === 408 ||
          err.sipStatusCode === 503 ||
          /486|480|481|408|503/.test(err.message || '')
        );

        if (attempt < maxAttempts && isBusyOrTransient) {
          this._log(`[BticinoVideoStreamer:_dialWithRetry] Gateway busy (${err.message}), retrying in ${retryDelayMs}ms (attempt ${attempt + 1}/${maxAttempts})...`);
          await new Promise((r) => setTimeout(r, retryDelayMs));
          continue;
        }
        throw err;
      }
    }
    if (lastErr) throw lastErr;
  }

  /**
   * Resets the SIP dialog state for a fresh call (new Call-ID, From tag, CSeq, and empty Route set).
   *
   * @private
   * @returns {void}
   */
  _resetDialogState() {
    this._callId = crypto.randomBytes(8).toString('hex');
    this._fromTag = crypto.randomBytes(8).toString('hex');
    this._toTag = null;
    this._cseq = 20;
    this._routeSet = [];
    this._remoteTargetUri = null;
    this._lastAuthHeader = null;
    this._nonceCount = 0;
  }

  /**
   * Tears down RTSP, UDP, and TLS sockets without emitting stream stop events.
   *
   * @private
   * @async
   * @returns {Promise<void>}
   */
  async _teardownResources() {
    if (this._keepAliveTimer) {
      clearInterval(this._keepAliveTimer);
      this._keepAliveTimer = null;
    }

    this._detachDialogSipListener();

    try {
      await this.rtspServer.stop();
    } catch (_) {}

    if (this._udpVideoSocket) {
      try { this._udpVideoSocket.close(); } catch (_) {}
      this._udpVideoSocket = null;
    }

    if (this._tlsSocket) {
      const sock = this._tlsSocket;
      this._tlsSocket = null;
      try { sock.end(); } catch (_) {}
    }
  }

  /**
   * Stops live video streaming, sends SIP BYE to terminate the call,
   * closes all UDP/TLS sockets, and shuts down the RTSP loopback server.
   *
   * @public
   * @async
   * @returns {Promise<void>}
   *
   * @example
   * await streamer.stopStream();
   */
  async stopStream() {
    if (this._idleTimer) {
      clearTimeout(this._idleTimer);
      this._idleTimer = null;
    }

    if (!this._activeStream && !this._restarting) {
      return;
    }

    this._log('[BticinoVideoStreamer:stopStream] Stopping video stream...');
    this._activeStream = false;
    this._restarting = false;

    if (this._keepAliveTimer) {
      clearInterval(this._keepAliveTimer);
      this._keepAliveTimer = null;
    }

    this._detachDialogSipListener();

    // 1. Send SIP BYE if dialog was established
    if (this._tlsSocket && !this._tlsSocket.destroyed && this._toTag) {
      try {
        await this._sendBye();
      } catch (err) {
        this._log('[BticinoVideoStreamer:stopStream] SIP BYE warning:', err.message);
      }
    }

    // 2. Stop RTSP, UDP, and TLS resources
    await this._teardownResources();

    this.snapshotExtractor.reset();
    this.emit('stopped');
    this.emit('streamStopped');
    this._log('[BticinoVideoStreamer:stopStream] Video stream stopped cleanly');
  }

  /**
   * Captures a single on-demand JPEG snapshot from the specified camera and channel.
   * If a stream is already active on this instance, returns the latest or next available JPEG snapshot.
   * If no stream is active, establishes an ephemeral video session, awaits the first
   * complete JPEG snapshot, and cleanly stops the session to release the 2-wire bus.
   *
   * @public
   * @async
   * @param {string|null} [cameraId=null] - Module UUID of the camera station.
   * @param {Object} [options={}] - Options.
   * @param {number} [options.cameraIndex=1] - Video channel index (1 for main outdoor unit, 2 for aux).
   * @param {number} [options.timeoutMs=15000] - Maximum milliseconds to await a keyframe.
   * @param {number} [options.jpegQuality=85] - Target JPEG compression quality (1-100).
   * @param {number} [options.maxDialAttempts=6] - Maximum retry attempts when gateway reports 486 busy.
   * @param {number} [options.retryDelayMs=1500] - Delay between retry attempts in milliseconds.
   * @returns {Promise<Buffer>} Resolved with the encoded JPEG image buffer.
   * @throws {Error} If the stream cannot be started or snapshot capture times out.
   *
   * @example
   * const jpegBuffer = await streamer.captureSingleSnapshot('00000000-0000-0000-0000-000000000000', { cameraIndex: 1 });
   */
  async captureSingleSnapshot(cameraId = null, options = {}) {
    const cameraIndex = options.cameraIndex || 1;
    const timeoutMs = options.timeoutMs || 15000;
    const jpegQuality = options.jpegQuality || 85;
    const maxDialAttempts = options.maxDialAttempts || 6;
    const retryDelayMs = options.retryDelayMs || 1500;

    const cleanTargetId = cameraId ? String(cameraId).replace(/_cam\d+$/, '').trim() : null;
    const cleanActiveId = this._activeCameraId ? String(this._activeCameraId).replace(/_cam\d+$/, '').trim() : null;
    const isSameCamera = (!cleanTargetId || cleanTargetId === cleanActiveId) && (Number(cameraIndex) === Number(this._activeCameraIndex));

    // Case 1: Stream is already active for this camera
    if (this._activeStream && isSameCamera) {
      if (!options.forceFresh && this.snapshotExtractor.hasJpegSnapshot()) {
        const cached = this.snapshotExtractor.getLatestJpegSnapshot();
        if (cached) return cached;
      }
      return new Promise((resolve, reject) => {
        let timer = null;
        const cleanup = () => {
          if (timer) clearTimeout(timer);
          this.snapshotExtractor.removeListener('jpeg', onJpeg);
          this.snapshotExtractor.removeListener('keyframe', onKeyframe);
        };

        const onJpeg = (buf) => {
          cleanup();
          resolve(buf);
        };

        const onKeyframe = (keyframe) => {
          const converted = this.snapshotExtractor.convertKeyframeToJpeg(keyframe, jpegQuality);
          if (converted) {
            cleanup();
            resolve(converted);
          }
        };

        timer = setTimeout(() => {
          cleanup();
          reject(new Error(`Timeout waiting for live snapshot after ${timeoutMs}ms`));
        }, timeoutMs);

        this.snapshotExtractor.once('jpeg', onJpeg);
        this.snapshotExtractor.once('keyframe', onKeyframe);
      });
    }

    // If stream is active on a different camera, stop it before ephemeral dial
    if (this._activeStream && !isSameCamera) {
      this._log(`[BticinoVideoStreamer:captureSingleSnapshot] Active stream is on channel ${this._activeCameraIndex}, stopping before capturing channel ${cameraIndex}...`);
      await this.stopStream();
    }

    // Case 2: Ephemeral on-demand stream
    this._log(`[BticinoVideoStreamer:captureSingleSnapshot] Starting ephemeral stream for cameraId: ${cameraId || 'default'} (channel: ${cameraIndex})...`);

    let resolved = false;
    let timer = null;

    try {
      const snapshotPromise = new Promise((resolve, reject) => {
        const cleanup = () => {
          if (timer) clearTimeout(timer);
          this.snapshotExtractor.removeListener('jpeg', onJpeg);
          this.snapshotExtractor.removeListener('keyframe', onKeyframe);
        };

        const onJpeg = (buf) => {
          if (resolved) return;
          resolved = true;
          cleanup();
          resolve(buf);
        };

        const onKeyframe = (keyframe) => {
          if (resolved) return;
          const converted = this.snapshotExtractor.convertKeyframeToJpeg(keyframe, jpegQuality);
          if (converted) {
            resolved = true;
            cleanup();
            resolve(converted);
          }
        };

        timer = setTimeout(() => {
          cleanup();
          reject(new Error(`Timeout awaiting snapshot keyframe after ${timeoutMs}ms`));
        }, timeoutMs);

        this.snapshotExtractor.once('jpeg', onJpeg);
        this.snapshotExtractor.once('keyframe', onKeyframe);
      });

      // Start stream with extended retry budget for active doorbell ring scenarios
      await this.startStream(cameraId, { cameraIndex, maxDialAttempts, retryDelayMs });

      // Await snapshot
      const jpegBuffer = await snapshotPromise;
      return jpegBuffer;
    } finally {
      if (timer) clearTimeout(timer);
      try {
        await this.stopStream();
      } catch (err) {
        this._log('[BticinoVideoStreamer:captureSingleSnapshot] Error stopping ephemeral stream:', err.message);
      }
    }
  }

  /**
   * Handles call termination initiated by the remote gateway (SIP BYE at the ~30s hardware limit)
   * or detected via RTP silence. If RTSP clients are still actively watching and the auto-restart
   * limit has not been reached, transparently re-dials the SIP call while keeping the RTSP server open.
   *
   * @private
   * @param {string} reason - Reason for call end ('remote-bye' | 'rtp-silence' | 'tls-closed').
   * @returns {void}
   */
  _handleCallEnded(reason) {
    if (!this._activeStream || this._restarting) {
      return;
    }

    const activeClients = this.rtspServer ? this.rtspServer.getActiveSessionCount() : 0;
    const maxRestarts = typeof this.opts.maxAutoRestarts === 'number' ? this.opts.maxAutoRestarts : 20;

    if (activeClients > 0 && this._autoRestartCount < maxRestarts) {
      this._restartCall(reason).catch((err) => {
        this._error('[BticinoVideoStreamer:_handleCallEnded] Transparent call renewal failed:', err.message);
        this.stopStream().catch(() => {});
      });
    } else {
      this._log(`[BticinoVideoStreamer:_handleCallEnded] Stopping stream (reason: ${reason}, activeClients: ${activeClients}, restarts: ${this._autoRestartCount}/${maxRestarts})`);
      this.stopStream().catch((err) => {
        this._log('[BticinoVideoStreamer:_handleCallEnded] Error stopping stream:', err.message);
      });
    }
  }

  /**
   * Transparently re-establishes a new SIP video call with the gateway while keeping the local
   * RTSP loopback server and UDP video socket alive so the Homey player experiences an uninterrupted stream.
   *
   * @private
   * @async
   * @param {string} reason - Trigger reason for the renewal.
   * @returns {Promise<void>}
   */
  async _restartCall(reason) {
    if (!this._activeStream || this._restarting) {
      return;
    }

    this._restarting = true;
    this._autoRestartCount++;
    const attemptNum = this._autoRestartCount;
    const maxRestarts = typeof this.opts.maxAutoRestarts === 'number' ? this.opts.maxAutoRestarts : 20;

    this._log(`[BticinoVideoStreamer:_restartCall] Renewing SIP video call #${attemptNum}/${maxRestarts} (reason: ${reason}) while keeping RTSP stream open...`);

    if (this._keepAliveTimer) {
      clearInterval(this._keepAliveTimer);
      this._keepAliveTimer = null;
    }

    this._detachDialogSipListener();

    if (this._tlsSocket) {
      const oldSocket = this._tlsSocket;
      this._tlsSocket = null;
      try { oldSocket.destroy(); } catch (_) {}
    }

    // Mark RTP continuity state for resynchronization on the first packet of the new call
    if (this._rtpState) {
      this._rtpResyncPending = true;
    }

    let lastErr = null;
    for (let retry = 1; retry <= 3; retry++) {
      if (!this._activeStream) {
        this._restarting = false;
        return;
      }

      try {
        // Brief pause before re-dialing so the gateway 2-wire bus finishes releasing the previous call
        const delayMs = retry === 1 ? 150 : 1000;
        await new Promise((r) => setTimeout(r, delayMs));

        if (!this._activeStream) {
          this._restarting = false;
          return;
        }

        this._resetDialogState();
        await this._connectTls();
        const cleanCameraId = this._activeCameraId ? this._activeCameraId.split('#')[0] : null;
        await this._negotiateSipCall(cleanCameraId);

        if (!this._activeStream) {
          this._restarting = false;
          return;
        }

        // If secondary camera channel (> 1) was active, wait 300ms (bus already energized) and re-issue in-dialog re-INVITE with CAMERASLIDING:2
        if (this._activeCameraIndex > 1) {
          this._log(`[BticinoVideoStreamer:_restartCall] Renewing secondary camera index ${this._activeCameraIndex}, waiting 300ms before re-INVITE with CAMERASLIDING...`);
          await new Promise((r) => setTimeout(r, 300));
          if (!this._activeStream) {
            this._restarting = false;
            return;
          }
          await this._sendReInvite(cleanCameraId, '2');
        }

        if (!this._activeStream) {
          this._restarting = false;
          return;
        }

        this._restarting = false;
        this._lastRtpPacketTimestamp = Date.now();
        this._startRtpKeepAlive();
        this._log(`[BticinoVideoStreamer:_restartCall] SIP video call renewed successfully (#${attemptNum})`);
        return;
      } catch (err) {
        lastErr = err;
        this._log(`[BticinoVideoStreamer:_restartCall] Renewal attempt ${retry}/3 failed: ${err.message}`);
        this._detachDialogSipListener();
        if (this._tlsSocket) {
          const sock = this._tlsSocket;
          this._tlsSocket = null;
          try { sock.destroy(); } catch (_) {}
        }
      }
    }

    this._restarting = false;
    throw lastErr || new Error('Failed to renew SIP call after 3 attempts');
  }

  /**
   * Returns the most recent H.264 Annex-B keyframe buffer captured from the stream.
   *
   * @public
   * @returns {Buffer|null} Complete Annex-B H.264 I-frame buffer.
   */
  getLatestSnapshot() {
    return this.snapshotExtractor.getLatestSnapshot();
  }

  /**
   * Checks whether at least one keyframe snapshot is cached.
   *
   * @public
   * @returns {boolean} True if snapshot is cached.
   */
  hasSnapshot() {
    return this.snapshotExtractor.hasSnapshot();
  }

  /**
   * Returns the most recent decoded JPEG snapshot buffer captured from the stream.
   *
   * @public
   * @returns {Buffer|null} Complete JPEG image buffer, or null if none decoded yet.
   *
   * @example
   * const jpeg = streamer.getLatestJpegSnapshot();
   */
  getLatestJpegSnapshot() {
    return this.snapshotExtractor.getLatestJpegSnapshot();
  }

  /**
   * Checks whether at least one decoded JPEG snapshot is cached.
   *
   * @public
   * @returns {boolean} True if a JPEG snapshot is cached.
   *
   * @example
   * if (streamer.hasJpegSnapshot()) {
   *   const img = streamer.getLatestJpegSnapshot();
   * }
   */
  hasJpegSnapshot() {
    return this.snapshotExtractor.hasJpegSnapshot();
  }

  /**
   * Binds a local UDP socket on an ephemeral port to receive incoming SRTP video packets.
   *
   * @private
   * @returns {Promise<void>}
   */
  _bindLocalUdpSocket() {
    return new Promise((resolve, reject) => {
      this._udpVideoSocket = dgram.createSocket('udp4');

      this._udpVideoSocket.on('error', (err) => {
        this._error('[BticinoVideoStreamer:_bindLocalUdpSocket] UDP socket error:', err.message);
      });

      this._udpVideoSocket.on('message', (msg) => {
        this._handleIncomingUdpPacket(msg);
      });

      this._udpVideoSocket.bind(0, '0.0.0.0', () => {
        this._localVideoPort = this._udpVideoSocket.address().port;
        this._log(`[BticinoVideoStreamer:_bindLocalUdpSocket] Local UDP video socket bound on port ${this._localVideoPort}`);
        resolve();
      });
    });
  }

  /**
   * Connects mTLS socket to the Legrand Flexisip server.
   *
   * @private
   * @returns {Promise<void>}
   */
  _connectTls() {
    return new Promise((resolve, reject) => {
      const serverHost = this.opts.localGatewayIp || this.opts.server;
      const serverPort = this.opts.port;

      this._log(`[BticinoVideoStreamer:_connectTls] Connecting TLS socket to ${serverHost}:${serverPort}...`);

      const tlsOptions = {
        host: serverHost,
        port: serverPort,
        rejectUnauthorized: false,
        cert: this.certs.cert,
        key: this.certs.key
      };

      let connected = false;
      const socket = tls.connect(tlsOptions, () => {
        connected = true;
        this._log('[BticinoVideoStreamer:_connectTls] mTLS connection established');
        resolve();
      });

      this._tlsSocket = socket;

      socket.on('error', (err) => {
        this._error('[BticinoVideoStreamer:_connectTls] TLS socket error:', err.message);
        if (!connected) {
          reject(err);
        }
      });

      socket.on('close', () => {
        if (this._tlsSocket === socket && this._activeStream && !this._restarting) {
          this._log('[BticinoVideoStreamer:_connectTls] TLS socket closed unexpectedly by remote peer');
          this._handleCallEnded('tls-closed');
        }
      });
    });
  }

  /**
   * Executes the full SIP INVITE negotiation:
   * 1. Sends initial INVITE with SDP offer.
   * 2. Handles 407 Proxy Authentication Required and resends authenticated INVITE.
   * 3. Awaits 200 OK with SDP answer and parses remote media relay IP/port and SRTP key.
   * 4. Sends ACK and attaches in-dialog listener.
   *
   * @private
   * @param {string|null} cameraId - Optional camera module ID.
   * @returns {Promise<void>}
   */
  async _negotiateSipCall(cameraId) {
    this._sdpSessionVersion = 3658;
    this._receivedUdpCount = 0;
    this._decryptedRtpCount = 0;
    // Initial INVITE must include a=DEVADDR:<cameraId> to target the ExternalUnit camera
    // (without a=DEVADDR, the gateway treats an INVITE to sip:diy@... as an internal CallHome intercom call)
    const sdpOffer = this._buildSdpOffer(cameraId, this._sdpSessionVersion);
    this._cseq = 20;

    // Send initial INVITE
    this._log(`[BticinoVideoStreamer:_negotiateSipCall] Sending initial SIP INVITE (DEVADDR: ${cameraId || 'none'})...`);
    const initialInvite = this._buildSipInvite({
      cseq: this._cseq,
      sdp: sdpOffer
    });

    const response = await this._sendSipRequestAndAwaitResponse(initialInvite);

    // Handle 407 Proxy Authentication Required
    if (response.statusCode === 407 || response.statusCode === 401) {
      this._log(`[BticinoVideoStreamer:_negotiateSipCall] Received ${response.statusCode} authentication challenge`);
      const authHeader = response.headers['proxy-authenticate'] || response.headers['www-authenticate'];
      this._lastAuthHeader = authHeader;
      this._nonceCount = 0;
      const proxyAuth = this._computeProxyAuthorization(this._lastAuthHeader, 'INVITE');

      // Send ACK for 407 (RFC 3261 Section 17.1.1.3: must use same branch and challenge To header)
      const ack407 = this._buildSipAck(this._cseq, {
        branch: this._lastInviteBranch,
        toHeader: response.headers['to'],
        isNon2xx: true
      });
      this._tlsSocket.write(ack407);

      // Resend authenticated INVITE with incremented CSeq
      this._cseq++;
      this._log(`[BticinoVideoStreamer:_negotiateSipCall] Resending authenticated INVITE (CSeq: ${this._cseq})...`);
      const authInvite = this._buildSipInvite({
        cseq: this._cseq,
        sdp: sdpOffer,
        proxyAuth
      });

      const finalResponse = await this._sendSipRequestAndAwaitResponse(authInvite);
      if (finalResponse.statusCode !== 200) {
        const err = new Error(`[BticinoVideoStreamer:_negotiateSipCall] SIP INVITE failed with status ${finalResponse.statusCode} ${finalResponse.statusText}`);
        err.sipStatusCode = finalResponse.statusCode;
        throw err;
      }

      this._handleSdpAnswer(finalResponse);

      // Send ACK for 200 OK
      const ack200 = this._buildSipAck(this._cseq);
      this._tlsSocket.write(ack200);
      this._attachDialogSipListener();
    } else if (response.statusCode === 200) {
      this._handleSdpAnswer(response);
      const ack200 = this._buildSipAck(this._cseq);
      this._tlsSocket.write(ack200);
      this._attachDialogSipListener();
    } else {
      const err = new Error(`[BticinoVideoStreamer:_negotiateSipCall] Unexpected SIP response: ${response.statusCode} ${response.statusText}`);
      err.sipStatusCode = response.statusCode;
      throw err;
    }
  }

  /**
   * Parses the SDP answer from 200 OK to extract remote media relay IP, video port, and SRTP key.
   *
   * @private
   * @param {Object} response - Parsed SIP response object.
   * @returns {void}
   */
  _handleSdpAnswer(response) {
    this._toTag = response.headers['to-tag'] || response.headers['totag'] || this._toTag;
    if (!this._toTag && response.headers['to']) {
      const match = String(response.headers['to']).match(/tag=([^\s;>]+)/);
      if (match) this._toTag = match[1];
    }

    // Extract remote Contact URI for in-dialog requests (RFC 3261 Section 12.1.2)
    if (response.headers['contact']) {
      const contactHeader = Array.isArray(response.headers['contact'])
        ? response.headers['contact'][0]
        : response.headers['contact'];
      const contactMatch = String(contactHeader).match(/<([^>]+)>/);
      if (contactMatch) {
        this._remoteTargetUri = contactMatch[1];
      }
    }

    // Extract Record-Route headers to build in-dialog Route set (only on initial dialog establishment)
    if (response.headers['record-route'] && this._routeSet.length === 0) {
      const rrHeaders = Array.isArray(response.headers['record-route'])
        ? response.headers['record-route'].slice()
        : [response.headers['record-route']];

      this._routeSet = rrHeaders.reverse();
    }

    const sdpBody = response.body || '';
    this._log('[BticinoVideoStreamer:_handleSdpAnswer] Parsing gateway SDP answer:\n' + sdpBody);

    // Extract connection IP (c=IN IP4 <ip>)
    const cMatch = sdpBody.match(/c=IN\s+IP4\s+([0-9\.]+)/i);
    if (cMatch) {
      this._remoteRelayIp = cMatch[1];
    } else if (!this._remoteRelayIp) {
      this._remoteRelayIp = this.opts.server;
    }

    // Extract video port and payload type (m=video <port> RTP/SAVP <pt>)
    const mMatch = sdpBody.match(/m=video\s+(\d+)\s+RTP\/SAVP(?:\s+(\d+))?/i);
    if (mMatch) {
      this._remoteVideoPort = parseInt(mMatch[1], 10);
      if (mMatch[2]) {
        this._negotiatedVideoPt = parseInt(mMatch[2], 10);
      }
    }

    // Extract video SRTP crypto key from the m=video section specifically
    const videoSectionIdx = sdpBody.indexOf('m=video');
    const searchArea = videoSectionIdx !== -1 ? sdpBody.slice(videoSectionIdx) : sdpBody;
    // The gateway selects one of the offered suites (_80 or _32): honour the negotiated one
    const cryptoMatches = searchArea.match(/a=crypto:\d+\s+(AES_CM_128_HMAC_SHA1_(?:80|32))\s+inline:([a-zA-Z0-9+/=|]+)/i);
    if (cryptoMatches) {
      const suite = cryptoMatches[1].toUpperCase();
      const inlineKey = cryptoMatches[2];
      this.srtpDecryptor = new BticinoSrtpDecryptor(inlineKey, { debug: this.opts.debug, suite });
      this._log(`[BticinoVideoStreamer:_handleSdpAnswer] Initialized video SRTP decryptor (suite: ${suite}, auth tag: ${this.srtpDecryptor.authTagLen} bytes)`);
    } else {
      this._error('[BticinoVideoStreamer:_handleSdpAnswer] WARNING: No matching a=crypto AES_CM_128_HMAC_SHA1_80/32 line found in video SDP!');
    }

    this._log(`[BticinoVideoStreamer:_handleSdpAnswer] Media Relay endpoint: ${this._remoteRelayIp}:${this._remoteVideoPort}`);
  }

  /**
   * Sends in-dialog re-INVITE (linphone_call_update) with custom session-level a=DEVADDR and optional
   * a=CAMERASLIDING attributes to cycle/select cameras on the 2-wire bus or renew an active session.
   *
   * @private
   * @async
   * @param {string} cameraId - Camera module UUID.
   * @param {string|null} [cameraSliding=null] - Optional CAMERASLIDING value ('2' to switch camera).
   * @returns {Promise<void>}
   */
  async _sendReInvite(cameraId, cameraSliding = null) {
    if (!this._tlsSocket || this._tlsSocket.destroyed || !this._toTag) {
      this._log('[BticinoVideoStreamer:_sendReInvite] Cannot send re-INVITE: TLS socket not connected or dialog not established');
      return;
    }

    this._detachDialogSipListener();

    this._cseq++;
    this._sdpSessionVersion = (this._sdpSessionVersion || 3658) + 1;
    const requestUri = this._remoteTargetUri || `sip:diy@${this.domain}`;
    this._log(`[BticinoVideoStreamer:_sendReInvite] Sending re-INVITE for camera ${cameraId} (CAMERASLIDING: ${cameraSliding || 'none'}, CSeq: ${this._cseq})...`);

    const sdpOffer = this._buildSdpOffer(cameraId, this._sdpSessionVersion, cameraSliding);
    const proxyAuth = this._lastAuthHeader
      ? this._computeProxyAuthorization(this._lastAuthHeader, 'INVITE', requestUri)
      : null;
    const reInvite = this._buildSipInvite({
      cseq: this._cseq,
      sdp: sdpOffer,
      proxyAuth,
      targetUri: requestUri
    });

    try {
      let response = await this._sendSipRequestAndAwaitResponse(reInvite, 5000);
      if (response.statusCode === 407 || response.statusCode === 401) {
        const authHeader = response.headers['proxy-authenticate'] || response.headers['www-authenticate'];
        this._lastAuthHeader = authHeader;
        this._nonceCount = 0;
        const newProxyAuth = this._computeProxyAuthorization(this._lastAuthHeader, 'INVITE', requestUri);
        const ack407 = this._buildSipAck(this._cseq, {
          branch: this._lastInviteBranch,
          toHeader: response.headers['to'],
          isNon2xx: true,
          targetUri: requestUri
        });
        this._tlsSocket.write(ack407);

        this._cseq++;
        const authReInvite = this._buildSipInvite({
          cseq: this._cseq,
          sdp: sdpOffer,
          proxyAuth: newProxyAuth,
          targetUri: requestUri
        });
        response = await this._sendSipRequestAndAwaitResponse(authReInvite, 5000);
      }

      if (response.statusCode === 200) {
        this._handleSdpAnswer(response);
        const ack = this._buildSipAck(this._cseq);
        this._tlsSocket.write(ack);
        this._log('[BticinoVideoStreamer:_sendReInvite] Session re-INVITE confirmed by gateway (camera switched)');
        this._rtpResyncPending = true;
        this.snapshotExtractor.reset();
      } else {
        this._log(`[BticinoVideoStreamer:_sendReInvite] re-INVITE returned status ${response.statusCode} ${response.statusText}`);
      }
    } catch (err) {
      this._log('[BticinoVideoStreamer:_sendReInvite] re-INVITE non-fatal warning:', err.message);
    } finally {
      if (this._tlsSocket && !this._tlsSocket.destroyed && !this._dialogDataListener) {
        this._attachDialogSipListener();
      }
    }
  }

  /**
   * Attaches an in-dialog SIP data listener to the TLS socket to handle server-initiated
   * messages such as remote BYE (call termination) or OPTIONS pings.
   *
   * @private
   * @returns {void}
   */
  _attachDialogSipListener() {
    if (!this._tlsSocket || this._dialogDataListener) {
      return;
    }

    let responseBuf = Buffer.alloc(0);
    const separator = Buffer.from('\r\n\r\n', 'utf8');

    this._dialogDataListener = (data) => {
      responseBuf = Buffer.concat([responseBuf, Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8')]);

      while (true) {
        while (responseBuf.length >= 2 && responseBuf[0] === 0x0d && responseBuf[1] === 0x0a) {
          responseBuf = responseBuf.subarray(2);
        }

        const headerEnd = responseBuf.indexOf(separator);
        if (headerEnd === -1) break;

        const headersRaw = responseBuf.subarray(0, headerEnd).toString('utf8');
        const lines = headersRaw.split('\r\n');
        const firstLine = (lines[0] || '').trim();

        const headers = {};
        for (let i = 1; i < lines.length; i++) {
          const colon = lines[i].indexOf(':');
          if (colon > 0) {
            const key = lines[i].slice(0, colon).trim().toLowerCase();
            const val = lines[i].slice(colon + 1).trim();
            if (headers[key] !== undefined) {
              if (Array.isArray(headers[key])) {
                headers[key].push(val);
              } else {
                headers[key] = [headers[key], val];
              }
            } else {
              headers[key] = val;
            }
          }
        }

        const contentLength = parseInt(headers['content-length'] || '0', 10);
        const totalMsgLen = headerEnd + 4 + contentLength;
        if (responseBuf.length < totalMsgLen) break;

        responseBuf = responseBuf.subarray(totalMsgLen);

        this._log(`[BticinoVideoStreamer:_attachDialogSipListener] In-dialog SIP message: ${firstLine}`);

        if (!firstLine.toUpperCase().startsWith('SIP/2.0')) {
          const ended = this._handleIncomingDialogRequest(firstLine, headers);
          if (ended) {
            return;
          }
        }
      }
    };

    this._tlsSocket.on('data', this._dialogDataListener);
  }

  /**
   * Handles an incoming server-initiated SIP request on the active dialog socket (e.g. BYE, OPTIONS, INFO).
   * Sends a compliant RFC 3261 200 OK response and triggers call renewal / termination on BYE.
   *
   * @private
   * @param {string} requestLine - First line of the SIP request (e.g. 'BYE sip:... SIP/2.0').
   * @param {Object} headers - Parsed lowercase SIP headers map.
   * @returns {boolean} True if the request was a BYE that ended the current dialog.
   */
  _handleIncomingDialogRequest(requestLine, headers) {
    const upper = String(requestLine || '').trim().toUpperCase();
    const method = upper.split(/\s+/)[0] || '';

    if (method === 'ACK') {
      return false;
    }

    const vias = headers['via']
      ? (Array.isArray(headers['via']) ? headers['via'] : [headers['via']])
      : [];
    const viaLines = vias.map((v) => `Via: ${v}\r\n`).join('');
    const fromHeader = headers['from'] || `<sip:diy@${this.domain}>`;
    const toHeader = headers['to'] || `<sip:${this.username}@${this.domain}>`;
    const callId = headers['call-id'] || this._callId;
    const cseq = headers['cseq'] || `1 ${method || 'OPTIONS'}`;

    if (method === 'BYE') {
      this._log('[BticinoVideoStreamer:_handleIncomingDialogRequest] Remote gateway sent BYE, acknowledging with 200 OK...');
      const byeOk =
        `SIP/2.0 200 Ok\r\n` +
        viaLines +
        `From: ${fromHeader}\r\n` +
        `To: ${toHeader}\r\n` +
        `Call-ID: ${callId}\r\n` +
        `CSeq: ${cseq}\r\n` +
        `User-Agent: VctLinphoneService/1.7.7\r\n` +
        `Content-Length: 0\r\n\r\n`;

      if (this._tlsSocket && !this._tlsSocket.destroyed) {
        try { this._tlsSocket.write(byeOk); } catch (_) {}
      }

      this._handleCallEnded('remote-bye');
      return true;
    }

    if (method === 'OPTIONS' || method === 'INFO' || method === 'NOTIFY' || method === 'UPDATE') {
      const okResp =
        `SIP/2.0 200 Ok\r\n` +
        viaLines +
        `From: ${fromHeader}\r\n` +
        `To: ${toHeader}\r\n` +
        `Call-ID: ${callId}\r\n` +
        `CSeq: ${cseq}\r\n` +
        `User-Agent: VctLinphoneService/1.7.7\r\n` +
        `Content-Length: 0\r\n\r\n`;

      if (this._tlsSocket && !this._tlsSocket.destroyed) {
        try { this._tlsSocket.write(okResp); } catch (_) {}
      }
    }

    return false;
  }

  /**
   * Detaches the in-dialog SIP data listener from the TLS socket.
   *
   * @private
   * @returns {void}
   */
  _detachDialogSipListener() {
    if (this._tlsSocket && this._dialogDataListener) {
      this._tlsSocket.removeListener('data', this._dialogDataListener);
      this._dialogDataListener = null;
    }
  }

  /**
   * Sends SIP BYE request to terminate the active call.
   *
   * @private
   * @returns {Promise<void>}
   */
  _sendBye() {
    this._cseq++;
    const targetUri = this._remoteTargetUri || `sip:diy@${this.domain}`;
    const fromUri = `<sip:${this.username}@${this.domain}>;tag=${this._fromTag}`;
    const toUri = `<sip:diy@${this.domain}>${this._toTag ? `;tag=${this._toTag}` : ''}`;
    const branch = 'z9hG4bK.' + crypto.randomBytes(8).toString('hex');
    const localIp = this._getLocalIp();
    const localPort = (this._tlsSocket && this._tlsSocket.localPort) ? this._tlsSocket.localPort : 5060;

    let bye =
      `BYE ${targetUri} SIP/2.0\r\n` +
      `Via: SIP/2.0/TLS ${localIp}:${localPort};branch=${branch};rport\r\n` +
      `From: ${fromUri}\r\n` +
      `To: ${toUri}\r\n` +
      `Call-ID: ${this._callId}\r\n` +
      `CSeq: ${this._cseq} BYE\r\n` +
      `Max-Forwards: 70\r\n` +
      `User-Agent: VctLinphoneService/1.7.7\r\n`;

    if (this._routeSet.length > 0) {
      bye += `Route: ${this._routeSet.join(', ')}\r\n`;
    }

    bye += `Content-Length: 0\r\n\r\n`;

    return new Promise((resolve) => {
      if (this._tlsSocket && !this._tlsSocket.destroyed) {
        this._tlsSocket.write(bye, () => resolve());
      } else {
        resolve();
      }
    });
  }

  /**
   * Starts periodic UDP NAT hole-punching, optional SIP re-INVITE session renewal,
   * and RTP silence stall detection.
   *
   * @private
   * @returns {void}
   */
  _startRtpKeepAlive() {
    if (this._keepAliveTimer) {
      clearInterval(this._keepAliveTimer);
      this._keepAliveTimer = null;
    }

    if (!this._remoteRelayIp || !this._remoteVideoPort || !this._udpVideoSocket) {
      return;
    }

    this._streamStartTime = Date.now();
    this._lastRtpPacketTimestamp = Date.now();
    this._lastReInviteTime = Date.now();

    // Send immediate initial UDP punch packets
    this._sendUdpPunch();
    setTimeout(() => this._sendUdpPunch(), 300);
    setTimeout(() => this._sendUdpPunch(), 800);

    // Periodic keep-alive every 2.5 seconds
    this._keepAliveTimer = setInterval(() => {
      this._sendUdpPunch();

      if (!this._activeStream || this._restarting) return;

      const now = Date.now();
      const activeClients = this.rtspServer ? this.rtspServer.getActiveSessionCount() : 0;

      // 1. Optional proactive session renewal (re-INVITE) if explicitly enabled
      if (this.opts.reInviteKeepAlive && activeClients > 0 && (now - (this._lastReInviteTime || now)) >= 20000) {
        this._lastReInviteTime = now;
        this._log('[BticinoVideoStreamer] Proactively renewing SIP video session with re-INVITE (20s keep-alive)...');
        const cameraSliding = this._activeCameraIndex > 1 ? '2' : null;
        this._sendReInvite(this._activeCameraId, cameraSliding).catch((err) => {
          this._log('[BticinoVideoStreamer] re-INVITE keep-alive non-fatal error:', err.message);
        });
      }

      // 2. Silence / stall detector:
      // - If we already received media on this call, trigger after 4s of silence
      // - If no UDP packet ever arrived after call setup, trigger after 8s
      const silenceMs = now - (this._lastRtpPacketTimestamp || this._streamStartTime || now);
      const thresholdMs = this._receivedUdpCount > 0 ? 4000 : 8000;
      if (silenceMs > thresholdMs) {
        this._log(`[BticinoVideoStreamer] RTP stream silence detected (${Math.round(silenceMs / 1000)}s without packets). Handling call end...`);
        this._handleCallEnded('rtp-silence');
      }
    }, 2500);
  }

  /**
   * Sends a dummy RTP packet (for symmetric RTP NAT latching on the Flexisip Media Relay RTP port)
   * and an RTCP Picture Loss Indication (PLI, RFC 4585) packet to request an H.264 IDR keyframe.
   *
   * @private
   * @returns {void}
   */
  _sendUdpPunch() {
    if (!this._udpVideoSocket || !this._remoteRelayIp || !this._remoteVideoPort) {
      return;
    }

    try {
      // 1. Dummy RTP packet (V=2, PT=96) to RTP port for symmetric RTP NAT learning on Flexisip Media Relay
      const rtpPunch = Buffer.from([
        0x80, 0x60, 0x00, 0x01, // V=2, P=0, X=0, CC=0, M=0, PT=96, Seq=1
        0x00, 0x00, 0x00, 0x00, // Timestamp=0
        0x12, 0x34, 0x56, 0x78  // SSRC
      ]);
      this._udpVideoSocket.send(rtpPunch, this._remoteVideoPort, this._remoteRelayIp);

      // 2. RTCP PLI Packet: V=2, P=0, FMT=1 (PLI), PT=206 (PSFB), Length=2 (12 bytes)
      const pliPacket = Buffer.from([
        0x81, 0xCE, 0x00, 0x02, // Header: V=2, FMT=1, PT=206, Length=2
        0x12, 0x34, 0x56, 0x78, // SSRC of packet sender
        0x00, 0x00, 0x00, 0x00  // SSRC of media source (0 = all)
      ]);

      this._udpVideoSocket.send(pliPacket, this._remoteVideoPort, this._remoteRelayIp);
      this._udpVideoSocket.send(pliPacket, this._remoteVideoPort + 1, this._remoteRelayIp);
    } catch (_) {}
  }

  /**
   * Handles an incoming UDP packet from the Flexisip Media Relay, decrypts SRTP,
   * passes the plaintext RTP packet to the RTSP loopback server and snapshot extractor.
   *
   * @private
   * @param {Buffer} msg - Incoming UDP buffer.
   * @returns {void}
   */
  _handleIncomingUdpPacket(msg) {
    // Only discard packets too short to hold an RTP header plus payload: tiny packets (e.g. a 4-byte PPS NAL
    // with the 4-byte HMAC_SHA1_32 tag is only 20 bytes) are valid and must reach the SRTP decryptor
    if (!msg || msg.length < 13) {
      return;
    }

    this._lastRtpPacketTimestamp = Date.now();

    this._receivedUdpCount = (this._receivedUdpCount || 0) + 1;
    const pt = msg[1] & 0x7F;
    if (this._receivedUdpCount === 1) {
      this._log(`[BticinoVideoStreamer:_handleIncomingUdpPacket] First UDP packet received from relay (size: ${msg.length} bytes, PT: ${pt})`);
    }

    // Skip RTCP packets (Payload Types 200..207 or raw RTCP 72..79)
    if ((pt >= 200 && pt <= 207) || (pt >= 72 && pt <= 79)) {
      return;
    }

    // Drop non-video probe or dummy keepalive packets (e.g. PT: 1)
    const expectedPt = this._negotiatedVideoPt || 96;
    if (pt !== expectedPt) {
      if (this._receivedUdpCount <= 5) {
        this._log(`[BticinoVideoStreamer:_handleIncomingUdpPacket] Dropping non-video packet (size: ${msg.length} bytes, PT: ${pt}, expected: ${expectedPt})`);
      }
      return;
    }

    // Never forward still-encrypted media: without a negotiated SRTP key the payload is garbage
    if (!this.srtpDecryptor) {
      if (this._receivedUdpCount <= 3) {
        this._log('[BticinoVideoStreamer:_handleIncomingUdpPacket] Dropping packet: SRTP decryptor not initialized');
      }
      return;
    }

    const plaintextRtp = this.srtpDecryptor.decrypt(msg);
    if (!plaintextRtp) {
      if (this._receivedUdpCount <= 5) {
        this._log(`[BticinoVideoStreamer:_handleIncomingUdpPacket] SRTP decrypt returned null for packet #${this._receivedUdpCount} (size: ${msg.length}, PT: ${pt})`);
      }
      return;
    }

    this._decryptedRtpCount = (this._decryptedRtpCount || 0) + 1;
    if (this._decryptedRtpCount === 1) {
      const seq = plaintextRtp.readUInt16BE(2);
      this._log(`[BticinoVideoStreamer:_handleIncomingUdpPacket] First SRTP video packet decrypted (PT: ${pt}, seq: ${seq}, payload: ${plaintextRtp.length - 12} bytes)`);
    }

    // Process keyframes and snapshots on raw decrypted RTP
    this.snapshotExtractor.processRtpPacket(plaintextRtp);

    // Ensure RTP sequence number, timestamp, and SSRC stay monotonic across transparent SIP call renewals
    this._rewriteRtpContinuity(plaintextRtp);

    // Forward plaintext RTP packet to active RTSP client sessions (Homey)
    this.rtspServer.sendRtpPacket(plaintextRtp);

    this.emit('rtp', plaintextRtp);
  }

  /**
   * Rewrites the RTP header (Sequence Number, Timestamp, SSRC) in-place so that downstream RTSP
   * decoders observe a single continuous RTP stream with a constant SSRC and monotonically increasing
   * sequence numbers and timestamps across transparent 30s SIP call renewals.
   *
   * @private
   * @param {Buffer} rtpPacket - Decrypted RTP packet buffer (at least 12 bytes).
   * @returns {void}
   */
  _rewriteRtpContinuity(rtpPacket) {
    if (!rtpPacket || rtpPacket.length < 12) {
      return;
    }

    const now = Date.now();
    const inSeq = rtpPacket.readUInt16BE(2);
    const inTs = rtpPacket.readUInt32BE(4);
    const inSsrc = rtpPacket.readUInt32BE(8);

    if (!this._rtpState) {
      this._rtpState = {
        ssrc: inSsrc,
        seqDelta: 0,
        tsDelta: 0,
        lastOutSeq: inSeq,
        lastOutTs: inTs,
        lastOutAt: now
      };
      return;
    }

    if (this._rtpResyncPending) {
      const targetSeq = (this._rtpState.lastOutSeq + 1) & 0xFFFF;
      this._rtpState.seqDelta = (targetSeq - inSeq) & 0xFFFF;

      const elapsedMs = Math.max(40, Math.min(5000, now - (this._rtpState.lastOutAt || now)));
      const targetTs = (this._rtpState.lastOutTs + Math.round(elapsedMs * 90)) >>> 0;
      this._rtpState.tsDelta = (targetTs - inTs) >>> 0;

      this._rtpResyncPending = false;
      this._log(`[BticinoVideoStreamer:_rewriteRtpContinuity] Resynced RTP timeline across call renewal (outSeq=${targetSeq}, elapsedMs=${elapsedMs})`);
    }

    const outSeq = (inSeq + this._rtpState.seqDelta) & 0xFFFF;
    const outTs = (inTs + this._rtpState.tsDelta) >>> 0;

    rtpPacket.writeUInt16BE(outSeq, 2);
    rtpPacket.writeUInt32BE(outTs, 4);
    rtpPacket.writeUInt32BE(this._rtpState.ssrc, 8);

    this._rtpState.lastOutSeq = outSeq;
    this._rtpState.lastOutTs = outTs;
    this._rtpState.lastOutAt = now;
  }

  /**
   * Formulates the SDP offer string following BTicino's expected parameters.
   *
   * @private
   * @param {string|null} cameraId - Optional camera module ID for a=DEVADDR.
   * @param {number} [sessionVersion=3658] - SDP session version.
   * @param {string|null} [cameraSliding=null] - Optional CAMERASLIDING value ('2' to cycle camera).
   * @returns {string} Complete SDP offer body.
   */
  _buildSdpOffer(cameraId, sessionVersion = 3658, cameraSliding = null) {
    const localIp = this._getLocalIp();
    const audioPort = this._localVideoPort > 2 ? this._localVideoPort - 2 : 7076;
    const videoPort = this._localVideoPort || 9078;

    let sdp =
      `v=0\r\n` +
      `o=${this.username} 558 ${sessionVersion} IN IP4 ${localIp}\r\n` +
      `s=Talk\r\n` +
      `c=IN IP4 ${localIp}\r\n` +
      `t=0 0\r\n`;

    if (cameraId) {
      sdp += `a=DEVADDR:${cameraId}\r\n`;
    }

    if (cameraSliding) {
      sdp += `a=CAMERASLIDING:${cameraSliding}\r\n`;
    }

    sdp +=
      `m=audio ${audioPort} RTP/SAVP 98 100\r\n` +
      `a=rtpmap:98 speex/8000\r\n` +
      `a=fmtp:98 vbr=on\r\n` +
      `a=rtpmap:100 telephone-event/8000\r\n` +
      `a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:${this._clientInlineKey}\r\n` +
      `a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:${this._clientInlineKey}\r\n` +
      `m=video ${videoPort} RTP/SAVP 96\r\n` +
      `a=rtpmap:96 H264/90000\r\n` +
      `a=fmtp:96 profile-level-id=42801F\r\n` +
      `a=recvonly\r\n` +
      `a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:${this._clientInlineKey}\r\n` +
      `a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:${this._clientInlineKey}\r\n` +
      `a=rtcp-fb:* trr-int 5000\r\n` +
      `a=rtcp-fb:* ccm tmmbr\r\n` +
      `a=rtcp-fb:96 nack pli\r\n` +
      `a=rtcp-fb:96 ccm fir\r\n`;

    return sdp;
  }

  /**
   * Builds an RFC 3261 SIP INVITE string with headers and SDP body.
   *
   * @private
   * @param {Object} params - Message parameters.
   * @returns {string} Formatted SIP INVITE message.
   */
  _buildSipInvite({ cseq, sdp, proxyAuth, targetUri: customTargetUri }) {
    const targetUri = customTargetUri || `sip:diy@${this.domain}`;
    const fromUri = `<sip:${this.username}@${this.domain}>;tag=${this._fromTag}`;
    const toUri = `<sip:diy@${this.domain}>${this._toTag ? `;tag=${this._toTag}` : ''}`;
    const branch = 'z9hG4bK.' + crypto.randomBytes(8).toString('hex');
    this._lastInviteBranch = branch;
    const localIp = this._getLocalIp();
    const localPort = (this._tlsSocket && this._tlsSocket.localPort) ? this._tlsSocket.localPort : 5060;

    const bodyLength = Buffer.byteLength(sdp, 'utf8');

    let msg =
      `INVITE ${targetUri} SIP/2.0\r\n` +
      `Via: SIP/2.0/TLS ${localIp}:${localPort};branch=${branch};rport\r\n` +
      `From: ${fromUri}\r\n` +
      `To: ${toUri}\r\n` +
      `Call-ID: ${this._callId}\r\n` +
      `CSeq: ${cseq} INVITE\r\n` +
      `Contact: <sip:${this.username}@${localIp}:${localPort};transport=tls>\r\n` +
      `Max-Forwards: 70\r\n` +
      `User-Agent: VctLinphoneService/1.7.7\r\n` +
      `Supported: replaces, outbound, gruu, path\r\n`;

    if (this._routeSet.length > 0) {
      msg += `Route: ${this._routeSet.join(', ')}\r\n`;
    } else {
      msg += `Route: <sip:${this.opts.server};transport=tls;lr>\r\n`;
    }

    if (proxyAuth) {
      msg += `Proxy-Authorization: ${proxyAuth}\r\n`;
    }

    msg +=
      `Content-Type: application/sdp\r\n` +
      `Content-Length: ${bodyLength}\r\n\r\n` +
      sdp;

    return msg;
  }

  /**
   * Builds an RFC 3261 SIP ACK message for a completed INVITE transaction.
   *
   * @private
   * @param {number} cseq - CSeq sequence number matching the INVITE.
   * @param {Object} [opts={}] - Optional parameters for non-2xx ACK (branch, toHeader, isNon2xx, targetUri).
   * @returns {string} Formatted SIP ACK message.
   */
  _buildSipAck(cseq, opts = {}) {
    const targetUri = opts.targetUri
      ? opts.targetUri
      : (opts.isNon2xx
        ? `sip:diy@${this.domain}`
        : (this._remoteTargetUri || `sip:diy@${this.domain}`));
    const fromUri = `<sip:${this.username}@${this.domain}>;tag=${this._fromTag}`;
    const toUri = opts.toHeader || (`<sip:diy@${this.domain}>${this._toTag ? `;tag=${this._toTag}` : ''}`);
    const branch = opts.branch || ('z9hG4bK.' + crypto.randomBytes(8).toString('hex'));
    const localIp = this._getLocalIp();
    const localPort = (this._tlsSocket && this._tlsSocket.localPort) ? this._tlsSocket.localPort : 5060;

    let ack =
      `ACK ${targetUri} SIP/2.0\r\n` +
      `Via: SIP/2.0/TLS ${localIp}:${localPort};branch=${branch};rport\r\n` +
      `From: ${fromUri}\r\n` +
      `To: ${toUri}\r\n` +
      `Call-ID: ${this._callId}\r\n` +
      `CSeq: ${cseq} ACK\r\n` +
      `Max-Forwards: 70\r\n` +
      `User-Agent: VctLinphoneService/1.7.7\r\n`;

    if (this._routeSet.length > 0) {
      ack += `Route: ${this._routeSet.join(', ')}\r\n`;
    } else {
      ack += `Route: <sip:${this.opts.server};transport=tls;lr>\r\n`;
    }

    ack += `Content-Length: 0\r\n\r\n`;
    return ack;
  }

  /**
   * Computes the RFC 2617 Digest MD5 response string for Proxy-Authorization.
   *
   * @private
   * @param {string} authHeader - Proxy-Authenticate header string from 407 response.
   * @param {string} method - SIP method ('INVITE').
   * @param {string} [customUri] - Optional Request-URI if different from default AoR.
   * @returns {string} Proxy-Authorization header value.
   */
  _computeProxyAuthorization(authHeader, method, customUri = null) {
    const realm = authHeader.match(/realm="([^"]+)"/)?.[1] || this.domain;
    const nonce = authHeader.match(/nonce="([^"]+)"/)?.[1] || '';
    const opaque = authHeader.match(/opaque="([^"]+)"/)?.[1] || '';
    const qop = authHeader.match(/qop="([^"]+)"/)?.[1] || 'auth';

    this._nonceCount = (this._nonceCount || 0) + 1;
    const nc = this._nonceCount.toString(16).padStart(8, '0');
    const cnonce = crypto.randomBytes(8).toString('hex');
    const uri = customUri || `sip:diy@${this.domain}`;

    // HA1 = MD5(username:realm:password)
    const ha1 = crypto.createHash('md5')
      .update(`${this.username}:${realm}:${this.sipAccount.sipPassword}`)
      .digest('hex');

    // HA2 = MD5(method:uri)
    const ha2 = crypto.createHash('md5')
      .update(`${method}:${uri}`)
      .digest('hex');

    // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    const response = crypto.createHash('md5')
      .update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
      .digest('hex');

    return `Digest realm="${realm}", nonce="${nonce}", algorithm=MD5, opaque="${opaque}", username="${this.username}", uri="${uri}", response="${response}", cnonce="${cnonce}", nc=${nc}, qop=${qop}`;
  }

  /**
   * Writes a raw SIP request string to the TLS socket and awaits a final response (or challenge).
   * Properly consumes provisional responses (100 Trying, 180 Ringing) and handles interleaved
   * server-initiated requests (such as a remote BYE arriving while awaiting a response).
   *
   * @private
   * @param {string} requestStr - Raw SIP text request.
   * @param {number} [timeoutMs=15000] - Response timeout in milliseconds.
   * @returns {Promise<{statusCode: number, statusText: string, headers: Object, body: string}>}
   */
  _sendSipRequestAndAwaitResponse(requestStr, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      let responseBuf = Buffer.alloc(0);
      const separator = Buffer.from('\r\n\r\n', 'utf8');

      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('[BticinoVideoStreamer] Timeout awaiting SIP response'));
      }, timeoutMs);

      const onData = (data) => {
        responseBuf = Buffer.concat([responseBuf, Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8')]);

        while (true) {
          // Strip leading CRLFs (keep-alive pings)
          while (responseBuf.length >= 2 && responseBuf[0] === 0x0d && responseBuf[1] === 0x0a) {
            responseBuf = responseBuf.subarray(2);
          }

          const headerEnd = responseBuf.indexOf(separator);
          if (headerEnd === -1) {
            break; // Wait for complete SIP headers
          }

          const headersRaw = responseBuf.subarray(0, headerEnd).toString('utf8');
          const lines = headersRaw.split('\r\n');
          const statusLine = (lines[0] || '').trim();

          const headers = {};
          for (let i = 1; i < lines.length; i++) {
            const colon = lines[i].indexOf(':');
            if (colon > 0) {
              const key = lines[i].slice(0, colon).trim().toLowerCase();
              const val = lines[i].slice(colon + 1).trim();
              if (headers[key] !== undefined) {
                if (Array.isArray(headers[key])) {
                  headers[key].push(val);
                } else {
                  headers[key] = [headers[key], val];
                }
              } else {
                headers[key] = val;
              }
            }
          }

          const contentLength = parseInt(headers['content-length'] || '0', 10);
          const totalMsgLen = headerEnd + 4 + contentLength;

          if (responseBuf.length < totalMsgLen) {
            break; // Wait for full SIP message body
          }

          const body = responseBuf.subarray(headerEnd + 4, totalMsgLen).toString('utf8');
          // Advance buffer past this complete SIP message
          responseBuf = responseBuf.subarray(totalMsgLen);

          const match = statusLine.match(/SIP\/2\.0\s+(\d+)\s+(.+)/i);
          if (match) {
            const statusCode = parseInt(match[1], 10);
            const statusText = match[2];
            this._log(`[BticinoVideoStreamer:_sendSipRequestAndAwaitResponse] Received SIP response: ${statusCode} ${statusText} (body: ${contentLength} bytes)`);

            // Provisional responses (100 Trying, 180 Ringing, 183 Session Progress):
            // Consume and continue parsing next SIP message in stream!
            if (statusCode < 200) {
              if (headers['to'] && statusCode > 100) {
                const tagMatch = String(headers['to']).match(/tag=([^\s;>]+)/);
                if (tagMatch && !this._toTag) {
                  this._toTag = tagMatch[1];
                }
              }
              continue;
            }

            cleanup();
            resolve({ statusCode, statusText, headers, body });
            return;
          } else {
            // Interleaved server-initiated SIP request (e.g. remote BYE at 30s mark or OPTIONS ping)
            this._log(`[BticinoVideoStreamer:_sendSipRequestAndAwaitResponse] Processing incoming SIP request on call socket: ${statusLine}`);
            const ended = this._handleIncomingDialogRequest(statusLine, headers);
            if (ended) {
              cleanup();
              reject(new Error('[BticinoVideoStreamer] Remote gateway sent BYE while awaiting SIP response'));
              return;
            }
          }
        }
      };

      const onClose = () => {
        cleanup();
        reject(new Error('[BticinoVideoStreamer] Socket closed while awaiting SIP response'));
      };

      const onError = (err) => {
        cleanup();
        reject(err || new Error('[BticinoVideoStreamer] Socket error while awaiting SIP response'));
      };

      const cleanup = () => {
        clearTimeout(timer);
        if (this._tlsSocket) {
          this._tlsSocket.removeListener('data', onData);
          this._tlsSocket.removeListener('close', onClose);
          this._tlsSocket.removeListener('error', onError);
        }
      };

      this._tlsSocket.on('data', onData);
      this._tlsSocket.once('close', onClose);
      this._tlsSocket.once('error', onError);
      this._tlsSocket.write(requestStr);
    });
  }

  /**
   * Resolves the primary local IPv4 address of the host machine.
   *
   * @private
   * @returns {string} Local IPv4 address.
   */
  _getLocalIp() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }
}

module.exports = BticinoVideoStreamer;

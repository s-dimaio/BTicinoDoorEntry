/**
 * BticinoRtspLoopbackServer
 *
 * Lightweight local RTSP loopback server implementing RFC 2326 (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN).
 * Exposes an H.264 RTSP stream (rtsp://127.0.0.1:<port>/live) consumed by Homey Apps SDK v3 ManagerVideos
 * (createVideoRTSP) with zero external binaries (pure Node.js net/dgram).
 *
 * Supports both TCP interleaved transport (RTP/AVP/TCP) and UDP unicast transport (RTP/AVP).
 *
 * @module BticinoRtspLoopbackServer
 */

'use strict';

const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const EventEmitter = require('events');

class BticinoRtspLoopbackServer extends EventEmitter {
  /**
   * Initializes the RTSP loopback server.
   *
   * @public
   * @constructor
   * @param {Object} [opts={}] - Configuration options.
   * @param {number} [opts.port=0] - Local TCP port to bind (0 = dynamic ephemeral port).
   * @param {string} [opts.host='127.0.0.1'] - Local interface to bind (defaults to loopback).
   * @param {string} [opts.path='/live'] - RTSP mount path.
   * @param {boolean} [opts.debug=false] - Enables verbose debug logging.
   *
   * @example
   * const server = new BticinoRtspLoopbackServer({ debug: true });
   * const { url } = await server.start();
   * console.log('Local RTSP stream ready at:', url);
   */
  constructor(opts = {}) {
    super();
    this.opts = Object.assign({
      port: 0,
      host: '127.0.0.1',
      path: '/live',
      debug: false
    }, opts);

    this._log = (...args) => { if (this.opts.debug) console.log('[BticinoRtspServer]', ...args); };
    this._error = (...args) => { console.error('[BticinoRtspServer]', ...args); };

    this._tcpServer = null;
    this._boundPort = 0;
    this._sessions = new Map();
    this._running = false;
  }

  /**
   * Starts listening for RTSP connections on the configured host and port.
   *
   * @public
   * @async
   * @returns {Promise<{port: number, url: string}>} Resolved with assigned port and complete RTSP URL.
   *
   * @example
   * const { port, url } = await server.start();
   */
  start() {
    if (this._running) {
      const url = `rtsp://${this.opts.host}:${this._boundPort}${this.opts.path}`;
      return Promise.resolve({
        port: this._boundPort,
        url,
        rtspUrl: url
      });
    }

    return new Promise((resolve, reject) => {
      this._tcpServer = net.createServer((socket) => {
        this._handleClientConnection(socket);
      });

      this._tcpServer.on('error', (err) => {
        this._error('[BticinoRtspServer:start] TCP server error:', err.message);
        if (!this._running) {
          reject(err);
        }
      });

      this._tcpServer.listen(this.opts.port, this.opts.host, () => {
        this._running = true;
        this._boundPort = this._tcpServer.address().port;
        const url = `rtsp://${this.opts.host}:${this._boundPort}${this.opts.path}`;
        this._log(`[BticinoRtspServer:start] RTSP loopback server listening on ${url}`);
        resolve({ port: this._boundPort, url, rtspUrl: url });
      });
    });
  }

  /**
   * Stores the H.264 SPS and PPS NAL units (without Annex-B start codes) so that they can be advertised
   * as `sprop-parameter-sets` in the RTSP DESCRIBE SDP of subsequent client sessions.
   *
   * @public
   * @param {Buffer} sps - SPS NAL unit payload (starting with the NAL header byte).
   * @param {Buffer} pps - PPS NAL unit payload (starting with the NAL header byte).
   * @returns {void}
   *
   * @example
   * server.setParameterSets(spsNal, ppsNal);
   */
  setParameterSets(sps, pps) {
    if (!Buffer.isBuffer(sps) || !Buffer.isBuffer(pps) || sps.length === 0 || pps.length === 0) {
      return;
    }
    this._spropParameterSets = `${sps.toString('base64')},${pps.toString('base64')}`;
  }

  /**
   * Broadcasts an unencrypted RFC 3550 RTP H.264 packet to all active playing RTSP client sessions.
   *
   * @public
   * @param {Buffer} rtpPacket - Plaintext RTP packet buffer.
   * @returns {void}
   *
   * @example
   * server.sendRtpPacket(decryptedRtpPacket);
   */
  sendRtpPacket(rtpPacket) {
    if (!this._running || !Buffer.isBuffer(rtpPacket) || this._sessions.size === 0) {
      return;
    }

    for (const [sessionId, session] of this._sessions.entries()) {
      if (!session.playing) {
        continue;
      }

      try {
        if (session.transportType === 'tcp' && session.socket && !session.socket.destroyed && session.socket.writable) {
          // RFC 2326 Section 10.1 Interleaved frame: [0x24 ($), channel, length (2 bytes BE), ...rtpData]
          const frameHeader = Buffer.alloc(4);
          frameHeader[0] = 0x24; // '$'
          frameHeader[1] = session.interleavedRtpChannel;
          frameHeader.writeUInt16BE(rtpPacket.length, 2);

          session.socket.write(Buffer.concat([frameHeader, rtpPacket]));
        } else if (session.transportType === 'udp' && session.udpSocket && session.clientRtpPort) {
          session.udpSocket.send(rtpPacket, session.clientRtpPort, session.clientIp);
        }
      } catch (err) {
        this._log(`[BticinoRtspServer:sendRtpPacket] Error sending packet to session ${sessionId}:`, err.message);
      }
    }
  }

  /**
   * Alias for sendRtpPacket(rtpPacket). Broadcasts an RTP packet to all active playing sessions.
   *
   * @public
   * @param {Buffer} rtpPacket - Plaintext RTP packet buffer.
   * @returns {void}
   *
   * @example
   * server.broadcastRtp(rtpPacket);
   */
  broadcastRtp(rtpPacket) {
    this.sendRtpPacket(rtpPacket);
  }

  /**
   * Handles an incoming client TCP socket connection and processes RTSP text requests.
   *
   * @private
   * @param {net.Socket} socket - Incoming client TCP socket.
   * @returns {void}
   */
  _handleClientConnection(socket) {
    const sessionId = crypto.randomBytes(4).toString('hex');
    const clientIp = socket.remoteAddress;

    const session = {
      id: sessionId,
      socket,
      clientIp,
      transportType: 'tcp',
      interleavedRtpChannel: 0,
      interleavedRtcpChannel: 1,
      clientRtpPort: 0,
      clientRtcpPort: 0,
      udpSocket: null,
      playing: false
    };

    this._sessions.set(sessionId, session);
    this._log(`[BticinoRtspServer:_handleClientConnection] Client connected from ${clientIp} (session ${sessionId})`);

    let buffer = '';

    socket.on('data', (chunk) => {
      // In interleaved mode, client might send RTCP packets prefixed with 0x24
      if (chunk[0] === 0x24) {
        // Skip interleaved binary RTCP
        return;
      }

      buffer += chunk.toString('utf8');

      // Process complete RTSP request blocks separated by CRLFCRLF
      let delimiterIndex;
      while ((delimiterIndex = buffer.indexOf('\r\n\r\n')) !== -1) {
        const rawRequest = buffer.slice(0, delimiterIndex);
        buffer = buffer.slice(delimiterIndex + 4);
        this._processRtspRequest(session, rawRequest);
      }
    });

    socket.on('error', (err) => {
      this._log(`[BticinoRtspServer:_handleClientConnection] Client socket error (${sessionId}):`, err.message);
    });

    socket.on('close', () => {
      this._log(`[BticinoRtspServer:_handleClientConnection] Client disconnected (${sessionId})`);
      this._cleanupSession(sessionId);
    });
  }

  /**
   * Parses and responds to an individual RTSP request.
   *
   * @private
   * @param {Object} session - Active client session state.
   * @param {string} rawRequest - Raw RTSP request header string.
   * @returns {void}
   */
  _processRtspRequest(session, rawRequest) {
    const lines = rawRequest.split(/\r?\n/);
    if (lines.length === 0) return;

    const requestLine = lines[0].trim();
    const parts = requestLine.split(' ');
    if (parts.length < 3) return;

    const method = parts[0].toUpperCase();
    const uri = parts[1];

    const headers = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      const colon = line.indexOf(':');
      if (colon > 0) {
        headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
      }
    }

    const cseq = headers['cseq'] || '1';
    this._log(`[BticinoRtspServer] Request: ${method} ${uri} (CSeq: ${cseq}, Session: ${session.id})`);

    if (method === 'OPTIONS') {
      const response =
        `RTSP/1.0 200 OK\r\n` +
        `CSeq: ${cseq}\r\n` +
        `Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY\r\n` +
        `\r\n`;
      this._writeResponse(session, response);
    } else if (method === 'DESCRIBE') {
      // Advertise cached SPS/PPS when known (RFC 6184 Section 8.1) so decoders can initialise immediately
      const sprop = this._spropParameterSets ? `;sprop-parameter-sets=${this._spropParameterSets}` : '';
      const sdpBody =
        `v=0\r\n` +
        `o=- 0 0 IN IP4 127.0.0.1\r\n` +
        `s=BTicino Door Entry Live Video\r\n` +
        `c=IN IP4 127.0.0.1\r\n` +
        `t=0 0\r\n` +
        `m=video 0 RTP/AVP 96\r\n` +
        `a=rtpmap:96 H264/90000\r\n` +
        `a=fmtp:96 packetization-mode=1;profile-level-id=42801F${sprop}\r\n` +
        `a=control:track1\r\n`;

      const sdpLength = Buffer.byteLength(sdpBody, 'utf8');

      const response =
        `RTSP/1.0 200 OK\r\n` +
        `CSeq: ${cseq}\r\n` +
        `Content-Type: application/sdp\r\n` +
        `Content-Base: ${uri}/\r\n` +
        `Content-Length: ${sdpLength}\r\n` +
        `\r\n` +
        sdpBody;

      this._writeResponse(session, response);
    } else if (method === 'SETUP') {
      const transportHeader = headers['transport'] || '';

      if (transportHeader.toLowerCase().includes('interleaved')) {
        session.transportType = 'tcp';
        const match = transportHeader.match(/interleaved=(\d+)-(\d+)/i);
        if (match) {
          session.interleavedRtpChannel = parseInt(match[1], 10);
          session.interleavedRtcpChannel = parseInt(match[2], 10);
        }

        const response =
          `RTSP/1.0 200 OK\r\n` +
          `CSeq: ${cseq}\r\n` +
          `Session: ${session.id}\r\n` +
          `Transport: RTP/AVP/TCP;unicast;interleaved=${session.interleavedRtpChannel}-${session.interleavedRtcpChannel}\r\n` +
          `\r\n`;

        this._writeResponse(session, response);
      } else {
        // Fallback UDP transport
        session.transportType = 'udp';
        const match = transportHeader.match(/client_port=(\d+)-(\d+)/i);
        if (match) {
          session.clientRtpPort = parseInt(match[1], 10);
          session.clientRtcpPort = parseInt(match[2], 10);
        }

        session.udpSocket = dgram.createSocket('udp4');
        session.udpSocket.bind(0, '127.0.0.1', () => {
          const serverUdpPort = session.udpSocket.address().port;
          const response =
            `RTSP/1.0 200 OK\r\n` +
            `CSeq: ${cseq}\r\n` +
            `Session: ${session.id}\r\n` +
            `Transport: RTP/AVP;unicast;client_port=${session.clientRtpPort}-${session.clientRtcpPort};server_port=${serverUdpPort}-${serverUdpPort + 1}\r\n` +
            `\r\n`;
          this._writeResponse(session, response);
        });
      }
    } else if (method === 'PLAY') {
      session.playing = true;

      const response =
        `RTSP/1.0 200 OK\r\n` +
        `CSeq: ${cseq}\r\n` +
        `Session: ${session.id}\r\n` +
        `Range: npt=0.000-\r\n` +
        `\r\n`;

      this._writeResponse(session, response);
      this._log(`[BticinoRtspServer] Session ${session.id} is now PLAYING`);
      this.emit('play', session.id);
    } else if (method === 'TEARDOWN') {
      const response =
        `RTSP/1.0 200 OK\r\n` +
        `CSeq: ${cseq}\r\n` +
        `Session: ${session.id}\r\n` +
        `\r\n`;

      this._writeResponse(session, response);
      this._cleanupSession(session.id);
    }
  }

  /**
   * Safely writes an RTSP response string to a client session socket if it is still open and writable.
   *
   * @private
   * @param {Object} session - Client session object.
   * @param {string} response - Formatted RTSP response text.
   * @returns {void}
   */
  _writeResponse(session, response) {
    if (session && session.socket && !session.socket.destroyed && session.socket.writable) {
      try {
        session.socket.write(response);
      } catch (_) {}
    }
  }

  /**
   * Alias for sendRtpPacket(rtpPacket). Broadcasts an RTP packet to all active playing sessions.
   *
   * @public
   * @param {Buffer} rtpPacket - Plaintext RTP packet buffer.
   * @returns {void}
   *
   * @example
   * server.broadcastRtp(rtpPacket);
   */
  broadcastRtp(rtpPacket) {
    this.sendRtpPacket(rtpPacket);
  }

  /**
   * Cleans up an individual client session and associated UDP sockets.
   *
   * @private
   * @param {string} sessionId - ID of the session to terminate.
   * @returns {void}
   */
  _cleanupSession(sessionId) {
    const session = this._sessions.get(sessionId);
    if (!session) return;

    session.playing = false;
    if (session.udpSocket) {
      try { session.udpSocket.close(); } catch (_) {}
    }
    if (session.socket && !session.socket.destroyed) {
      try { session.socket.end(); } catch (_) {}
    }

    this._sessions.delete(sessionId);
    this._log(`[BticinoRtspServer:_cleanupSession] Session ${sessionId} cleaned up. Active sessions: ${this._sessions.size}`);

    if (this._sessions.size === 0) {
      this.emit('idle');
    }
  }

  /**
   * Returns the count of currently active playing client sessions.
   *
   * @public
   * @returns {number} Active playing session count.
   */
  getActiveSessionCount() {
    let count = 0;
    for (const session of this._sessions.values()) {
      if (session.playing) count++;
    }
    return count;
  }

  /**
   * Checks whether the RTSP server is actively listening and running.
   *
   * @public
   * @returns {boolean} True if server is running.
   */
  isRunning() {
    return this._running;
  }

  /**
   * Stops the RTSP server and terminates all active client connections.
   *
   * @public
   * @async
   * @returns {Promise<void>}
   */
  stop() {
    if (!this._running) {
      return Promise.resolve();
    }

    this._running = false;
    this._log('[BticinoRtspServer:stop] Stopping RTSP server...');

    for (const sessionId of Array.from(this._sessions.keys())) {
      this._cleanupSession(sessionId);
    }

    return new Promise((resolve) => {
      if (this._tcpServer) {
        this._tcpServer.close(() => {
          this._log('[BticinoRtspServer:stop] RTSP server stopped successfully');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

module.exports = BticinoRtspLoopbackServer;

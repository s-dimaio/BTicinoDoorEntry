/**
 * BticinoSrtpDecryptor
 *
 * Implements standard RFC 3711 / RFC 4568 SDES-SRTP decryption for AES_CM_128_HMAC_SHA1_80.
 * Derives session keys and salts using the AES-128 Counter Mode Pseudo-Random Function (PRF)
 * and decrypts incoming RTP media payloads in memory without external C++ dependencies.
 *
 * @module BticinoSrtpDecryptor
 */

'use strict';

const crypto = require('crypto');

class BticinoSrtpDecryptor {
  /**
   * Initializes the SRTP decryptor using an RFC 4568 SDES-SRTP inline key descriptor.
   *
   * @public
   * @constructor
   * @param {string} inlineKey - Base64 encoded 30-byte master key and master salt (16 bytes key + 14 bytes salt)
   *                             as extracted from SDP attribute `a=crypto:<tag> AES_CM_128_HMAC_SHA1_80 inline:<base64>`.
   * @param {Object} [opts={}] - Configuration options.
   * @param {boolean} [opts.debug=false] - Enables verbose debug logging.
   * @param {string} [opts.suite='AES_CM_128_HMAC_SHA1_80'] - SRTP crypto suite negotiated in SDP.
   *        Supported: `AES_CM_128_HMAC_SHA1_80` (10-byte auth tag) and `AES_CM_128_HMAC_SHA1_32` (4-byte auth tag).
   *
   * @example
   * const decryptor = new BticinoSrtpDecryptor('PE6tMhss+2m3PAiu/EvzgXQCrFOtRxRP3fzTQGx4');
   * const rtpPacket = decryptor.decrypt(srtpUdpBuffer);
   *
   * @example
   * const decryptor32 = new BticinoSrtpDecryptor(key, { suite: 'AES_CM_128_HMAC_SHA1_32' });
   */
  constructor(inlineKey, opts = {}) {
    if (!inlineKey || typeof inlineKey !== 'string') {
      throw new Error('[BticinoSrtpDecryptor:constructor] Master key must be a non-empty Base64 string');
    }

    this.opts = Object.assign({ debug: false, suite: 'AES_CM_128_HMAC_SHA1_80' }, opts);
    // Authentication tag length depends on the negotiated suite (RFC 4568 Section 6.2)
    this.authTagLen = /HMAC_SHA1_32$/i.test(this.opts.suite) ? 4 : 10;
    this._log = (...args) => { if (this.opts.debug) console.log('[BticinoSrtpDecryptor]', ...args); };
    this._error = (...args) => { console.error('[BticinoSrtpDecryptor]', ...args); };

    // Strip lifetime or MKI if present (e.g. inline:KEY|2^20|1:4)
    const base64Key = inlineKey.split('|')[0].trim();
    const rawKeyMaterial = Buffer.from(base64Key, 'base64');

    if (rawKeyMaterial.length < 30) {
      throw new Error(`[BticinoSrtpDecryptor:constructor] Invalid key material length (${rawKeyMaterial.length} bytes, expected at least 30 bytes)`);
    }

    this.masterKey = rawKeyMaterial.slice(0, 16);
    this.masterSalt = rawKeyMaterial.slice(16, 30);

    // Derive RFC 3711 session keys (label 0x00 for encryption, 0x02 for salt)
    this.sessionEncryptionKey = this._deriveKey(0x00, 16);
    this.sessionSalt = this._deriveKey(0x02, 14);

    // Track rollover counter (ROC) per SSRC for index calculation
    this._ssrcState = new Map();

    this._log('[BticinoSrtpDecryptor:constructor] Initialized SRTP decryptor successfully');
  }

  /**
   * Derives a session key or salt of specified length from the master key using RFC 3711 Section 4.3.1 PRF.
   *
   * @private
   * @param {number} label - Key derivation label (0x00 = encryption key, 0x01 = auth key, 0x02 = salt key).
   * @param {number} length - Desired key length in bytes.
   * @returns {Buffer} Derived session key or salt buffer.
   *
   * @example
   * const encKey = this._deriveKey(0x00, 16);
   */
  _deriveKey(label, length) {
    const x = Buffer.alloc(16, 0);
    this.masterSalt.copy(x, 0, 0, 14);
    // XOR label into byte 7
    x[7] ^= label;

    const cipher = crypto.createCipheriv('aes-128-ctr', this.masterKey, x);
    const zeros = Buffer.alloc(length, 0);
    return Buffer.concat([cipher.update(zeros), cipher.final()]);
  }

  /**
   * Decrypts an incoming UDP SRTP packet in-place and strips the trailing HMAC-SHA1-80 authentication tag.
   * Returns a standard unencrypted RFC 3550 RTP packet buffer (12-byte header + unencrypted H.264 payload).
   *
   * @public
   * @param {Buffer} packet - Raw UDP packet buffer containing SRTP encrypted payload and auth tag.
   * @returns {Buffer|null} Plaintext RFC 3550 RTP packet, or null if packet is invalid or truncated.
   *
   * @example
   * const plaintextRtp = decryptor.decrypt(udpBuffer);
   * if (plaintextRtp) {
   *   // Process or stream plaintext RTP packet
   * }
   */
  decrypt(packet) {
    // Minimum valid SRTP packet: 12-byte RTP header + at least 1 payload byte + authentication tag
    // (tag is 10 bytes for HMAC_SHA1_80 and 4 bytes for HMAC_SHA1_32; tiny NAL units such as PPS must not be dropped)
    if (!Buffer.isBuffer(packet) || packet.length < 12 + 1 + this.authTagLen) {
      return null;
    }

    try {
      const ssrc = packet.readUInt32BE(8);
      const seq = packet.readUInt16BE(2);

      // Parse variable RTP header length (CSRC list and header extensions)
      const cc = packet[0] & 0x0F;
      const hasExtension = (packet[0] & 0x10) !== 0;
      let headerLen = 12 + cc * 4;

      if (hasExtension) {
        if (packet.length < headerLen + 4) return null;
        const extLen = packet.readUInt16BE(headerLen + 2) * 4;
        headerLen += 4 + extLen;
      }

      // Trailing auth tag is 10 bytes (HMAC_SHA1_80) or 4 bytes (HMAC_SHA1_32)
      const authTagLen = this.authTagLen;
      const payloadLen = packet.length - headerLen - authTagLen;
      if (payloadLen <= 0) {
        return null;
      }

      // Track Rollover Counter (ROC) for index calculation
      let state = this._ssrcState.get(ssrc);
      if (!state) {
        state = { roc: 0, highestSeq: seq };
        this._ssrcState.set(ssrc, state);
      } else {
        // Detect 16-bit sequence number rollover
        if (seq < state.highestSeq && (state.highestSeq - seq) > 32768) {
          state.roc = (state.roc + 1) >>> 0;
        }
        state.highestSeq = seq;
      }

      // IV construction: (sessionSalt * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16)
      const iv = Buffer.alloc(16, 0);
      this.sessionSalt.copy(iv, 0, 0, 14);

      // XOR SSRC into bytes 4..7
      iv[4] ^= (ssrc >>> 24) & 0xFF;
      iv[5] ^= (ssrc >>> 16) & 0xFF;
      iv[6] ^= (ssrc >>> 8) & 0xFF;
      iv[7] ^= ssrc & 0xFF;

      // XOR ROC into bytes 8..11
      const roc = state.roc;
      iv[8] ^= (roc >>> 24) & 0xFF;
      iv[9] ^= (roc >>> 16) & 0xFF;
      iv[10] ^= (roc >>> 8) & 0xFF;
      iv[11] ^= roc & 0xFF;

      // XOR Sequence Number into bytes 12..13
      iv[12] ^= (seq >>> 8) & 0xFF;
      iv[13] ^= seq & 0xFF;

      // Decrypt encrypted payload using AES-128-CTR
      const encryptedPayload = packet.slice(headerLen, headerLen + payloadLen);
      const decipher = crypto.createDecipheriv('aes-128-ctr', this.sessionEncryptionKey, iv);
      const decryptedPayload = Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);

      // Reassemble standard unencrypted RTP packet (Header + Plaintext Payload)
      return Buffer.concat([
        packet.slice(0, headerLen),
        decryptedPayload
      ]);
    } catch (err) {
      this._error('[BticinoSrtpDecryptor:decrypt] Decryption error:', err.message);
      return null;
    }
  }
}

module.exports = BticinoSrtpDecryptor;

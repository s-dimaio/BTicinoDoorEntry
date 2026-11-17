/**
 * BticinoSnapshotExtractor
 *
 * Depacketizes RFC 6184 H.264 RTP streams into Annex-B NAL units (SPS, PPS, IDR frames).
 * Caches Sequence Parameter Sets (SPS) and Picture Parameter Sets (PPS) and emits
 * complete standalone H.264 Access Units (I-frames) whenever a keyframe arrives.
 * In addition, decodes H.264 keyframes into standard JPEG buffers using inlined WebAssembly
 * (H264Decoder) and pure JavaScript JPEG encoding (jpeg-js) for zero external binary dependencies.
 *
 * @module BticinoSnapshotExtractor
 */

'use strict';

const EventEmitter = require('events');
const { H264Decoder } = require('h264decoder');
const jpeg = require('jpeg-js');

class BticinoSnapshotExtractor extends EventEmitter {
  /**
   * Initializes the H.264 RTP depacketizer and snapshot extractor.
   *
   * @public
   * @constructor
   * @param {Object} [opts={}] - Configuration options.
   * @param {boolean} [opts.debug=false] - Enables verbose debug logging.
   * @param {number} [opts.jpegQuality=85] - Default JPEG quality (1-100).
   *
   * @example
   * const extractor = new BticinoSnapshotExtractor({ debug: true });
   * extractor.on('keyframe', (annexBBuffer) => {
   *   console.log('Complete H.264 IDR keyframe received, size:', annexBBuffer.length);
   * });
   * extractor.on('jpeg', (jpegBuffer) => {
   *   console.log('Decoded JPEG snapshot received, size:', jpegBuffer.length);
   * });
   */
  constructor(opts = {}) {
    super();
    this.opts = Object.assign({ debug: false, jpegQuality: 85 }, opts);
    this._log = (...args) => { if (this.opts.debug) console.log('[BticinoSnapshotExtractor]', ...args); };

    this._sps = null;
    this._pps = null;
    this._latestKeyframe = null;
    this._latestJpegSnapshot = null;

    // Buffer for assembling fragmented NAL units (FU-A, Type 28)
    this._fuBuffer = null;
    this._fuNalType = 0;
  }

  /**
   * Returns the most recent cached H.264 Annex-B keyframe buffer (SPS + PPS + IDR slice).
   *
   * @public
   * @returns {Buffer|null} Complete Annex-B H.264 keyframe buffer, or null if none received yet.
   *
   * @example
   * const keyframe = extractor.getLatestKeyframe();
   */
  getLatestKeyframe() {
    return this._latestKeyframe;
  }

  /**
   * Checks whether at least one complete H.264 keyframe snapshot has been received.
   *
   * @public
   * @returns {boolean} True if a keyframe snapshot is cached.
   *
   * @example
   * if (extractor.hasSnapshot()) {
   *   const snapshot = extractor.getLatestSnapshot();
   * }
   */
  hasSnapshot() {
    return this._latestKeyframe !== null;
  }

  /**
   * Alias for getLatestKeyframe(). Returns the most recent cached Annex-B keyframe buffer.
   *
   * @public
   * @returns {Buffer|null} Complete Annex-B H.264 keyframe buffer, or null if none received yet.
   *
   * @example
   * const snapshot = extractor.getLatestSnapshot();
   */
  getLatestSnapshot() {
    return this._latestKeyframe;
  }

  /**
   * Returns the most recent cached JPEG image buffer.
   *
   * @public
   * @returns {Buffer|null} JPEG image buffer, or null if none decoded yet.
   *
   * @example
   * const jpegBuffer = extractor.getLatestJpegSnapshot();
   */
  getLatestJpegSnapshot() {
    return this._latestJpegSnapshot;
  }

  /**
   * Checks whether at least one decoded JPEG snapshot is cached.
   *
   * @public
   * @returns {boolean} True if a JPEG snapshot is cached.
   *
   * @example
   * if (extractor.hasJpegSnapshot()) {
   *   const img = extractor.getLatestJpegSnapshot();
   * }
   */
  hasJpegSnapshot() {
    return this._latestJpegSnapshot !== null;
  }

  /**
   * Returns the cached SPS (Sequence Parameter Set) buffer.
   *
   * @public
   * @returns {Buffer|null} SPS NAL unit buffer, or null if not yet received.
   */
  getSps() {
    return this._sps;
  }

  /**
   * Returns the cached PPS (Picture Parameter Set) buffer.
   *
   * @public
   * @returns {Buffer|null} PPS NAL unit buffer, or null if not yet received.
   */
  getPps() {
    return this._pps;
  }

  /**
   * Converts a raw YUV420 (I420 planar) image buffer into an RGBA pixel buffer.
   *
   * @private
   * @param {Uint8Array} yuv - Raw YUV420 planar buffer.
   * @param {number} width - Image width in pixels.
   * @param {number} height - Image height in pixels.
   * @returns {Buffer} RGBA pixel buffer of size (width * height * 4).
   *
   * @example
   * const rgba = this._yuv420ToRgba(decoder.pic, 640, 480);
   */
  _yuv420ToRgba(yuv, width, height) {
    const rgba = Buffer.alloc(width * height * 4);
    const ySize = width * height;
    const uvSize = (width >> 1) * (height >> 1);
    const uOffset = ySize;
    const vOffset = ySize + uvSize;

    let rgbaIdx = 0;
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const yIdx = y * width + x;
        const uvIdx = (y >> 1) * (width >> 1) + (x >> 1);

        const yVal = yuv[yIdx];
        const uVal = yuv[uOffset + uvIdx] - 128;
        const vVal = yuv[vOffset + uvIdx] - 128;

        let r = yVal + 1.402 * vVal;
        let g = yVal - 0.344136 * uVal - 0.714136 * vVal;
        let b = yVal + 1.772 * uVal;

        rgba[rgbaIdx++] = r < 0 ? 0 : (r > 255 ? 255 : r);
        rgba[rgbaIdx++] = g < 0 ? 0 : (g > 255 ? 255 : g);
        rgba[rgbaIdx++] = b < 0 ? 0 : (b > 255 ? 255 : b);
        rgba[rgbaIdx++] = 255;
      }
    }

    return rgba;
  }

  /**
   * Splits an Annex-B H.264 byte stream into individual NAL units without start codes.
   *
   * @private
   * @param {Buffer} buffer - Complete Annex-B H.264 buffer.
   * @returns {Buffer[]} Array of NAL unit buffers without start codes.
   */
  _splitAnnexB(buffer) {
    const nalUnits = [];
    let startIndex = -1;

    for (let i = 0; i < buffer.length - 3; i++) {
      let startCodeLen = 0;
      if (buffer[i] === 0x00 && buffer[i + 1] === 0x00) {
        if (buffer[i + 2] === 0x01) {
          startCodeLen = 3;
        } else if (buffer[i + 2] === 0x00 && buffer[i + 3] === 0x01) {
          startCodeLen = 4;
        }
      }

      if (startCodeLen > 0) {
        if (startIndex >= 0) {
          const nalu = buffer.subarray(startIndex, i);
          if (nalu.length > 0) {
            nalUnits.push(nalu);
          }
        }
        startIndex = i + startCodeLen;
        i += (startCodeLen - 1);
      }
    }

    if (startIndex >= 0 && startIndex < buffer.length) {
      const nalu = buffer.subarray(startIndex);
      if (nalu.length > 0) {
        nalUnits.push(nalu);
      }
    }

    return nalUnits;
  }

  /**
   * Decodes an Annex-B H.264 keyframe buffer into a standard JPEG image buffer.
   * Uses WebAssembly H.264 decoder and pure JavaScript JPEG encoding.
   *
   * @public
   * @param {Buffer} keyframeBuffer - Complete Annex-B H.264 keyframe buffer.
   * @param {number} [quality=85] - Target JPEG quality (1-100).
   * @returns {Buffer|null} Encoded JPEG buffer, or null if decoding fails.
   *
   * @example
   * const jpegBuffer = extractor.convertKeyframeToJpeg(keyframeBuffer);
   */
  convertKeyframeToJpeg(keyframeBuffer, quality = 85) {
    if (!Buffer.isBuffer(keyframeBuffer) || keyframeBuffer.length < 64) {
      return null;
    }

    try {
      const nalUnits = this._splitAnnexB(keyframeBuffer);
      if (nalUnits.length < 3) {
        this._log('[BticinoSnapshotExtractor:convertKeyframeToJpeg] Incomplete NAL units in keyframe');
        return null;
      }

      const decoder = new H264Decoder();
      let pictureReady = false;

      for (const nalu of nalUnits) {
        const retCode = decoder.decode(nalu);
        if (retCode === H264Decoder.PIC_RDY) {
          pictureReady = true;
          break;
        }
      }

      if (!pictureReady || !decoder.pic || decoder.width <= 0 || decoder.height <= 0) {
        this._log('[BticinoSnapshotExtractor:convertKeyframeToJpeg] Decoder did not produce a ready picture');
        return null;
      }

      const rgba = this._yuv420ToRgba(decoder.pic, decoder.width, decoder.height);
      const encoded = jpeg.encode({ data: rgba, width: decoder.width, height: decoder.height }, quality);

      return encoded.data;
    } catch (err) {
      this._log('[BticinoSnapshotExtractor:convertKeyframeToJpeg] Failed to decode keyframe to JPEG:', err && err.message);
      return null;
    }
  }

  /**
   * Processes an incoming unencrypted RFC 3550 RTP packet carrying RFC 6184 H.264 payload.
   * Extracts SPS, PPS, and IDR keyframe NAL units and emits 'keyframe' and 'jpeg' when an IDR frame is complete.
   *
   * @public
   * @param {Buffer} rtpPacket - Plaintext RTP packet buffer (header + H.264 payload).
   * @returns {void}
   *
   * @example
   * extractor.processRtpPacket(decryptedRtpPacket);
   */
  processRtpPacket(rtpPacket) {
    if (!Buffer.isBuffer(rtpPacket) || rtpPacket.length < 13) {
      return;
    }

    // Parse RTP header length
    const cc = rtpPacket[0] & 0x0F;
    const hasExtension = (rtpPacket[0] & 0x10) !== 0;
    let headerLen = 12 + cc * 4;

    if (hasExtension) {
      if (rtpPacket.length < headerLen + 4) return;
      const extLen = rtpPacket.readUInt16BE(headerLen + 2) * 4;
      headerLen += 4 + extLen;
    }

    if (rtpPacket.length <= headerLen) {
      return;
    }

    const payload = rtpPacket.slice(headerLen);
    const nalHeader = payload[0];
    const nalType = nalHeader & 0x1F;

    // Single NAL unit packet (Types 1-23)
    if (nalType >= 1 && nalType <= 23) {
      this._handleNalUnit(nalType, payload);
      return;
    }

    // STAP-A: Aggregation Packet (Type 24)
    if (nalType === 24) {
      let offset = 1;
      while (offset + 2 < payload.length) {
        const naluSize = payload.readUInt16BE(offset);
        offset += 2;
        if (offset + naluSize <= payload.length) {
          const nalu = payload.slice(offset, offset + naluSize);
          const subType = nalu[0] & 0x1F;
          this._handleNalUnit(subType, nalu);
          offset += naluSize;
        } else {
          break;
        }
      }
      return;
    }

    // FU-A: Fragmentation Unit (Type 28)
    if (nalType === 28 && payload.length >= 2) {
      const fuIndicator = payload[0];
      const fuHeader = payload[1];
      const startBit = (fuHeader & 0x80) !== 0;
      const endBit = (fuHeader & 0x40) !== 0;
      const originalNalType = fuHeader & 0x1F;
      const reconstructedHeader = (fuIndicator & 0xE0) | originalNalType;

      const fuPayload = payload.slice(2);

      if (startBit) {
        this._fuNalType = originalNalType;
        this._fuBuffer = Buffer.concat([
          Buffer.from([reconstructedHeader]),
          fuPayload
        ]);
      } else if (this._fuBuffer) {
        this._fuBuffer = Buffer.concat([this._fuBuffer, fuPayload]);
        if (endBit) {
          const completeNalu = this._fuBuffer;
          const completedType = this._fuNalType;
          this._fuBuffer = null;
          this._fuNalType = 0;
          this._handleNalUnit(completedType, completeNalu);
        }
      }
    }
  }

  /**
   * Handles an extracted complete NAL unit and detects keyframe assembly.
   *
   * @private
   * @param {number} nalType - H.264 NAL unit type (5 = IDR, 7 = SPS, 8 = PPS).
   * @param {Buffer} nalu - NAL unit payload buffer without start code.
   * @returns {void}
   */
  _handleNalUnit(nalType, nalu) {
    const annexBPrefix = Buffer.from([0x00, 0x00, 0x00, 0x01]);

    if (nalType === 7) {
      // Sequence Parameter Set (SPS)
      this._sps = Buffer.concat([annexBPrefix, nalu]);
      this._log('[BticinoSnapshotExtractor:_handleNalUnit] Cached SPS NAL unit (length: ' + nalu.length + ')');
    } else if (nalType === 8) {
      // Picture Parameter Set (PPS)
      this._pps = Buffer.concat([annexBPrefix, nalu]);
      this._log('[BticinoSnapshotExtractor:_handleNalUnit] Cached PPS NAL unit (length: ' + nalu.length + ')');
    } else if (nalType === 5) {
      // Instantaneous Decoder Refresh (IDR) Keyframe
      // Drop bogus or micro-slices (e.g. 4-byte dummy probe packets) that would produce corrupt 29-byte snapshots
      if (!nalu || nalu.length < 64) {
        return;
      }

      // Ensure parameter sets (SPS and PPS) are available before assembling a keyframe
      if (!this._sps || !this._pps) {
        return;
      }

      this._log('[BticinoSnapshotExtractor:_handleNalUnit] Received IDR Keyframe slice (length: ' + nalu.length + ')');

      // Assemble complete Annex-B Access Unit: [SPS] + [PPS] + [IDR]
      const parts = [this._sps, this._pps, Buffer.concat([annexBPrefix, nalu])];
      const completeKeyframe = Buffer.concat(parts);
      this._latestKeyframe = completeKeyframe;

      this.emit('keyframe', completeKeyframe);
      this.emit('snapshot', completeKeyframe);

      // Attempt JPEG decoding
      const jpegBuffer = this.convertKeyframeToJpeg(completeKeyframe, this.opts.jpegQuality || 85);
      if (jpegBuffer) {
        this._latestJpegSnapshot = jpegBuffer;
        this._log(`[BticinoSnapshotExtractor:_handleNalUnit] Decoded JPEG snapshot ready (${jpegBuffer.length} bytes)`);
        this.emit('jpeg', jpegBuffer);
      }
    }
  }

  /**
   * Resets all internal buffers, cached parameter sets, and snapshots.
   *
   * @public
   * @returns {void}
   */
  reset() {
    this._sps = null;
    this._pps = null;
    this._latestKeyframe = null;
    this._latestJpegSnapshot = null;
    this._fuBuffer = null;
    this._fuNalType = 0;
  }
}

module.exports = BticinoSnapshotExtractor;

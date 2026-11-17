/**
 * Test: BTicino Snapshot JPEG Decoder & Extractor
 *
 * Validates:
 * 1. BticinoSnapshotExtractor instance and JPEG API surface.
 * 2. YUV420 to RGBA conversion and JPEG encoding.
 * 3. Validation of output JPEG headers (SOI 0xFFD8, EOI 0xFFD9).
 *
 * Run with: node test/test_snapshot_jpeg.js
 */

'use strict';

const { BticinoSnapshotExtractor } = require('../index.js');
const jpeg = require('jpeg-js');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

/**
 * Asserts a test condition.
 *
 * @param {string} testName - Description of the test case.
 * @param {boolean} condition - Condition expected to be true.
 * @param {string} [details=''] - Optional diagnostic details.
 */
function assert(testName, condition, details = '') {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`[PASS] ${testName}`);
  } else {
    failedTests++;
    console.error(`[FAIL] ${testName} ${details ? '- ' + details : ''}`);
  }
}

/**
 * Runs unit tests for snapshot JPEG extraction.
 */
function runTests() {
  console.log('\n--- Test Suite: BticinoSnapshotExtractor JPEG Conversion ---');

  const extractor = new BticinoSnapshotExtractor({ debug: false, jpegQuality: 80 });

  assert('Extractor has getLatestJpegSnapshot method', typeof extractor.getLatestJpegSnapshot === 'function');
  assert('Extractor has hasJpegSnapshot method', typeof extractor.hasJpegSnapshot === 'function');
  assert('Extractor has convertKeyframeToJpeg method', typeof extractor.convertKeyframeToJpeg === 'function');
  assert('Initial hasJpegSnapshot is false', extractor.hasJpegSnapshot() === false);
  assert('Initial getLatestJpegSnapshot is null', extractor.getLatestJpegSnapshot() === null);

  // Test YUV420 to RGBA conversion
  const width = 320;
  const height = 240;
  const yuv = new Uint8Array((width * height * 3) / 2);
  yuv.fill(128); // Neutral grey frame

  const rgba = extractor._yuv420ToRgba(yuv, width, height);
  assert('YUV420 to RGBA produces correct buffer size', Buffer.isBuffer(rgba) && rgba.length === width * height * 4);

  // Test JPEG encoding from RGBA
  const encoded = jpeg.encode({ data: rgba, width, height }, 80);
  assert('JPEG encode produces non-empty buffer', Buffer.isBuffer(encoded.data) && encoded.data.length > 500);

  const isJpeg = encoded.data[0] === 0xFF && encoded.data[1] === 0xD8 &&
    encoded.data[encoded.data.length - 2] === 0xFF && encoded.data[encoded.data.length - 1] === 0xD9;
  assert('JPEG buffer has valid SOI (0xFFD8) and EOI (0xFFD9) markers', isJpeg);

  // Test reset cleans up JPEG cache
  extractor._latestJpegSnapshot = encoded.data;
  assert('hasJpegSnapshot returns true when cached', extractor.hasJpegSnapshot() === true);
  extractor.reset();
  assert('reset() clears cached JPEG snapshot', extractor.hasJpegSnapshot() === false);

  console.log(`\nTests completed: ${passedTests}/${totalTests} passed (${failedTests} failed)`);
  if (failedTests > 0) {
    process.exit(1);
  }
}

runTests();

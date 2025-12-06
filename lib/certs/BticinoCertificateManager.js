const crypto = require('crypto');
const EventEmitter = require('events');
const { provisionCertificate } = require('./BticinoCertificates');

/**
 * Weekly check interval for certificate renewal (7 days in ms).
 * Used instead of a single long timer because Node.js setTimeout has a max limit
 * of ~24.8 days (2^31-1 ms), and certificates typically last 8+ months.
 * With a 30-day renewal buffer, weekly checks provide 4+ retry opportunities
 * while minimizing resource consumption.
 * @constant {number}
 */
const CHECK_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;  // 7 days

/**
 * BticinoCertificateManager
 * Certificate lifecycle orchestrator that mirrors the token refresh pattern used in BticinoAuthentication.
 * 
 * Responsibilities:
 *  1. Store current certificates with enriched timing metadata (validFrom, validTo, expiresAtMs)
 *  2. Schedule automatic certificate renewal before expiry (configurable skew)
 *  3. Emit 'certificatesCreated' whenever certificates are acquired (initial or renewal)
 *  4. Emit 'certificatesRefreshed' ONLY for renewal events (scheduled/forced)
 *  5. Provide forceRenew() for manual certificate renewal
 *  6. Manage cleanup of renewal timers on shutdown
 * 
 * @example
 * const certManager = new BticinoCertificateManager(api, {
 *   autoRenewal: true,
 *   renewalSkewSec: 30 * 24 * 60 * 60, // 30 days before expiry
 *   debug: false
 * });
 * 
 * // Set initial certificates (from disk or provisioning)
 * certManager.setCertificates(certPEM, privateKeyPem, {
 *   ownerId: 'uuid',
 *   ownerEmail: 'user@example.com',
 *   deviceId: 'device-id',
 *   plantId: 'plant-uuid',
 *   gatewayId: 'gateway-uuid'
 * });
 * 
 * // Listen for renewal events
 * certManager.on('certificatesRefreshed', (certs, meta) => {
 *   console.log('Certificates renewed, expires at:', certs.expiresAt);
 *   saveCertificatesToDisk(certs);
 * });
 * 
 * // Force renewal manually (e.g., after SIP auth failure)
 * await certManager.forceRenew();
 * 
 * // Cleanup on shutdown
 * certManager.shutdown();
 * 
 * @emits certificatesCreated {Object} Emitted after certificates are acquired (initial or renewal)
 * @emits certificatesRefreshed {Object} Emitted ONLY when certificates are renewed (not on initial set)
 */
class BticinoCertificateManager extends EventEmitter {
    /**
     * Create a BticinoCertificateManager instance.
     * @param {Object} api BticinoApiClient instance (must have renewCertificates method)
     * @param {Object} [options]
     * @param {boolean} [options.autoRenewal=true] Automatically schedule certificate renewal before expiry
     * @param {number} [options.renewalSkewSec=2592000] Seconds before expiry to trigger renewal (default: 30 days)
     * @param {boolean} [options.unrefRenewalTimer=true] Call unref() on renewal timer (allows process exit)
     * @param {boolean} [options.debug=false] Enable debug logging
     */
    constructor(api, options = {}) {
        super();
        this.api = api;
        this.opts = {
            autoRenewal: options.autoRenewal !== undefined ? options.autoRenewal : true,
            renewalSkewSec: options.renewalSkewSec !== undefined ? options.renewalSkewSec : (30 * 24 * 60 * 60), // 30 days
            unrefRenewalTimer: options.unrefRenewalTimer !== undefined ? options.unrefRenewalTimer : true,
            debug: !!options.debug
        };

        // Current enriched certificate object
        this.currentCertificates = null;

        // Parameters required for renewal (stored when setCertificates is called)
        this.renewalParams = null;

        // Renewal timer reference
        this._renewalTimer = null;
    }

    /**
     * Conditional logger (internal).
     * @private
     */
    _log(...args) {
        if (this.opts.debug) console.log('[CertificateManager]', ...args);
    }

    /**
     * Conditional warn logger (internal).
     * @private
     */
    _warn(...args) {
        if (this.opts.debug) console.warn('[CertificateManager]', ...args);
    }

    /**
     * Internal error logger — always log errors to stderr.
     * @private
     */
    _error(...args) {
        console.error('[CertificateManager]', ...args);
    }

    /**
     * Set/update current certificates and optionally schedule renewal.
     * Accepts PEM-encoded certificate and private key, extracts validity metadata,
     * and schedules automatic renewal if enabled.
     * 
     * @param {string} certPEM PEM-encoded certificate
     * @param {string} privateKeyPem PEM-encoded private key
     * @param {Object} [renewalParams] Parameters required for renewal
     * @param {string} [renewalParams.ownerId] Owner UUID (required for renewal)
     * @param {string} [renewalParams.ownerEmail] Owner email (required for renewal)
     * @param {string} [renewalParams.deviceId] Device ID / CN (required for renewal)
     * @param {string} [renewalParams.plantId] Plant UUID (required for renewal)
     * @param {string} [renewalParams.gatewayId] Gateway UUID (required for renewal)
     * @param {string} [renewalParams.plantName] Plant display name (optional)
     * @param {string} [renewalParams.country] Country code (optional, defaults to 'it')
     * @param {Object} [meta] Metadata flags (renewal, scheduled, forced, etc.)
     * @returns {Object} Enriched certificate object
     * @example
     * certManager.setCertificates(certPEM, privateKeyPem, {
     *   ownerId: 'user-uuid',
     *   ownerEmail: 'user@example.com',
     *   deviceId: 'device-123',
     *   plantId: 'plant-uuid',
     *   gatewayId: 'gateway-uuid'
     * });
     */
    setCertificates(certPEM, privateKeyPem, renewalParams = null, meta = {}) {
        if (!certPEM || !privateKeyPem) {
            throw new Error('Both certPEM and privateKeyPem are required');
        }

        // Store renewal parameters for future use
        if (renewalParams) {
            this.renewalParams = renewalParams;
        }

        // Enrich certificate with timing metadata
        const enriched = this._enrichCertificate(certPEM, privateKeyPem);

        // Handle the new certificates (emit events, schedule renewal)
        this._handleNewCertificates(enriched, meta);

        return enriched;
    }

    /**
     * Get current certificates.
     * @returns {Object|null} Current enriched certificate object or null if not set
     */
    getCurrentCertificates() {
        return this.currentCertificates;
    }

    /**
     * Force immediate certificate renewal.
     * Requires renewal parameters to have been set via setCertificates() or constructor.
     * @param {Object} [overrideParams] Optional parameters to override stored renewal params
     * @returns {Promise<Object>} Renewed certificate object
     * @throws {Error} If renewal parameters are missing or renewal fails
     * @example
     * const renewed = await certManager.forceRenew();
     * console.log('Renewed cert expires:', renewed.expiresAt);
     */
    async forceRenew(overrideParams = null) {
        const params = overrideParams || this.renewalParams;

        if (!params || !params.ownerId || !params.ownerEmail || !params.deviceId || !params.plantId || !params.gatewayId) {
            throw new Error('Renewal parameters (ownerId, ownerEmail, deviceId, plantId, gatewayId) are required for certificate renewal');
        }

        this._log('Forcing certificate renewal...');

        try {
            // Call the API's renewCertificates method
            const renewed = await this.api.renewCertificates({
                deviceId: params.deviceId,
                plantId: params.plantId,
                gatewayId: params.gatewayId,
                ownerEmail: params.ownerEmail,
                ownerId: params.ownerId,
                plantName: params.plantName,
                country: params.country || 'it'
            });

            this._log('Certificate renewal succeeded');

            // Handle the renewed certificates (emit events, schedule next renewal)
            this._handleNewCertificates(
                { certPEM: renewed.certificate, privateKeyPem: renewed.privateKey },
                { renewal: true, forced: true }
            );

            return this.currentCertificates;
        } catch (error) {
            this._error('Certificate renewal failed:', error.message);
            throw error;
        }
    }

    /**
     * Stop the certificate manager and cancel any scheduled renewal timer.
     * Safe to call multiple times.
     */
    stop() {
        this._clearRenewalTimer();
    }

    /**
     * Graceful shutdown alias (semantic convenience).
     * Ensures timers are cleared so the process can exit cleanly.
     */
    shutdown() {
        this.stop();
        this._log('Certificate manager shutdown complete');
    }

    /**
     * Alias for shutdown().
     */
    dispose() {
        this.shutdown();
    }

    /**
     * Internal: enrich certificate with timing metadata.
     * Extracts validFrom/validTo from X509Certificate and calculates expiresAtMs.
     * @private
     * @param {string} certPEM PEM-encoded certificate
     * @param {string} privateKeyPem PEM-encoded private key
     * @returns {Object} Enriched certificate object
     */
    _enrichCertificate(certPEM, privateKeyPem) {
        try {
            // Parse the certificate to extract metadata
            const cert = new crypto.X509Certificate(certPEM);

            const validFrom = cert.validFrom; // e.g., "Dec  6 10:30:00 2025 GMT"
            const validTo = cert.validTo;     // e.g., "Dec  6 10:30:00 2026 GMT"

            // Convert validTo to milliseconds timestamp
            const expiresAtMs = new Date(validTo).getTime();
            const validFromMs = new Date(validFrom).getTime();

            const receivedAtMs = Date.now();

            return {
                certPEM,
                privateKeyPem,
                validFrom,
                validTo,
                validFromMs,
                expiresAtMs,
                expiresAt: new Date(expiresAtMs).toISOString(),
                receivedAtMs,
                receivedAt: new Date(receivedAtMs).toISOString(),
                subject: cert.subject,
                issuer: cert.issuer,
                serialNumber: cert.serialNumber
            };
        } catch (error) {
            this._error('Failed to parse certificate:', error.message);
            throw new Error(`Certificate parsing failed: ${error.message}`);
        }
    }

    /**
     * Internal: schedule certificate renewal before expiry.
     * Uses a weekly polling approach instead of a single long timer because
     * Node.js setTimeout has a max limit of ~24.8 days (2^31-1 ms).
     * 
     * The method:
     * 1. Calculates the target renewal time (expiry - skew)
     * 2. If renewal is already due, triggers immediate renewal
     * 3. Otherwise, starts a weekly check that monitors time until renewal
     * 
     * @private
     * @param {Object} certs Enriched certificate object (must include expiresAtMs)
     */
    _scheduleCertificateRenewal(certs) {
        // Require renewal params to schedule automatic renewal
        if (!this.renewalParams || !certs?.expiresAtMs) {
            this._log('Skipping renewal scheduling (missing renewal params or expiresAtMs)');
            return;
        }

        // Clear any existing renewal timer
        this._clearRenewalTimer();

        const skewMs = this.opts.renewalSkewSec * 1000;
        const renewAtMs = certs.expiresAtMs - skewMs;
        const nowMs = Date.now();
        const delayMs = renewAtMs - nowMs;

        this._log(`Certificate renewal scheduling:`);
        this._log(`  Certificate expires: ${certs.expiresAt}`);
        this._log(`  Renewal target: ${new Date(renewAtMs).toISOString()}`);
        this._log(`  Time until renewal: ${this._formatDuration(delayMs)}`);

        // If renewal is already due, trigger immediately
        if (delayMs <= 0) {
            this._log('Certificate renewal is DUE NOW, triggering immediate renewal');
            setImmediate(() => this._doRenewal());
            return;
        }

        // Start weekly polling check
        this._log('Starting weekly renewal check (every 7 days)');
        this._renewalTargetMs = renewAtMs;  // Store target for weekly checks

        this._renewalTimer = setInterval(() => {
            this._renewalCheck();
        }, CHECK_INTERVAL_MS);

        // Unref the timer if supported (Node.js: allow process to exit even if timer is pending)
        if (this.opts.unrefRenewalTimer && typeof this._renewalTimer.unref === 'function') {
            this._renewalTimer.unref();
        }
    }

    /**
     * Internal: periodic check to see if it's time to renew.
     * Logs status and triggers renewal when target time is reached.
     * Runs weekly to balance security (4+ retry opportunities within 30-day buffer)
     * with resource efficiency.
     * @private
     */
    _renewalCheck() {
        const nowMs = Date.now();
        const remainingMs = this._renewalTargetMs - nowMs;

        if (remainingMs <= 0) {
            this._log('Renewal check: certificate renewal time reached, executing renewal...');
            this._clearRenewalTimer();
            this._doRenewal();
        } else {
            const daysLeft = Math.floor(remainingMs / (24 * 60 * 60 * 1000));
            this._log(`Renewal check: ${daysLeft} days until certificate renewal`);
        }
    }

    /**
     * Internal: clear renewal timer/interval.
     * @private
     */
    _clearRenewalTimer() {
        if (this._renewalTimer) {
            clearInterval(this._renewalTimer);  // Works for both setTimeout and setInterval
            this._renewalTimer = null;
            this._log('Renewal timer cleared');
        }
    }

    /**
     * Internal: format milliseconds as human-readable duration.
     * @private
     * @param {number} ms Milliseconds
     * @returns {string} Formatted duration (e.g., "45d 3h 12m 5s")
     */
    _formatDuration(ms) {
        if (ms < 0) return 'overdue';
        
        const totalSeconds = Math.floor(ms / 1000);
        const days = Math.floor(totalSeconds / (24 * 60 * 60));
        const hours = Math.floor((totalSeconds % (24 * 60 * 60)) / (60 * 60));
        const minutes = Math.floor((totalSeconds % (60 * 60)) / 60);
        const seconds = totalSeconds % 60;

        const parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        if (seconds > 0 || parts.length === 0) parts.push(`${seconds}s`);

        return parts.join(' ');
    }

    /**
     * Internal: perform scheduled certificate renewal.
     * Logs errors but does not throw to prevent unhandled rejections.
     * @private
     */
    async _doRenewal() {
        if (!this.renewalParams) {
            this._log('Scheduled renewal skipped (no renewal params set)');
            return;
        }

        this._log('Performing scheduled certificate renewal...');

        try {
            // Use BticinoCertificates.provisionCertificate directly
            const result = await provisionCertificate(this.api, {
                ownerId: this.renewalParams.ownerId,
                ownerEmail: this.renewalParams.ownerEmail,
                deviceId: this.renewalParams.deviceId,
                plantId: this.renewalParams.plantId,
                gatewayId: this.renewalParams.gatewayId,
                plantName: this.renewalParams.plantName,
                country: this.renewalParams.country || 'it',
                type: this.renewalParams.type,
                debug: this.opts.debug
            });

            this._log('Scheduled renewal succeeded');

            // Handle the renewed certificates
            this._handleNewCertificates(
                { certPEM: result.certPEM, privateKeyPem: result.privateKeyPem },
                { renewal: true, scheduled: true }
            );
        } catch (error) {
            this._error('Scheduled certificate renewal failed:', error.message);
            // Do not throw — let the error be logged but don't crash the process
        }
    }

    /**
     * Internal: central handler for all certificate acquisitions.
     * Enriches, stores, emits events, and schedules next renewal.
     * @private
     * @param {Object} certs Certificate object (may be raw or enriched)
     * @param {Object} [meta] Metadata flags (renewal, scheduled, forced, etc.)
     */
    _handleNewCertificates(certs, meta = {}) {
        if (!certs) return;

        // Enrich if not already enriched
        let enriched = certs;
        if (!certs.expiresAtMs) {
            enriched = this._enrichCertificate(certs.certPEM, certs.privateKeyPem);
        }

        // Store enriched certificates
        this.currentCertificates = enriched;

        // Emit 'certificatesCreated' event for all acquisitions
        try {
            this.emit('certificatesCreated', enriched, meta);
        } catch (e) {
            this._error('certificatesCreated event handler error:', e.message);
        }

        // Emit 'certificatesRefreshed' event ONLY for renewals
        if (meta && meta.renewal) {
            try {
                this.emit('certificatesRefreshed', enriched, meta);
            } catch (e) {
                this._error('certificatesRefreshed event handler error:', e.message);
            }
        }

        // Schedule next renewal if autoRenewal is enabled
        if (this.opts.autoRenewal) {
            this._scheduleCertificateRenewal(enriched);
        }
    }

    /**
     * Determine if certificate is still valid considering the renewal skew.
     * @private
     * @param {Object} certs Enriched certificate object
     * @returns {boolean}
     */
    _isCertificateStillValid(certs) {
        if (!certs?.expiresAtMs) return false;
        const skewMs = this.opts.renewalSkewSec * 1000;
        return Date.now() < (certs.expiresAtMs - skewMs);
    }
}

module.exports = BticinoCertificateManager;

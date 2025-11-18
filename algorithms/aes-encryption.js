import crypto from 'crypto';

/**
 * Encrypts data using AES-256-GCM
 * @param {string} text - Plaintext to encrypt
 * @param {Buffer} key - 32-byte AES key
 * @returns {Object} { iv, encryptedData, authTag }
 */
export function encryptAES256(text, key) {
    if (key.length !== 32) {
        throw new Error('Key must be 32 bytes (256 bits) for AES-256-GCM');
    }

    // Recommended IV size for GCM = 12 bytes
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted,
        authTag: authTag.toString('hex')
    };
}

/**
 * Decrypts AES-256-GCM encrypted data
 * @param {string} encryptedData - Encrypted hex string
 * @param {Buffer} key - 32-byte AES key
 * @param {string} ivHex - IV used during encryption (hex)
 * @param {string} authTagHex - GCM Auth Tag (hex)
 * @returns {string} Decrypted plaintext
 */
export function decryptAES256(encryptedData, key, ivHex, authTagHex) {
    if (key.length !== 32) {
        throw new Error('Key must be 32 bytes (256 bits) for AES-256-GCM');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

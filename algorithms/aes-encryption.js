import crypto from 'crypto';

/**
 * Encrypts data using AES-256-CBC with the provided 256-bit key
 * @param {string} text - The plaintext to encrypt
 * @param {Buffer} key - 256-bit (32-byte) encryption key
 * @returns {Object} - { iv: string, encryptedData: string }
 */
export function encryptAES256(text, key) {
    // Ensure key is 32 bytes (256 bits)
    if (key.length !== 32) {
        throw new Error('Key must be 32 bytes (256 bits) for AES-256');
    }

    // Generate random 16-byte initialization vector
    const iv = crypto.randomBytes(16);

    // Create cipher with AES-256-CBC
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    // Encrypt the text
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Return IV and encrypted data (both needed for decryption)
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted
    };
}

/**
 * Decrypts data using AES-256-CBC with the provided 256-bit key
 * @param {string} encryptedData - The encrypted data (hex string)
 * @param {Buffer} key - 256-bit (32-byte) encryption key
 * @param {string} ivHex - Initialization vector (hex string)
 * @returns {string} - Decrypted plaintext
 */
export function decryptAES256(encryptedData, key, ivHex) {
    // Ensure key is 32 bytes (256 bits)
    if (key.length !== 32) {
        throw new Error('Key must be 32 bytes (256 bits) for AES-256');
    }

    // Convert IV from hex to Buffer
    const iv = Buffer.from(ivHex, 'hex');

    // Create decipher with AES-256-CBC
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

    // Decrypt the data
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

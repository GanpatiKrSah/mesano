import crypto from 'crypto';

/**
 * Generates a 256-bit shared key from a message
 * @param {string} message - The input message
 * @returns {Object} - { sharedKey: Buffer|number, keyHash: Buffer|null }
 */
export function generateSharedKey(message) {
    // Encode message to UTF-8 buffer
    const messageBuffer = Buffer.from(message, 'utf8');
    const byteLength = messageBuffer.length;

    // Check byte length conditions
    if (byteLength < 20) {
        return { sharedKey: -1, keyHash: null }; // Less than 20 bytes
    }

    if (byteLength === 32) {
        // Exactly 32 bytes (256 bits), return as-is
        const keyHash = crypto.createHash('sha256').update(messageBuffer).digest();
        return { sharedKey: messageBuffer, keyHash: keyHash };
    }

    if (byteLength > 32) {
        return { sharedKey: 2, keyHash: null }; // More than 32 bytes
    }

    // If 20 <= byteLength < 32: Create 256-bit key
    // Hash the message with SHA256
    const hash = crypto.createHash('sha256').update(messageBuffer).digest();

    // Calculate how many bytes we need from the hash
    const bytesNeeded = 32 - byteLength; // To reach 256 bits (32 bytes)

    // Concatenate: original message + hash bytes (until we reach 256 bits)
    const sharedKey = Buffer.concat([
        messageBuffer,
        hash.slice(0, bytesNeeded)
    ]);

    // Generate hash of the shared key
    const keyHash = crypto.createHash('sha512').update(sharedKey).digest();

    return { sharedKey: sharedKey, keyHash: keyHash };
}
import crypto from 'crypto';

/**
 * Generates a 256-bit shared key from a message
 * @param {string} message - The input message
 * @returns {Object} - { sharedKey: Buffer|number, UID: Buffer|null }
 * UID is a unique identifier derived from the shared key
 * If the message is less than 20 bytes, sharedKey is -1 and UID is null
 * If the message is exactly 32 bytes, sharedKey is the message itself and UID is its SHA256 hash
 * If the message is more than 32 bytes, sharedKey is 2 and UID is null
 * If the message is between 20 and 32 bytes, sharedKey is a concatenation of the message and additional bytes from its SHA256 hash
 * The UID is derived from the shared key using SHA512
 */
export function generateSharedKey(message) {
    // Encode message to UTF-8 buffer
    const messageBuffer = Buffer.from(message, 'utf8');
    const byteLength = messageBuffer.length;

    // Check byte length conditions
    if (byteLength < 20) {
        return { sharedKey: -1, UID: null }; // Less than 20 bytes
    }

    if (byteLength === 32) {
        // Exactly 32 bytes (256 bits), return as-is
        const UID = crypto.createHash('sha256').update(messageBuffer).digest();
        return { sharedKey: messageBuffer, UID: UID };
    }

    if (byteLength > 32) {
        return { sharedKey: 2, UID: null }; // More than 32 bytes
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
    const UID = crypto.createHash('sha512').update(sharedKey).digest();

    return { sharedKey: sharedKey, UID: UID };
}
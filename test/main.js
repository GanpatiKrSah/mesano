import { generateSharedKey } from '../scripts/shared-key-generator.js';
import { encryptAES256, decryptAES256 } from '../algorithms/aes-encryption.js';
import readline from 'readline';

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

let sharedKey = null;
let keyHash = null;

function question(query) {
    return new Promise((resolve) => {
        rl.question(query, resolve);
    });
}

async function main() {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║            AES-256 Encryption with Shared Key Generator        ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    // Step 1: Get password and generate shared key
    while (true) {
        const password = await question('Enter your password: ');

        if (!password.trim()) {
            console.log('❌ Password cannot be empty\n');
            continue;
        }

        const result = generateSharedKey(password);
        sharedKey = result.sharedKey;
        keyHash = result.keyHash;

        if (sharedKey === -1) {
            console.log('❌ Password too short (minimum 20 bytes)\n');
            continue;
        } else if (sharedKey === 2) {
            console.log('❌ Password too long (maximum 32 bytes)\n');
            continue;
        }

        // Success - show generated shared key
        console.log('\n✅ Generated Shared Key:');
        console.log(sharedKey.toString('hex'));
        console.log('\nShared Key Hash:');
        console.log(keyHash.toString('hex'));
        console.log('');
        break;
    }

    // Step 2: Get message
    const message = await question('Enter your message: ');

    if (!message.trim()) {
        console.log('\n❌ Message cannot be empty');
        rl.close();
        return;
    }

    console.log('');

    // Step 3: Choose operation
    while (true) {
        console.log('1. Encrypt');
        console.log('2. Decrypt');
        const choice = await question('\nChoose operation (1 or 2): ');

        if (choice === '1') {
            // Encrypt
            try {
                const { iv, encryptedData } = encryptAES256(message, sharedKey);

                console.log('\n╔════════════════════════════════════════════════════════════════╗');
                console.log('║                      ENCRYPTION RESULT                         ║');
                console.log('╚════════════════════════════════════════════════════════════════╝\n');

                console.log('Encrypted Data:');
                console.log(encryptedData);
                console.log('\nIV (Initialization Vector):');
                console.log(iv);
                console.log('\n💾 Save both values for decryption\n');

            } catch (error) {
                console.log('\n❌ Encryption failed:', error.message, '\n');
            }
            break;

        } else if (choice === '2') {
            // Decrypt
            console.log('\nFor decryption, provide the encrypted data and IV');
            const encryptedData = await question('Enter encrypted data (hex): ');
            const iv = await question('Enter IV (hex): ');

            try {
                const decrypted = decryptAES256(encryptedData, sharedKey, iv);

                console.log('\n╔════════════════════════════════════════════════════════════════╗');
                console.log('║                      DECRYPTION RESULT                         ║');
                console.log('╚════════════════════════════════════════════════════════════════╝\n');

                console.log('Decrypted Message:');
                console.log(decrypted);
                console.log('');

            } catch (error) {
                console.log('\n❌ Decryption failed:', error.message, '\n');
            }
            break;

        } else {
            console.log('\n❌ Invalid choice. Please enter 1 or 2\n');
        }
    }

    rl.close();
}

main().catch(error => {
    console.error('Error:', error);
    rl.close();
});
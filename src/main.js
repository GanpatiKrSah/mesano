import { generateSharedKey } from '../scripts/shared-key-generator.js';
import readline from 'readline';

console.log('\n256-bit Shared Key Generator');
console.log('Type "exit" to quit\n');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'Password: '
});

rl.prompt();

rl.on('line', (input) => {
    const password = input.trim();

    // Handle exit command
    if (password.toLowerCase() === 'exit' || password.toLowerCase() === 'quit') {
        console.log('\nGoodbye!\n');
        rl.close();
        return;
    }

    // Skip empty input
    if (!password) {
        console.log('Empty input\n');
        rl.prompt();
        return;
    }

    // Generate shared key
    const { sharedKey, keyHash } = generateSharedKey(password);

    // Display only shared key and hash
    if (sharedKey === -1) {
        console.log('Error: Too short (min 20 bytes)\n');
    } else if (sharedKey === 2) {
        console.log('Error: Too long (max 32 bytes)\n');
    } else if (Buffer.isBuffer(sharedKey)) {
        console.log('\nShared Key:');
        console.log(sharedKey.toString('hex'));
        console.log('\nShared Key Hash:');
        console.log(keyHash.toString('hex'));
        console.log('');
    }

    rl.prompt();
});

rl.on('close', () => {
    process.exit(0);
});
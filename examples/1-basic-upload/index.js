/**
 * Example 1: Basic File Encryption
 * 
 * This example demonstrates how to encrypt and decrypt file content
 * using @zkterm/zkstorage crypto functions directly.
 * 
 * Works in Node.js 18+ using Web Crypto API.
 */

// Note: In a published package, use: import { ... } from '@zkterm/zkstorage';
// For local development, we import from the dist folder
import {
  encryptContent,
  decryptFile,
  formatFileSize,
  arrayBufferToBase64,
  isBrowser,
  isNode,
} from '../../dist/index.js';

async function main() {
  console.log('=== @zkterm/zkstorage - Basic Encryption Example ===\n');
  console.log('Environment:', isBrowser() ? 'Browser' : isNode() ? 'Node.js' : 'Unknown');
  console.log('');

  // Sample file content (in real usage, this would be from fs.readFileSync)
  const fileContent = 'Hello, this is a secret message that needs encryption!';
  const encoder = new TextEncoder();
  const contentBuffer = encoder.encode(fileContent).buffer;
  
  const password = 'MySecurePassword123!';
  const fileName = 'secret-message.txt';
  const mimeType = 'text/plain';

  console.log('Original Content:', fileContent);
  console.log('Original Size:', formatFileSize(contentBuffer.byteLength));
  console.log('Password:', password);
  console.log('');

  // Step 1: Encrypt the content
  console.log('Step 1: Encrypting...');
  const encrypted = await encryptContent(contentBuffer, password, {
    name: fileName,
    mimeType: mimeType,
  });

  console.log('Encrypted successfully!');
  console.log('- Original Name:', encrypted.originalName);
  console.log('- Original Size:', formatFileSize(encrypted.originalSize));
  console.log('- MIME Type:', encrypted.mimeType);
  console.log('- Checksum (SHA-256):', encrypted.checksum);
  console.log('- IV (base64):', encrypted.iv);
  console.log('- Salt (base64):', encrypted.salt);
  console.log('- Iterations:', encrypted.iterations);
  console.log('- Encrypted Size:', formatFileSize(encrypted.encryptedContent.byteLength));
  console.log('');

  // Step 2: Create metadata object (normally stored alongside encrypted content)
  const metadata = {
    iv: encrypted.iv,
    salt: encrypted.salt,
    iterations: encrypted.iterations,
    originalName: encrypted.originalName,
    originalSize: encrypted.originalSize,
    mimeType: encrypted.mimeType,
    checksum: encrypted.checksum,
    encryptedAt: Date.now(),
    version: '1.0',
  };

  // Step 3: Decrypt the content
  console.log('Step 2: Decrypting with correct password...');
  const decrypted = await decryptFile(encrypted.encryptedContent, metadata, password);

  const decoder = new TextDecoder();
  const decryptedText = decoder.decode(decrypted.content);

  console.log('Decrypted successfully!');
  console.log('- Name:', decrypted.name);
  console.log('- Size:', formatFileSize(decrypted.size));
  console.log('- MIME Type:', decrypted.mimeType);
  console.log('- Content:', decryptedText);
  console.log('');

  // Verify content matches
  console.log('Step 3: Verifying integrity...');
  if (decryptedText === fileContent) {
    console.log('SUCCESS: Decrypted content matches original!');
  } else {
    console.log('ERROR: Content mismatch!');
  }
  console.log('');

  // Step 4: Try with wrong password (should fail)
  console.log('Step 4: Attempting decryption with wrong password...');
  try {
    await decryptFile(encrypted.encryptedContent, metadata, 'WrongPassword');
    console.log('ERROR: Should have failed!');
  } catch (error) {
    console.log('Expected error:', error.message);
    console.log('SUCCESS: Wrong password correctly rejected!');
  }
  console.log('');

  console.log('=== Example Complete ===');
}

main().catch(console.error);

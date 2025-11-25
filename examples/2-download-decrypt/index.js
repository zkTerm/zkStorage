/**
 * Example 2: Download and Decrypt Workflow
 * 
 * This example demonstrates a complete encryption/decryption workflow
 * with serialization (simulating storage/download).
 * 
 * Works in Node.js 18+ using Web Crypto API.
 */

// Note: In a published package, use: import { ... } from '@zkterm/zkstorage';
import {
  encryptContent,
  decryptFile,
  formatFileSize,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  calculateChecksum,
} from '../../dist/index.js';

async function main() {
  console.log('=== @zkterm/zkstorage - Download & Decrypt Example ===\n');

  // Simulate a larger file with JSON data
  const jsonData = {
    users: [
      { id: 1, name: 'Alice', email: 'alice@example.com', role: 'admin' },
      { id: 2, name: 'Bob', email: 'bob@example.com', role: 'user' },
      { id: 3, name: 'Charlie', email: 'charlie@example.com', role: 'user' },
    ],
    settings: {
      theme: 'dark',
      language: 'en',
      notifications: true,
    },
    createdAt: new Date().toISOString(),
  };

  const fileContent = JSON.stringify(jsonData, null, 2);
  const encoder = new TextEncoder();
  const contentBuffer = encoder.encode(fileContent).buffer;
  
  const password = 'SuperSecretKey456!';
  const fileName = 'database-backup.json';

  console.log('Original JSON Data:');
  console.log(fileContent.substring(0, 200) + '...');
  console.log('');
  console.log('File Size:', formatFileSize(contentBuffer.byteLength));
  console.log('');

  // Step 1: Encrypt
  console.log('=== ENCRYPTION PHASE ===');
  const encrypted = await encryptContent(contentBuffer, password, {
    name: fileName,
    mimeType: 'application/json',
  });

  console.log('Encrypted File Details:');
  console.log('- Name:', encrypted.originalName);
  console.log('- Size:', formatFileSize(encrypted.originalSize));
  console.log('- Checksum:', encrypted.checksum);
  console.log('- Encrypted Size:', formatFileSize(encrypted.encryptedContent.byteLength));
  console.log('');

  // Step 2: Serialize for storage (convert to base64 for transport)
  console.log('=== STORAGE SIMULATION ===');
  const serialized = {
    content: arrayBufferToBase64(encrypted.encryptedContent),
    metadata: {
      iv: encrypted.iv,
      salt: encrypted.salt,
      iterations: encrypted.iterations,
      originalName: encrypted.originalName,
      originalSize: encrypted.originalSize,
      mimeType: encrypted.mimeType,
      checksum: encrypted.checksum,
      encryptedAt: Date.now(),
      version: '1.0',
    },
  };

  // Simulate storage as JSON (like saving to database or file)
  const storageJson = JSON.stringify(serialized);
  console.log('Serialized for storage:', formatFileSize(storageJson.length), 'bytes');
  console.log('');

  // Step 3: Deserialize (simulate download)
  console.log('=== DOWNLOAD SIMULATION ===');
  const downloaded = JSON.parse(storageJson);
  const encryptedContent = base64ToArrayBuffer(downloaded.content);
  const metadata = downloaded.metadata;

  console.log('Downloaded metadata:');
  console.log('- Original Name:', metadata.originalName);
  console.log('- IV:', metadata.iv.substring(0, 20) + '...');
  console.log('- Salt:', metadata.salt.substring(0, 20) + '...');
  console.log('- Iterations:', metadata.iterations);
  console.log('');

  // Step 4: Decrypt
  console.log('=== DECRYPTION PHASE ===');
  const decrypted = await decryptFile(encryptedContent, metadata, password);

  const decoder = new TextDecoder();
  const decryptedText = decoder.decode(decrypted.content);
  const decryptedJson = JSON.parse(decryptedText);

  console.log('Decrypted successfully!');
  console.log('- File Name:', decrypted.name);
  console.log('- File Size:', formatFileSize(decrypted.size));
  console.log('- MIME Type:', decrypted.mimeType);
  console.log('');

  // Step 5: Verify data integrity
  console.log('=== VERIFICATION ===');
  console.log('Decrypted JSON Data:');
  console.log('- Users count:', decryptedJson.users.length);
  console.log('- First user:', decryptedJson.users[0].name);
  console.log('- Theme:', decryptedJson.settings.theme);
  console.log('');

  // Verify checksum
  const verifyChecksum = await calculateChecksum(decrypted.content);
  if (verifyChecksum === metadata.checksum) {
    console.log('SUCCESS: Checksum verified!');
    console.log('- Original:', metadata.checksum.substring(0, 32) + '...');
    console.log('- Computed:', verifyChecksum.substring(0, 32) + '...');
  } else {
    console.log('ERROR: Checksum mismatch!');
  }
  console.log('');

  console.log('=== Example Complete ===');
}

main().catch(console.error);

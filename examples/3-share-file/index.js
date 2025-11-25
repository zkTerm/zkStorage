/**
 * Example 3: Secure File Sharing
 * 
 * This example demonstrates how to:
 * 1. Encrypt a file with user's password
 * 2. Generate a share key
 * 3. Re-encrypt the file with the share key
 * 4. Share the file without revealing the original password
 * 
 * Works in Node.js 18+ using Web Crypto API.
 */

// Note: In a published package, use: import { ... } from '@zkterm/zkstorage';
import {
  encryptContent,
  decryptFile,
  generateShareKey,
  createShareableFile,
  formatFileSize,
  arrayBufferToBase64,
} from '../../dist/index.js';

async function main() {
  console.log('=== @zkterm/zkstorage - Secure File Sharing Example ===\n');

  // Alice's secret document
  const document = `
CONFIDENTIAL MEMO
==================
To: Board of Directors
From: CEO Office
Date: ${new Date().toLocaleDateString()}

This is a confidential document that Alice wants to share
with Bob without revealing her master password.

Key points:
1. Q4 revenue exceeded expectations by 15%
2. New product launch scheduled for January
3. Strategic partnership under negotiation

Please keep this information strictly confidential.
`;

  const encoder = new TextEncoder();
  const contentBuffer = encoder.encode(document).buffer;
  
  // Alice's credentials
  const alicePassword = 'AliceSecretPassword123!';
  const fileName = 'confidential-memo.txt';

  console.log('=== ALICE: ENCRYPTS DOCUMENT ===');
  console.log('Document preview:', document.substring(0, 100) + '...');
  console.log('');

  // Step 1: Alice encrypts with her password
  const encrypted = await encryptContent(contentBuffer, alicePassword, {
    name: fileName,
    mimeType: 'text/plain',
  });

  const originalMetadata = {
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

  console.log('Document encrypted with Alice\'s password');
  console.log('- Original size:', formatFileSize(encrypted.originalSize));
  console.log('- Encrypted size:', formatFileSize(encrypted.encryptedContent.byteLength));
  console.log('- Checksum:', encrypted.checksum.substring(0, 32) + '...');
  console.log('');

  // Step 2: Alice generates a share key
  console.log('=== ALICE: GENERATES SHARE KEY ===');
  const shareKey = await generateShareKey();
  console.log('Share key generated:', shareKey.substring(0, 20) + '...');
  console.log('(This key can be shared with Bob via secure channel)');
  console.log('');

  // Step 3: Alice re-encrypts with share key
  console.log('=== ALICE: RE-ENCRYPTS FOR SHARING ===');
  const shareable = await createShareableFile(
    encrypted.encryptedContent,
    originalMetadata,
    alicePassword,
    shareKey
  );

  console.log('Document re-encrypted with share key');
  console.log('- New IV:', shareable.metadata.iv.substring(0, 20) + '...');
  console.log('- New Salt:', shareable.metadata.salt.substring(0, 20) + '...');
  console.log('- Same checksum:', shareable.metadata.checksum.substring(0, 32) + '...');
  console.log('');

  // Alice sends Bob: shareable.encryptedContent + shareable.metadata + shareKey
  // (In practice, this would be uploaded to a server)

  console.log('=== BOB: RECEIVES SHARED FILE ===');
  console.log('Bob receives:');
  console.log('- Encrypted content (base64):', arrayBufferToBase64(shareable.encryptedContent).substring(0, 40) + '...');
  console.log('- Metadata (IV, salt, etc.)');
  console.log('- Share key (via secure channel)');
  console.log('');

  // Step 4: Bob decrypts with share key
  console.log('=== BOB: DECRYPTS WITH SHARE KEY ===');
  const decrypted = await decryptFile(
    shareable.encryptedContent,
    shareable.metadata,
    shareKey
  );

  const decoder = new TextDecoder();
  const decryptedText = decoder.decode(decrypted.content);

  console.log('Document decrypted successfully!');
  console.log('- File name:', decrypted.name);
  console.log('- File size:', formatFileSize(decrypted.size));
  console.log('');
  console.log('Decrypted content:');
  console.log(decryptedText);
  console.log('');

  // Verify Bob got the same content
  console.log('=== VERIFICATION ===');
  if (decryptedText === document) {
    console.log('SUCCESS: Bob received the exact same document!');
  } else {
    console.log('ERROR: Content mismatch!');
  }
  console.log('');

  // Try with wrong share key
  console.log('=== SECURITY TEST: WRONG SHARE KEY ===');
  try {
    const wrongKey = await generateShareKey(); // Different key
    await decryptFile(shareable.encryptedContent, shareable.metadata, wrongKey);
    console.log('ERROR: Should have failed!');
  } catch (error) {
    console.log('Expected error:', error.message);
    console.log('SUCCESS: Wrong share key correctly rejected!');
  }
  console.log('');

  // Note: Alice's original password is never exposed
  console.log('=== SECURITY SUMMARY ===');
  console.log('- Alice\'s password: NEVER SHARED');
  console.log('- Share key: Used only for this share');
  console.log('- Each share can have a unique key');
  console.log('- Keys can expire (handled by backend)');
  console.log('');

  console.log('=== Example Complete ===');
}

main().catch(console.error);

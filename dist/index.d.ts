/**
 * @zkterm/zkstorage
 *
 * Privacy-first decentralized file storage with client-side AES-256-GCM encryption.
 * Files never leave your browser unencrypted - only the password holder can decrypt.
 *
 * Features:
 * - Client-side AES-256-GCM encryption
 * - PBKDF2 key derivation (200,000 iterations)
 * - SHA-256 checksum validation
 * - Unique IV and salt per file
 * - Support for file sharing with separate keys
 * - Works in browser and Node.js 18+
 *
 * Environment Support:
 * - Core crypto (encryptContent, decryptFile) works everywhere
 * - Browser-only: uploadFile, downloadFile (uses File API)
 * - Node.js: Use encryptContent/createFileLike for compatibility
 *
 * Quick Start (Browser):
 * ```typescript
 * import { uploadFile, downloadFile, listFiles } from '@zkterm/zkstorage';
 *
 * // Upload encrypted file
 * const result = await uploadFile(file, 'my-password');
 *
 * // Download and decrypt
 * await downloadFile(result.fileId, 'my-password');
 *
 * // List all files
 * const files = await listFiles();
 * ```
 *
 * Quick Start (Node.js):
 * ```typescript
 * import { encryptContent, decryptFile, createFileLike } from '@zkterm/zkstorage';
 * import { readFileSync } from 'fs';
 *
 * // Encrypt file content
 * const buffer = readFileSync('./myfile.pdf');
 * const file = createFileLike(buffer, 'myfile.pdf', 'application/pdf');
 * const encrypted = await encryptFile(file, 'password');
 * ```
 */
export { encryptFile, encryptContent, decryptFile, calculateChecksum, deriveKey, generateRandomBytes, downloadDecryptedFile, createDownloadBlob, generateShareKey, createShareableFile, formatFileSize, arrayBufferToBase64, base64ToArrayBuffer, uint8ArrayToBase64, base64ToUint8Array, uint8ArrayToHex, hexToUint8Array, isBrowser, isNode, createFileLike, PBKDF2_ITERATIONS, AES_KEY_LENGTH, IV_LENGTH, SALT_LENGTH, type EncryptedFileData, type DecryptedFileData, type EncryptionMetadata, type FileLike, } from './crypto';
export { createStorageClient, defaultClient, uploadToStorage, downloadFromStorage, downloadByCid, listStoredFiles, deleteStoredFile, createShareLink, downloadSharedFile, getIPFSGatewayUrl, getAlternativeGateways, } from './client';
export { createStorageService, defaultService, uploadFile, downloadFile, downloadFileByCid, downloadShared, uploadContent, downloadFileContent, listFiles, deleteFile, shareFile, type DownloadContentResult, } from './service';
export { type StoredFile, type StorageConfig, type StorageUploadResult, type StorageDownloadResult, type StorageListResult, type StorageErrorType, type StorageError, type StorageResult, type UploadResult, type DownloadResult, type ListResult, type ShareResult, DEFAULT_CONFIG, } from './types';

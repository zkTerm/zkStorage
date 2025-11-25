/**
 * @zkterm/zkstorage - Crypto Module
 * 
 * Client-side file encryption using AES-256-GCM + PBKDF2
 * 
 * Security Model:
 * - AES-256-GCM encryption for all files before upload
 * - Password-derived keys using PBKDF2 (200,000 iterations)
 * - Each file gets unique IV and salt for maximum security
 * - Files never leave browser/Node.js unencrypted
 * - SHA-256 checksum validation for file integrity
 * 
 * Environment Support:
 * - Core crypto functions work in both browser and Node.js 18+
 * - encryptFile() requires browser File API
 * - encryptContent() works in both environments
 * - downloadDecryptedFile() is browser-only
 */

// Encryption constants
export const PBKDF2_ITERATIONS = 200000;
export const AES_KEY_LENGTH = 256;
export const PBKDF2_HASH = 'SHA-256';
export const IV_LENGTH = 12; // 96 bits for GCM
export const SALT_LENGTH = 32; // 256 bits

/**
 * Encrypted file data with all metadata needed for decryption
 */
export interface EncryptedFileData {
  encryptedContent: ArrayBuffer;
  iv: string; // base64
  salt: string; // base64
  iterations: number;
  originalName: string;
  originalSize: number;
  mimeType: string;
  checksum: string; // SHA-256 of original file
}

/**
 * Decrypted file data ready for use
 */
export interface DecryptedFileData {
  content: ArrayBuffer;
  name: string;
  size: number;
  mimeType: string;
}

/**
 * Encryption metadata stored alongside encrypted file
 */
export interface EncryptionMetadata {
  iv: string;
  salt: string;
  iterations: number;
  originalName: string;
  originalSize: number;
  mimeType: string;
  checksum: string;
  encryptedAt: number; // timestamp
  version: string; // encryption version for future upgrades
}

/**
 * File-like object for Node.js compatibility
 * In browser, use native File. In Node.js, create this interface.
 */
export interface FileLike {
  name: string;
  size: number;
  type: string;
  arrayBuffer(): Promise<ArrayBuffer>;
}

// ============================================================
// Environment Detection
// ============================================================

/**
 * Check if running in browser environment
 */
export function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined';
}

/**
 * Check if running in Node.js environment
 */
export function isNode(): boolean {
  return typeof process !== 'undefined' && 
         process.versions != null && 
         process.versions.node != null;
}

// ============================================================
// Utility Functions
// ============================================================

/**
 * Convert ArrayBuffer to base64 string (works in browser and Node.js)
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  if (isNode()) {
    return Buffer.from(bytes).toString('base64');
  }
  // Browser
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to ArrayBuffer (works in browser and Node.js)
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  if (isNode()) {
    const buf = Buffer.from(base64, 'base64');
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  // Browser
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert Uint8Array to base64 string (works in browser and Node.js)
 */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  if (isNode()) {
    return Buffer.from(bytes).toString('base64');
  }
  // Browser - avoid spread on large arrays
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array (works in browser and Node.js)
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  if (isNode()) {
    const buf = Buffer.from(base64, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  // Browser
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function uint8ArrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ============================================================
// Crypto Functions
// ============================================================

/**
 * Get the crypto object (works in browser and Node.js 18+)
 */
function getCrypto(): Crypto {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  // Node.js fallback
  if (isNode()) {
    const nodeCrypto = require('crypto');
    if (nodeCrypto.webcrypto) {
      return nodeCrypto.webcrypto as Crypto;
    }
    throw new Error('Node.js 18+ required for Web Crypto API support');
  }
  throw new Error('Web Crypto API not available');
}

/**
 * Ensure Uint8Array has proper ArrayBuffer backing (not SharedArrayBuffer)
 * This fixes TypeScript compatibility with Web Crypto API
 */
function toBufferSource(arr: Uint8Array): BufferSource {
  const buffer = new ArrayBuffer(arr.length);
  const copy = new Uint8Array(buffer);
  copy.set(arr);
  return copy as BufferSource;
}

/**
 * Generate random bytes for IV or salt
 */
export function generateRandomBytes(length: number): Uint8Array {
  const crypto = getCrypto();
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Derive AES-256-GCM key from password using PBKDF2
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const crypto = getCrypto();
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toBufferSource(salt),
      iterations,
      hash: PBKDF2_HASH,
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: AES_KEY_LENGTH,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Calculate SHA-256 checksum of content
 */
export async function calculateChecksum(content: ArrayBuffer): Promise<string> {
  const crypto = getCrypto();
  const hashBuffer = await crypto.subtle.digest('SHA-256', content);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================
// Encryption Functions
// ============================================================

/**
 * Encrypt a File object using AES-256-GCM
 * 
 * @param file - File or FileLike object to encrypt
 * @param password - User's password for key derivation
 * @returns Encrypted file data with metadata
 * 
 * @note Browser: Use native File from input[type=file]
 * @note Node.js: Create FileLike object with name, size, type, and arrayBuffer()
 */
export async function encryptFile(
  file: File | FileLike,
  password: string
): Promise<EncryptedFileData> {
  const content = await file.arrayBuffer();
  
  const iv = generateRandomBytes(IV_LENGTH);
  const salt = generateRandomBytes(SALT_LENGTH);
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  const checksum = await calculateChecksum(content);
  
  const crypto = getCrypto();
  const encryptedContent = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBufferSource(iv) },
    key,
    content
  );
  
  return {
    encryptedContent,
    iv: uint8ArrayToBase64(iv),
    salt: uint8ArrayToBase64(salt),
    iterations: PBKDF2_ITERATIONS,
    originalName: file.name,
    originalSize: file.size,
    mimeType: file.type || 'application/octet-stream',
    checksum,
  };
}

/**
 * Encrypt raw content (ArrayBuffer) using AES-256-GCM
 * Works in both browser and Node.js environments.
 * 
 * @param content - ArrayBuffer to encrypt
 * @param password - User's password for key derivation
 * @param metadata - File metadata (name, mimeType)
 * @returns Encrypted file data with metadata
 */
export async function encryptContent(
  content: ArrayBuffer,
  password: string,
  metadata: { name: string; mimeType: string }
): Promise<EncryptedFileData> {
  const iv = generateRandomBytes(IV_LENGTH);
  const salt = generateRandomBytes(SALT_LENGTH);
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  const checksum = await calculateChecksum(content);
  
  const crypto = getCrypto();
  const encryptedContent = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBufferSource(iv) },
    key,
    content
  );
  
  return {
    encryptedContent,
    iv: uint8ArrayToBase64(iv),
    salt: uint8ArrayToBase64(salt),
    iterations: PBKDF2_ITERATIONS,
    originalName: metadata.name,
    originalSize: content.byteLength,
    mimeType: metadata.mimeType || 'application/octet-stream',
    checksum,
  };
}

/**
 * Decrypt file content using AES-256-GCM
 * Works in both browser and Node.js environments.
 * 
 * @param encryptedContent - Encrypted file content
 * @param metadata - Encryption metadata (IV, salt, etc.)
 * @param password - User's password for key derivation
 * @returns Decrypted file data
 * @throws Error if password is incorrect or file is corrupted
 */
export async function decryptFile(
  encryptedContent: ArrayBuffer,
  metadata: EncryptionMetadata,
  password: string
): Promise<DecryptedFileData> {
  const iv = base64ToUint8Array(metadata.iv);
  const salt = base64ToUint8Array(metadata.salt);
  const key = await deriveKey(password, salt, metadata.iterations);
  
  const crypto = getCrypto();
  
  try {
    const decryptedContent = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBufferSource(iv) },
      key,
      encryptedContent
    );
    
    // Verify checksum - CRITICAL for file integrity
    const checksum = await calculateChecksum(decryptedContent);
    if (checksum !== metadata.checksum) {
      throw new Error('File integrity check failed - checksum mismatch');
    }
    
    return {
      content: decryptedContent,
      name: metadata.originalName,
      size: metadata.originalSize,
      mimeType: metadata.mimeType,
    };
  } catch (error: any) {
    if (error.name === 'OperationError') {
      throw new Error('Decryption failed - incorrect password or corrupted file');
    }
    throw error;
  }
}

// ============================================================
// File Download Helpers (Browser only)
// ============================================================

/**
 * Create a Blob from decrypted file data
 * @note Browser-only
 */
export function createDownloadBlob(decryptedData: DecryptedFileData): Blob {
  if (!isBrowser()) {
    throw new Error('createDownloadBlob is only available in browser environment');
  }
  return new Blob([decryptedData.content], { type: decryptedData.mimeType });
}

/**
 * Trigger browser download of a decrypted file
 * @note Browser-only
 */
export function downloadDecryptedFile(decryptedData: DecryptedFileData): void {
  if (!isBrowser()) {
    throw new Error('downloadDecryptedFile is only available in browser environment');
  }
  
  const blob = new Blob([decryptedData.content], { type: decryptedData.mimeType });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = decryptedData.name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  
  URL.revokeObjectURL(url);
}

// ============================================================
// Share Key Functions
// ============================================================

/**
 * Generate a random file encryption key for sharing
 * This allows sharing files with a separate key instead of user password
 */
export async function generateShareKey(): Promise<string> {
  const keyBytes = generateRandomBytes(32);
  return uint8ArrayToBase64(keyBytes);
}

/**
 * Re-encrypt file with a share key instead of password
 * Useful for sharing encrypted files without revealing password
 */
export async function createShareableFile(
  encryptedContent: ArrayBuffer,
  originalMetadata: EncryptionMetadata,
  password: string,
  shareKey: string
): Promise<{ encryptedContent: ArrayBuffer; metadata: EncryptionMetadata }> {
  // First decrypt with password
  const decrypted = await decryptFile(encryptedContent, originalMetadata, password);
  
  // Re-encrypt with share key
  const newIv = generateRandomBytes(IV_LENGTH);
  const newSalt = generateRandomBytes(SALT_LENGTH);
  const key = await deriveKey(shareKey, newSalt, PBKDF2_ITERATIONS);
  
  const crypto = getCrypto();
  const newEncryptedContent = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBufferSource(newIv) },
    key,
    decrypted.content
  );
  
  return {
    encryptedContent: newEncryptedContent,
    metadata: {
      iv: uint8ArrayToBase64(newIv),
      salt: uint8ArrayToBase64(newSalt),
      iterations: PBKDF2_ITERATIONS,
      originalName: originalMetadata.originalName,
      originalSize: originalMetadata.originalSize,
      mimeType: originalMetadata.mimeType,
      checksum: originalMetadata.checksum,
      encryptedAt: Date.now(),
      version: '1.0',
    },
  };
}

// ============================================================
// Utilities
// ============================================================

/**
 * Format file size for display
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================
// Node.js Helpers
// ============================================================

/**
 * Create a FileLike object from a Node.js Buffer or ArrayBuffer
 * Use this for Node.js compatibility with encryptFile()
 * 
 * @example
 * ```typescript
 * import { readFileSync } from 'fs';
 * const buffer = readFileSync('./myfile.pdf');
 * const file = createFileLike(buffer, 'myfile.pdf', 'application/pdf');
 * const encrypted = await encryptFile(file, 'password');
 * ```
 */
export function createFileLike(
  content: Buffer | ArrayBuffer | Uint8Array,
  name: string,
  mimeType: string = 'application/octet-stream'
): FileLike {
  let arrayBuffer: ArrayBuffer;
  let size: number;

  if (content instanceof ArrayBuffer) {
    arrayBuffer = content;
    size = content.byteLength;
  } else if (Buffer.isBuffer(content)) {
    const buffer = new ArrayBuffer(content.length);
    const view = new Uint8Array(buffer);
    view.set(content);
    arrayBuffer = buffer;
    size = content.length;
  } else if (content instanceof Uint8Array) {
    const buffer = new ArrayBuffer(content.byteLength);
    const view = new Uint8Array(buffer);
    view.set(content);
    arrayBuffer = buffer;
    size = content.byteLength;
  } else {
    throw new Error('Invalid content type. Expected Buffer, ArrayBuffer, or Uint8Array.');
  }

  return {
    name,
    size,
    type: mimeType,
    arrayBuffer: async () => arrayBuffer,
  };
}

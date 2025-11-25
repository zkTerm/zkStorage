"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SALT_LENGTH = exports.IV_LENGTH = exports.PBKDF2_HASH = exports.AES_KEY_LENGTH = exports.PBKDF2_ITERATIONS = void 0;
exports.isBrowser = isBrowser;
exports.isNode = isNode;
exports.arrayBufferToBase64 = arrayBufferToBase64;
exports.base64ToArrayBuffer = base64ToArrayBuffer;
exports.uint8ArrayToBase64 = uint8ArrayToBase64;
exports.base64ToUint8Array = base64ToUint8Array;
exports.uint8ArrayToHex = uint8ArrayToHex;
exports.hexToUint8Array = hexToUint8Array;
exports.generateRandomBytes = generateRandomBytes;
exports.deriveKey = deriveKey;
exports.calculateChecksum = calculateChecksum;
exports.encryptFile = encryptFile;
exports.encryptContent = encryptContent;
exports.decryptFile = decryptFile;
exports.createDownloadBlob = createDownloadBlob;
exports.downloadDecryptedFile = downloadDecryptedFile;
exports.generateShareKey = generateShareKey;
exports.createShareableFile = createShareableFile;
exports.formatFileSize = formatFileSize;
exports.createFileLike = createFileLike;
// Encryption constants
exports.PBKDF2_ITERATIONS = 200000;
exports.AES_KEY_LENGTH = 256;
exports.PBKDF2_HASH = 'SHA-256';
exports.IV_LENGTH = 12; // 96 bits for GCM
exports.SALT_LENGTH = 32; // 256 bits
// ============================================================
// Environment Detection
// ============================================================
/**
 * Check if running in browser environment
 */
function isBrowser() {
    return typeof window !== 'undefined' && typeof document !== 'undefined';
}
/**
 * Check if running in Node.js environment
 */
function isNode() {
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
function arrayBufferToBase64(buffer) {
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
function base64ToArrayBuffer(base64) {
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
function uint8ArrayToBase64(bytes) {
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
function base64ToUint8Array(base64) {
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
function uint8ArrayToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
/**
 * Convert hex string to Uint8Array
 */
function hexToUint8Array(hex) {
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
function getCrypto() {
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
        return globalThis.crypto;
    }
    // Node.js fallback
    if (isNode()) {
        const nodeCrypto = require('crypto');
        if (nodeCrypto.webcrypto) {
            return nodeCrypto.webcrypto;
        }
        throw new Error('Node.js 18+ required for Web Crypto API support');
    }
    throw new Error('Web Crypto API not available');
}
/**
 * Generate random bytes for IV or salt
 */
function generateRandomBytes(length) {
    const crypto = getCrypto();
    return crypto.getRandomValues(new Uint8Array(length));
}
/**
 * Derive AES-256-GCM key from password using PBKDF2
 */
async function deriveKey(password, salt, iterations = exports.PBKDF2_ITERATIONS) {
    const crypto = getCrypto();
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const baseKey = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({
        name: 'PBKDF2',
        salt,
        iterations,
        hash: exports.PBKDF2_HASH,
    }, baseKey, {
        name: 'AES-GCM',
        length: exports.AES_KEY_LENGTH,
    }, false, ['encrypt', 'decrypt']);
}
/**
 * Calculate SHA-256 checksum of content
 */
async function calculateChecksum(content) {
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
async function encryptFile(file, password) {
    const content = await file.arrayBuffer();
    const iv = generateRandomBytes(exports.IV_LENGTH);
    const salt = generateRandomBytes(exports.SALT_LENGTH);
    const key = await deriveKey(password, salt, exports.PBKDF2_ITERATIONS);
    const checksum = await calculateChecksum(content);
    const crypto = getCrypto();
    const encryptedContent = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, content);
    return {
        encryptedContent,
        iv: uint8ArrayToBase64(iv),
        salt: uint8ArrayToBase64(salt),
        iterations: exports.PBKDF2_ITERATIONS,
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
async function encryptContent(content, password, metadata) {
    const iv = generateRandomBytes(exports.IV_LENGTH);
    const salt = generateRandomBytes(exports.SALT_LENGTH);
    const key = await deriveKey(password, salt, exports.PBKDF2_ITERATIONS);
    const checksum = await calculateChecksum(content);
    const crypto = getCrypto();
    const encryptedContent = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, content);
    return {
        encryptedContent,
        iv: uint8ArrayToBase64(iv),
        salt: uint8ArrayToBase64(salt),
        iterations: exports.PBKDF2_ITERATIONS,
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
async function decryptFile(encryptedContent, metadata, password) {
    const iv = base64ToUint8Array(metadata.iv);
    const salt = base64ToUint8Array(metadata.salt);
    const key = await deriveKey(password, salt, metadata.iterations);
    const crypto = getCrypto();
    try {
        const decryptedContent = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedContent);
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
    }
    catch (error) {
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
function createDownloadBlob(decryptedData) {
    if (!isBrowser()) {
        throw new Error('createDownloadBlob is only available in browser environment');
    }
    return new Blob([decryptedData.content], { type: decryptedData.mimeType });
}
/**
 * Trigger browser download of a decrypted file
 * @note Browser-only
 */
function downloadDecryptedFile(decryptedData) {
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
async function generateShareKey() {
    const keyBytes = generateRandomBytes(32);
    return uint8ArrayToBase64(keyBytes);
}
/**
 * Re-encrypt file with a share key instead of password
 * Useful for sharing encrypted files without revealing password
 */
async function createShareableFile(encryptedContent, originalMetadata, password, shareKey) {
    // First decrypt with password
    const decrypted = await decryptFile(encryptedContent, originalMetadata, password);
    // Re-encrypt with share key
    const newIv = generateRandomBytes(exports.IV_LENGTH);
    const newSalt = generateRandomBytes(exports.SALT_LENGTH);
    const key = await deriveKey(shareKey, newSalt, exports.PBKDF2_ITERATIONS);
    const crypto = getCrypto();
    const newEncryptedContent = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: newIv }, key, decrypted.content);
    return {
        encryptedContent: newEncryptedContent,
        metadata: {
            iv: uint8ArrayToBase64(newIv),
            salt: uint8ArrayToBase64(newSalt),
            iterations: exports.PBKDF2_ITERATIONS,
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
function formatFileSize(bytes) {
    if (bytes === 0)
        return '0 B';
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
function createFileLike(content, name, mimeType = 'application/octet-stream') {
    let arrayBuffer;
    let size;
    if (content instanceof ArrayBuffer) {
        arrayBuffer = content;
        size = content.byteLength;
    }
    else if (Buffer.isBuffer(content)) {
        arrayBuffer = content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength);
        size = content.length;
    }
    else if (content instanceof Uint8Array) {
        arrayBuffer = content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength);
        size = content.byteLength;
    }
    else {
        throw new Error('Invalid content type. Expected Buffer, ArrayBuffer, or Uint8Array.');
    }
    return {
        name,
        size,
        type: mimeType,
        arrayBuffer: async () => arrayBuffer,
    };
}

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
export declare const PBKDF2_ITERATIONS = 200000;
export declare const AES_KEY_LENGTH = 256;
export declare const PBKDF2_HASH = "SHA-256";
export declare const IV_LENGTH = 12;
export declare const SALT_LENGTH = 32;
/**
 * Encrypted file data with all metadata needed for decryption
 */
export interface EncryptedFileData {
    encryptedContent: ArrayBuffer;
    iv: string;
    salt: string;
    iterations: number;
    originalName: string;
    originalSize: number;
    mimeType: string;
    checksum: string;
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
    encryptedAt: number;
    version: string;
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
/**
 * Check if running in browser environment
 */
export declare function isBrowser(): boolean;
/**
 * Check if running in Node.js environment
 */
export declare function isNode(): boolean;
/**
 * Convert ArrayBuffer to base64 string (works in browser and Node.js)
 */
export declare function arrayBufferToBase64(buffer: ArrayBuffer): string;
/**
 * Convert base64 string to ArrayBuffer (works in browser and Node.js)
 */
export declare function base64ToArrayBuffer(base64: string): ArrayBuffer;
/**
 * Convert Uint8Array to base64 string (works in browser and Node.js)
 */
export declare function uint8ArrayToBase64(bytes: Uint8Array): string;
/**
 * Convert base64 string to Uint8Array (works in browser and Node.js)
 */
export declare function base64ToUint8Array(base64: string): Uint8Array;
/**
 * Convert Uint8Array to hex string
 */
export declare function uint8ArrayToHex(bytes: Uint8Array): string;
/**
 * Convert hex string to Uint8Array
 */
export declare function hexToUint8Array(hex: string): Uint8Array;
/**
 * Generate random bytes for IV or salt
 */
export declare function generateRandomBytes(length: number): Uint8Array;
/**
 * Derive AES-256-GCM key from password using PBKDF2
 */
export declare function deriveKey(password: string, salt: Uint8Array, iterations?: number): Promise<CryptoKey>;
/**
 * Calculate SHA-256 checksum of content
 */
export declare function calculateChecksum(content: ArrayBuffer): Promise<string>;
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
export declare function encryptFile(file: File | FileLike, password: string): Promise<EncryptedFileData>;
/**
 * Encrypt raw content (ArrayBuffer) using AES-256-GCM
 * Works in both browser and Node.js environments.
 *
 * @param content - ArrayBuffer to encrypt
 * @param password - User's password for key derivation
 * @param metadata - File metadata (name, mimeType)
 * @returns Encrypted file data with metadata
 */
export declare function encryptContent(content: ArrayBuffer, password: string, metadata: {
    name: string;
    mimeType: string;
}): Promise<EncryptedFileData>;
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
export declare function decryptFile(encryptedContent: ArrayBuffer, metadata: EncryptionMetadata, password: string): Promise<DecryptedFileData>;
/**
 * Create a Blob from decrypted file data
 * @note Browser-only
 */
export declare function createDownloadBlob(decryptedData: DecryptedFileData): Blob;
/**
 * Trigger browser download of a decrypted file
 * @note Browser-only
 */
export declare function downloadDecryptedFile(decryptedData: DecryptedFileData): void;
/**
 * Generate a random file encryption key for sharing
 * This allows sharing files with a separate key instead of user password
 */
export declare function generateShareKey(): Promise<string>;
/**
 * Re-encrypt file with a share key instead of password
 * Useful for sharing encrypted files without revealing password
 */
export declare function createShareableFile(encryptedContent: ArrayBuffer, originalMetadata: EncryptionMetadata, password: string, shareKey: string): Promise<{
    encryptedContent: ArrayBuffer;
    metadata: EncryptionMetadata;
}>;
/**
 * Format file size for display
 */
export declare function formatFileSize(bytes: number): string;
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
export declare function createFileLike(content: Buffer | ArrayBuffer | Uint8Array, name: string, mimeType?: string): FileLike;

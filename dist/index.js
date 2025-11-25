"use strict";
/**
 * @zkterm/zkstorage
 *
 * Privacy-first decentralized file storage with client-side AES-256-GCM encryption
 * and Groth16 zkSNARK password proofs.
 *
 * Files never leave your browser unencrypted - only the password holder can decrypt.
 * Zero-knowledge proofs verify password knowledge without revealing the password.
 *
 * Features:
 * - Client-side AES-256-GCM encryption
 * - PBKDF2 key derivation (200,000 iterations)
 * - SHA-256 checksum validation
 * - Unique IV and salt per file
 * - Groth16 zkSNARK password proofs (Poseidon hash)
 * - Full 256-bit SHA-256 password security (no truncation)
 * - Support for file sharing with separate keys
 * - Works in browser and Node.js 18+
 *
 * Environment Support:
 * - Core crypto (encryptContent, decryptFile) works everywhere
 * - ZK proofs require circuit files (WASM + zkey)
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
 * ZK Proof Usage:
 * ```typescript
 * import { generateStorageProof, verifyStorageProofLocal } from '@zkterm/zkstorage';
 *
 * // Generate proof (requires circuit files at /circuits/)
 * const result = await generateStorageProof('my-password');
 * console.log('Commitment:', result.commitment);
 *
 * // Verify password on download
 * const valid = await verifyStorageProofLocal(result.proof, result.commitment);
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateSaltFieldElement = exports.computeCommitment = exports.generateStorageProof = exports.DEFAULT_CONFIG = exports.shareFile = exports.deleteFile = exports.listFiles = exports.downloadFileContent = exports.uploadContent = exports.downloadShared = exports.downloadFileByCid = exports.downloadFile = exports.uploadFile = exports.defaultService = exports.createStorageService = exports.getAlternativeGateways = exports.getIPFSGatewayUrl = exports.downloadSharedFile = exports.createShareLink = exports.deleteStoredFile = exports.listStoredFiles = exports.downloadByCid = exports.downloadFromStorage = exports.uploadToStorage = exports.defaultClient = exports.createStorageClient = exports.SALT_LENGTH = exports.IV_LENGTH = exports.AES_KEY_LENGTH = exports.PBKDF2_ITERATIONS = exports.createFileLike = exports.isNode = exports.isBrowser = exports.hexToUint8Array = exports.uint8ArrayToHex = exports.base64ToUint8Array = exports.uint8ArrayToBase64 = exports.base64ToArrayBuffer = exports.arrayBufferToBase64 = exports.formatFileSize = exports.createShareableFile = exports.generateShareKey = exports.createDownloadBlob = exports.downloadDecryptedFile = exports.generateRandomBytes = exports.deriveKey = exports.calculateChecksum = exports.decryptFile = exports.encryptContent = exports.encryptFile = void 0;
exports.preloadCircuitFiles = exports.checkCircuitFilesAvailable = exports.resetCircuitConfig = exports.getCircuitConfig = exports.configureCircuitPaths = exports.parseProofFromAPI = exports.formatProofForAPI = exports.verifyStorageProofWithKey = exports.verifyStorageProofLocal = void 0;
// Core encryption utilities
var crypto_1 = require("./crypto");
// Encryption functions
Object.defineProperty(exports, "encryptFile", { enumerable: true, get: function () { return crypto_1.encryptFile; } });
Object.defineProperty(exports, "encryptContent", { enumerable: true, get: function () { return crypto_1.encryptContent; } });
Object.defineProperty(exports, "decryptFile", { enumerable: true, get: function () { return crypto_1.decryptFile; } });
Object.defineProperty(exports, "calculateChecksum", { enumerable: true, get: function () { return crypto_1.calculateChecksum; } });
Object.defineProperty(exports, "deriveKey", { enumerable: true, get: function () { return crypto_1.deriveKey; } });
Object.defineProperty(exports, "generateRandomBytes", { enumerable: true, get: function () { return crypto_1.generateRandomBytes; } });
// File download helpers (browser-only)
Object.defineProperty(exports, "downloadDecryptedFile", { enumerable: true, get: function () { return crypto_1.downloadDecryptedFile; } });
Object.defineProperty(exports, "createDownloadBlob", { enumerable: true, get: function () { return crypto_1.createDownloadBlob; } });
// Share key functions
Object.defineProperty(exports, "generateShareKey", { enumerable: true, get: function () { return crypto_1.generateShareKey; } });
Object.defineProperty(exports, "createShareableFile", { enumerable: true, get: function () { return crypto_1.createShareableFile; } });
// Utility functions
Object.defineProperty(exports, "formatFileSize", { enumerable: true, get: function () { return crypto_1.formatFileSize; } });
Object.defineProperty(exports, "arrayBufferToBase64", { enumerable: true, get: function () { return crypto_1.arrayBufferToBase64; } });
Object.defineProperty(exports, "base64ToArrayBuffer", { enumerable: true, get: function () { return crypto_1.base64ToArrayBuffer; } });
Object.defineProperty(exports, "uint8ArrayToBase64", { enumerable: true, get: function () { return crypto_1.uint8ArrayToBase64; } });
Object.defineProperty(exports, "base64ToUint8Array", { enumerable: true, get: function () { return crypto_1.base64ToUint8Array; } });
Object.defineProperty(exports, "uint8ArrayToHex", { enumerable: true, get: function () { return crypto_1.uint8ArrayToHex; } });
Object.defineProperty(exports, "hexToUint8Array", { enumerable: true, get: function () { return crypto_1.hexToUint8Array; } });
// Environment detection
Object.defineProperty(exports, "isBrowser", { enumerable: true, get: function () { return crypto_1.isBrowser; } });
Object.defineProperty(exports, "isNode", { enumerable: true, get: function () { return crypto_1.isNode; } });
// Node.js helpers
Object.defineProperty(exports, "createFileLike", { enumerable: true, get: function () { return crypto_1.createFileLike; } });
// Constants
Object.defineProperty(exports, "PBKDF2_ITERATIONS", { enumerable: true, get: function () { return crypto_1.PBKDF2_ITERATIONS; } });
Object.defineProperty(exports, "AES_KEY_LENGTH", { enumerable: true, get: function () { return crypto_1.AES_KEY_LENGTH; } });
Object.defineProperty(exports, "IV_LENGTH", { enumerable: true, get: function () { return crypto_1.IV_LENGTH; } });
Object.defineProperty(exports, "SALT_LENGTH", { enumerable: true, get: function () { return crypto_1.SALT_LENGTH; } });
// Storage client (low-level API)
var client_1 = require("./client");
Object.defineProperty(exports, "createStorageClient", { enumerable: true, get: function () { return client_1.createStorageClient; } });
Object.defineProperty(exports, "defaultClient", { enumerable: true, get: function () { return client_1.defaultClient; } });
Object.defineProperty(exports, "uploadToStorage", { enumerable: true, get: function () { return client_1.uploadToStorage; } });
Object.defineProperty(exports, "downloadFromStorage", { enumerable: true, get: function () { return client_1.downloadFromStorage; } });
Object.defineProperty(exports, "downloadByCid", { enumerable: true, get: function () { return client_1.downloadByCid; } });
Object.defineProperty(exports, "listStoredFiles", { enumerable: true, get: function () { return client_1.listStoredFiles; } });
Object.defineProperty(exports, "deleteStoredFile", { enumerable: true, get: function () { return client_1.deleteStoredFile; } });
Object.defineProperty(exports, "createShareLink", { enumerable: true, get: function () { return client_1.createShareLink; } });
Object.defineProperty(exports, "downloadSharedFile", { enumerable: true, get: function () { return client_1.downloadSharedFile; } });
Object.defineProperty(exports, "getIPFSGatewayUrl", { enumerable: true, get: function () { return client_1.getIPFSGatewayUrl; } });
Object.defineProperty(exports, "getAlternativeGateways", { enumerable: true, get: function () { return client_1.getAlternativeGateways; } });
// High-level service
var service_1 = require("./service");
Object.defineProperty(exports, "createStorageService", { enumerable: true, get: function () { return service_1.createStorageService; } });
Object.defineProperty(exports, "defaultService", { enumerable: true, get: function () { return service_1.defaultService; } });
// Browser-only functions
Object.defineProperty(exports, "uploadFile", { enumerable: true, get: function () { return service_1.uploadFile; } });
Object.defineProperty(exports, "downloadFile", { enumerable: true, get: function () { return service_1.downloadFile; } });
Object.defineProperty(exports, "downloadFileByCid", { enumerable: true, get: function () { return service_1.downloadFileByCid; } });
Object.defineProperty(exports, "downloadShared", { enumerable: true, get: function () { return service_1.downloadShared; } });
// Universal functions
Object.defineProperty(exports, "uploadContent", { enumerable: true, get: function () { return service_1.uploadContent; } });
Object.defineProperty(exports, "downloadFileContent", { enumerable: true, get: function () { return service_1.downloadFileContent; } });
Object.defineProperty(exports, "listFiles", { enumerable: true, get: function () { return service_1.listFiles; } });
Object.defineProperty(exports, "deleteFile", { enumerable: true, get: function () { return service_1.deleteFile; } });
Object.defineProperty(exports, "shareFile", { enumerable: true, get: function () { return service_1.shareFile; } });
// Types
var types_1 = require("./types");
Object.defineProperty(exports, "DEFAULT_CONFIG", { enumerable: true, get: function () { return types_1.DEFAULT_CONFIG; } });
// Zero-Knowledge Proof module
var proof_1 = require("./proof");
// Proof generation
Object.defineProperty(exports, "generateStorageProof", { enumerable: true, get: function () { return proof_1.generateStorageProof; } });
Object.defineProperty(exports, "computeCommitment", { enumerable: true, get: function () { return proof_1.computeCommitment; } });
Object.defineProperty(exports, "generateSaltFieldElement", { enumerable: true, get: function () { return proof_1.generateSaltFieldElement; } });
// Proof verification
Object.defineProperty(exports, "verifyStorageProofLocal", { enumerable: true, get: function () { return proof_1.verifyStorageProofLocal; } });
Object.defineProperty(exports, "verifyStorageProofWithKey", { enumerable: true, get: function () { return proof_1.verifyStorageProofWithKey; } });
// API helpers
Object.defineProperty(exports, "formatProofForAPI", { enumerable: true, get: function () { return proof_1.formatProofForAPI; } });
Object.defineProperty(exports, "parseProofFromAPI", { enumerable: true, get: function () { return proof_1.parseProofFromAPI; } });
// Circuit configuration
Object.defineProperty(exports, "configureCircuitPaths", { enumerable: true, get: function () { return proof_1.configureCircuitPaths; } });
Object.defineProperty(exports, "getCircuitConfig", { enumerable: true, get: function () { return proof_1.getCircuitConfig; } });
Object.defineProperty(exports, "resetCircuitConfig", { enumerable: true, get: function () { return proof_1.resetCircuitConfig; } });
// Utility functions
Object.defineProperty(exports, "checkCircuitFilesAvailable", { enumerable: true, get: function () { return proof_1.checkCircuitFilesAvailable; } });
Object.defineProperty(exports, "preloadCircuitFiles", { enumerable: true, get: function () { return proof_1.preloadCircuitFiles; } });

/**
 * @zkterm/zkstorage - Type Definitions
 */
/**
 * Stored file record from database/storage backend
 */
export interface StoredFile {
    id: string;
    cid: string;
    metadataCid: string;
    originalName: string;
    originalSize: number;
    mimeType: string;
    uploadedAt: number;
    checksum: string;
}
/**
 * Storage upload result
 */
export interface StorageUploadResult {
    success: boolean;
    cid?: string;
    metadataCid?: string;
    fileId?: string;
    gateway?: string;
    error?: string;
}
/**
 * Storage download result
 */
export interface StorageDownloadResult {
    success: boolean;
    encryptedContent?: ArrayBuffer;
    metadata?: import('./crypto').EncryptionMetadata;
    error?: string;
}
/**
 * Storage list result
 */
export interface StorageListResult {
    success: boolean;
    files?: StoredFile[];
    error?: string;
}
/**
 * Storage error types for error handling
 */
export type StorageErrorType = 'auth' | 'encryption' | 'network' | 'storage' | 'validation' | 'unknown';
/**
 * Structured error with user-friendly message
 */
export interface StorageError {
    type: StorageErrorType;
    message: string;
    userMessage: string;
}
/**
 * Base storage result with optional error
 */
export interface StorageResult {
    success: boolean;
    error?: StorageError;
}
/**
 * Upload result with file details
 */
export interface UploadResult extends StorageResult {
    fileId?: string;
    cid?: string;
    name?: string;
    size?: number;
    gateway?: string;
}
/**
 * Download result with file details
 */
export interface DownloadResult extends StorageResult {
    name?: string;
    size?: number;
    mimeType?: string;
}
/**
 * List result with files and totals
 */
export interface ListResult extends StorageResult {
    files?: StoredFile[];
    totalSize?: number;
    totalCount?: number;
}
/**
 * Share result with share URL and key
 */
export interface ShareResult extends StorageResult {
    shareUrl?: string;
    shareKey?: string;
    expiresAt?: number;
}
/**
 * Storage client configuration
 */
export interface StorageConfig {
    /** Base URL for storage API (default: '/api/storage') */
    apiBaseUrl?: string;
    /** IPFS gateway URL template (use {cid} placeholder) */
    ipfsGateway?: string;
    /** Maximum file size in bytes (default: 100MB) */
    maxFileSize?: number;
    /** Custom fetch function (for Node.js or testing) */
    fetchFn?: typeof fetch;
}
/**
 * Default storage configuration
 */
export declare const DEFAULT_CONFIG: Required<StorageConfig>;

/**
 * @zkterm/zkstorage - Storage Client
 *
 * Handles communication with storage backend:
 * - Uploading encrypted files
 * - Downloading encrypted files
 * - Listing and managing files
 * - Creating share links
 */
import { type EncryptedFileData } from './crypto';
import { type StorageConfig, type StorageUploadResult, type StorageDownloadResult, type StorageListResult } from './types';
/**
 * Create a configured storage client
 *
 * @param config - Configuration options
 * @returns Storage client instance
 */
export declare function createStorageClient(config?: StorageConfig): {
    uploadToStorage: (encryptedData: EncryptedFileData) => Promise<StorageUploadResult>;
    downloadFromStorage: (fileId: string) => Promise<StorageDownloadResult>;
    downloadByCid: (cid: string, metadataCid: string) => Promise<StorageDownloadResult>;
    listStoredFiles: () => Promise<StorageListResult>;
    deleteStoredFile: (fileId: string) => Promise<{
        success: boolean;
        error?: string;
    }>;
    createShareLink: (fileId: string, shareKey: string, expiresIn?: number) => Promise<{
        success: boolean;
        shareToken?: string;
        shareUrl?: string;
        error?: string;
    }>;
    downloadSharedFile: (shareToken: string) => Promise<StorageDownloadResult & {
        shareKey?: string;
    }>;
    getIPFSGatewayUrl: (cid: string) => string;
    getAlternativeGateways: (cid: string) => string[];
};
export declare const defaultClient: {
    uploadToStorage: (encryptedData: EncryptedFileData) => Promise<StorageUploadResult>;
    downloadFromStorage: (fileId: string) => Promise<StorageDownloadResult>;
    downloadByCid: (cid: string, metadataCid: string) => Promise<StorageDownloadResult>;
    listStoredFiles: () => Promise<StorageListResult>;
    deleteStoredFile: (fileId: string) => Promise<{
        success: boolean;
        error?: string;
    }>;
    createShareLink: (fileId: string, shareKey: string, expiresIn?: number) => Promise<{
        success: boolean;
        shareToken?: string;
        shareUrl?: string;
        error?: string;
    }>;
    downloadSharedFile: (shareToken: string) => Promise<StorageDownloadResult & {
        shareKey?: string;
    }>;
    getIPFSGatewayUrl: (cid: string) => string;
    getAlternativeGateways: (cid: string) => string[];
};
export declare const uploadToStorage: (encryptedData: EncryptedFileData) => Promise<StorageUploadResult>, downloadFromStorage: (fileId: string) => Promise<StorageDownloadResult>, downloadByCid: (cid: string, metadataCid: string) => Promise<StorageDownloadResult>, listStoredFiles: () => Promise<StorageListResult>, deleteStoredFile: (fileId: string) => Promise<{
    success: boolean;
    error?: string;
}>, createShareLink: (fileId: string, shareKey: string, expiresIn?: number) => Promise<{
    success: boolean;
    shareToken?: string;
    shareUrl?: string;
    error?: string;
}>, downloadSharedFile: (shareToken: string) => Promise<StorageDownloadResult & {
    shareKey?: string;
}>, getIPFSGatewayUrl: (cid: string) => string, getAlternativeGateways: (cid: string) => string[];

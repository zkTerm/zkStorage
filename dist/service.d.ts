/**
 * @zkterm/zkstorage - High-level Service
 *
 * Provides unified interface for:
 * - File upload (encrypt + upload)
 * - File download (download + decrypt)
 * - File listing
 * - File sharing
 *
 * Environment Support:
 * - uploadFile(): Browser-only (uses File API and FormData)
 * - uploadContent(): Works in both browser and Node.js
 * - downloadFile(): Browser-only (triggers download)
 * - downloadFileContent(): Works in both environments (returns ArrayBuffer)
 * - listFiles(), deleteFile(), shareFile(): Work in both environments
 */
import { formatFileSize, type FileLike } from './crypto';
import { type StorageConfig } from './types';
import { type StorageResult, type UploadResult, type DownloadResult, type ListResult, type ShareResult } from './types';
/**
 * Extended download result that includes decrypted content
 */
export interface DownloadContentResult extends DownloadResult {
    content?: ArrayBuffer;
}
/**
 * Create a high-level storage service
 *
 * @param config - Storage client configuration
 * @returns Storage service with upload, download, list, delete, share functions
 */
export declare function createStorageService(config?: StorageConfig): {
    uploadFile: (file: File | FileLike, password: string, onProgress?: (progress: number) => void) => Promise<UploadResult>;
    downloadFile: (fileId: string, password: string) => Promise<DownloadResult>;
    downloadFileByCid: (cid: string, metadataCid: string, password: string) => Promise<DownloadResult>;
    downloadShared: (shareToken: string, shareKey: string) => Promise<DownloadResult>;
    uploadContent: (content: ArrayBuffer, metadata: {
        name: string;
        mimeType: string;
    }, password: string, onProgress?: (progress: number) => void) => Promise<UploadResult>;
    downloadFileContent: (fileId: string, password: string) => Promise<DownloadContentResult>;
    listFiles: () => Promise<ListResult>;
    deleteFile: (fileId: string) => Promise<StorageResult>;
    shareFile: (fileId: string, password: string, expiresInHours?: number) => Promise<ShareResult>;
    formatFileSize: typeof formatFileSize;
    getIPFSGatewayUrl: (cid: string) => string;
};
export declare const defaultService: {
    uploadFile: (file: File | FileLike, password: string, onProgress?: (progress: number) => void) => Promise<UploadResult>;
    downloadFile: (fileId: string, password: string) => Promise<DownloadResult>;
    downloadFileByCid: (cid: string, metadataCid: string, password: string) => Promise<DownloadResult>;
    downloadShared: (shareToken: string, shareKey: string) => Promise<DownloadResult>;
    uploadContent: (content: ArrayBuffer, metadata: {
        name: string;
        mimeType: string;
    }, password: string, onProgress?: (progress: number) => void) => Promise<UploadResult>;
    downloadFileContent: (fileId: string, password: string) => Promise<DownloadContentResult>;
    listFiles: () => Promise<ListResult>;
    deleteFile: (fileId: string) => Promise<StorageResult>;
    shareFile: (fileId: string, password: string, expiresInHours?: number) => Promise<ShareResult>;
    formatFileSize: typeof formatFileSize;
    getIPFSGatewayUrl: (cid: string) => string;
};
export declare const uploadFile: (file: File | FileLike, password: string, onProgress?: (progress: number) => void) => Promise<UploadResult>, downloadFile: (fileId: string, password: string) => Promise<DownloadResult>, downloadFileByCid: (cid: string, metadataCid: string, password: string) => Promise<DownloadResult>, downloadShared: (shareToken: string, shareKey: string) => Promise<DownloadResult>, uploadContent: (content: ArrayBuffer, metadata: {
    name: string;
    mimeType: string;
}, password: string, onProgress?: (progress: number) => void) => Promise<UploadResult>, downloadFileContent: (fileId: string, password: string) => Promise<DownloadContentResult>, listFiles: () => Promise<ListResult>, deleteFile: (fileId: string) => Promise<StorageResult>, shareFile: (fileId: string, password: string, expiresInHours?: number) => Promise<ShareResult>;

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

import {
  encryptFile,
  encryptContent,
  decryptFile,
  downloadDecryptedFile,
  generateShareKey,
  formatFileSize,
  isBrowser,
  type EncryptionMetadata,
  type FileLike,
} from './crypto';

import { createStorageClient } from './client';
import { type StorageConfig } from './types';

import {
  type StoredFile,
  type StorageResult,
  type UploadResult,
  type DownloadResult,
  type ListResult,
  type ShareResult,
} from './types';

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
export function createStorageService(config?: StorageConfig) {
  const client = createStorageClient(config);
  const maxFileSize = config?.maxFileSize || 100 * 1024 * 1024; // 100MB default

  /**
   * Upload a file with client-side encryption
   * 
   * @note Browser-only: Uses File API and FormData
   * @note For Node.js, use uploadContent() instead
   * 
   * @param file - File to upload
   * @param password - User's password for encryption
   * @param onProgress - Optional progress callback (0-100)
   */
  async function uploadFile(
    file: File | FileLike,
    password: string,
    onProgress?: (progress: number) => void
  ): Promise<UploadResult> {
    try {
      // Validate inputs
      if (!file) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: 'No file provided',
            userMessage: 'Please select a file to upload.',
          },
        };
      }

      if (!password || password.length < 1) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: 'Password required',
            userMessage: 'Password is required for file encryption.',
          },
        };
      }

      if (file.size > maxFileSize) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: 'File too large',
            userMessage: `File size exceeds ${formatFileSize(maxFileSize)} limit. Current: ${formatFileSize(file.size)}`,
          },
        };
      }

      onProgress?.(10);

      // Step 1: Encrypt file client-side
      const encryptedData = await encryptFile(file, password);
      onProgress?.(50);

      // Step 2: Upload encrypted file to storage
      const uploadResult = await client.uploadToStorage(encryptedData);
      onProgress?.(90);

      if (!uploadResult.success) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: uploadResult.error || 'Upload failed',
            userMessage: 'Failed to upload encrypted file. Please try again.',
          },
        };
      }

      onProgress?.(100);

      return {
        success: true,
        fileId: uploadResult.fileId || uploadResult.cid,
        cid: uploadResult.cid,
        name: file.name,
        size: file.size,
        gateway: uploadResult.gateway,
      };
    } catch (error: any) {
      if (error.name === 'OperationError' || error.message.includes('encrypt')) {
        return {
          success: false,
          error: {
            type: 'encryption',
            message: error.message,
            userMessage: 'Encryption failed. Please check your password and try again.',
          },
        };
      }

      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * Upload raw content with client-side encryption
   * Works in both browser and Node.js environments.
   * 
   * @param content - ArrayBuffer to upload
   * @param metadata - File metadata (name, mimeType)
   * @param password - User's password for encryption
   * @param onProgress - Optional progress callback (0-100)
   */
  async function uploadContent(
    content: ArrayBuffer,
    metadata: { name: string; mimeType: string },
    password: string,
    onProgress?: (progress: number) => void
  ): Promise<UploadResult> {
    try {
      if (!content || content.byteLength === 0) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: 'No content provided',
            userMessage: 'No content to upload.',
          },
        };
      }

      if (!password || password.length < 1) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: 'Password required',
            userMessage: 'Password is required for encryption.',
          },
        };
      }

      if (content.byteLength > maxFileSize) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: 'Content too large',
            userMessage: `Content size exceeds ${formatFileSize(maxFileSize)} limit. Current: ${formatFileSize(content.byteLength)}`,
          },
        };
      }

      onProgress?.(10);

      // Encrypt content
      const encryptedData = await encryptContent(content, password, metadata);
      onProgress?.(50);

      // Upload
      const uploadResult = await client.uploadToStorage(encryptedData);
      onProgress?.(90);

      if (!uploadResult.success) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: uploadResult.error || 'Upload failed',
            userMessage: 'Failed to upload encrypted content. Please try again.',
          },
        };
      }

      onProgress?.(100);

      return {
        success: true,
        fileId: uploadResult.fileId || uploadResult.cid,
        cid: uploadResult.cid,
        name: metadata.name,
        size: content.byteLength,
        gateway: uploadResult.gateway,
      };
    } catch (error: any) {
      if (error.name === 'OperationError' || error.message.includes('encrypt')) {
        return {
          success: false,
          error: {
            type: 'encryption',
            message: error.message,
            userMessage: 'Encryption failed. Please check your password and try again.',
          },
        };
      }

      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * Download and decrypt a file by file ID, triggering browser download
   * 
   * @note Browser-only: Triggers file download dialog
   * @note For Node.js, use downloadFileContent() instead
   * 
   * @param fileId - File ID to download
   * @param password - User's password for decryption
   */
  async function downloadFile(
    fileId: string,
    password: string
  ): Promise<DownloadResult> {
    if (!isBrowser()) {
      return {
        success: false,
        error: {
          type: 'validation',
          message: 'Browser-only function',
          userMessage: 'downloadFile() only works in browser. Use downloadFileContent() for Node.js.',
        },
      };
    }

    try {
      // Step 1: Download encrypted file from storage
      const downloadResult = await client.downloadFromStorage(fileId);

      if (!downloadResult.success || !downloadResult.encryptedContent || !downloadResult.metadata) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: downloadResult.error || 'Download failed',
            userMessage: 'Failed to download file from storage. Please try again.',
          },
        };
      }

      // Step 2: Decrypt file client-side
      const decryptedData = await decryptFile(
        downloadResult.encryptedContent,
        downloadResult.metadata,
        password
      );

      // Step 3: Trigger download
      downloadDecryptedFile(decryptedData);

      return {
        success: true,
        name: decryptedData.name,
        size: decryptedData.size,
        mimeType: decryptedData.mimeType,
      };
    } catch (error: any) {
      if (error.message.includes('Decryption failed') || error.message.includes('incorrect password')) {
        return {
          success: false,
          error: {
            type: 'encryption',
            message: error.message,
            userMessage: 'Incorrect password. Please try again.',
          },
        };
      }

      if (error.message.includes('checksum')) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: error.message,
            userMessage: 'File integrity check failed. The file may be corrupted.',
          },
        };
      }

      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * Download and decrypt a file, returning the decrypted content
   * Works in both browser and Node.js environments.
   * 
   * @param fileId - File ID to download
   * @param password - User's password for decryption
   * @returns Decrypted content as ArrayBuffer
   */
  async function downloadFileContent(
    fileId: string,
    password: string
  ): Promise<DownloadContentResult> {
    try {
      const downloadResult = await client.downloadFromStorage(fileId);

      if (!downloadResult.success || !downloadResult.encryptedContent || !downloadResult.metadata) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: downloadResult.error || 'Download failed',
            userMessage: 'Failed to download file from storage. Please try again.',
          },
        };
      }

      const decryptedData = await decryptFile(
        downloadResult.encryptedContent,
        downloadResult.metadata,
        password
      );

      return {
        success: true,
        name: decryptedData.name,
        size: decryptedData.size,
        mimeType: decryptedData.mimeType,
        content: decryptedData.content,
      };
    } catch (error: any) {
      if (error.message.includes('Decryption failed') || error.message.includes('incorrect password')) {
        return {
          success: false,
          error: {
            type: 'encryption',
            message: error.message,
            userMessage: 'Incorrect password. Please try again.',
          },
        };
      }

      if (error.message.includes('checksum')) {
        return {
          success: false,
          error: {
            type: 'validation',
            message: error.message,
            userMessage: 'File integrity check failed. The file may be corrupted.',
          },
        };
      }

      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * Download and decrypt a file by CID (legacy method)
   * 
   * @note Browser-only
   * 
   * @param cid - IPFS Content Identifier
   * @param metadataCid - CID for encryption metadata
   * @param password - User's password for decryption
   */
  async function downloadFileByCid(
    cid: string,
    metadataCid: string,
    password: string
  ): Promise<DownloadResult> {
    if (!isBrowser()) {
      return {
        success: false,
        error: {
          type: 'validation',
          message: 'Browser-only function',
          userMessage: 'downloadFileByCid() only works in browser.',
        },
      };
    }

    try {
      const downloadResult = await client.downloadByCid(cid, metadataCid);

      if (!downloadResult.success || !downloadResult.encryptedContent || !downloadResult.metadata) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: downloadResult.error || 'Download failed',
            userMessage: 'Failed to download file from storage. Please try again.',
          },
        };
      }

      const decryptedData = await decryptFile(
        downloadResult.encryptedContent,
        downloadResult.metadata,
        password
      );

      downloadDecryptedFile(decryptedData);

      return {
        success: true,
        name: decryptedData.name,
        size: decryptedData.size,
        mimeType: decryptedData.mimeType,
      };
    } catch (error: any) {
      if (error.message.includes('Decryption failed') || error.message.includes('incorrect password')) {
        return {
          success: false,
          error: {
            type: 'encryption',
            message: error.message,
            userMessage: 'Incorrect password. Please try again.',
          },
        };
      }

      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * List all stored files for current user
   * Works in both browser and Node.js environments.
   */
  async function listFiles(): Promise<ListResult> {
    try {
      const result = await client.listStoredFiles();

      if (!result.success) {
        return {
          success: false,
          error: {
            type: 'network',
            message: result.error || 'Failed to list files',
            userMessage: 'Failed to retrieve file list. Please try again.',
          },
        };
      }

      const files = result.files || [];
      const totalSize = files.reduce((sum, f) => sum + f.originalSize, 0);

      return {
        success: true,
        files,
        totalSize,
        totalCount: files.length,
      };
    } catch (error: any) {
      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * Delete a stored file
   * Works in both browser and Node.js environments.
   */
  async function deleteFile(fileId: string): Promise<StorageResult> {
    try {
      const result = await client.deleteStoredFile(fileId);

      if (!result.success) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: result.error || 'Delete failed',
            userMessage: 'Failed to delete file. Please try again.',
          },
        };
      }

      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * Create a shareable link for a file
   * Works in both browser and Node.js environments.
   * 
   * @param fileId - File ID to share
   * @param password - User's password (to re-encrypt with share key)
   * @param expiresInHours - Optional expiration time
   */
  async function shareFile(
    fileId: string,
    password: string,
    expiresInHours?: number
  ): Promise<ShareResult> {
    try {
      // Generate a unique share key
      const shareKey = await generateShareKey();

      // Create share link on backend
      const result = await client.createShareLink(fileId, shareKey, expiresInHours);

      if (!result.success) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: result.error || 'Failed to create share link',
            userMessage: 'Failed to create share link. Please try again.',
          },
        };
      }

      return {
        success: true,
        shareUrl: result.shareUrl,
        shareKey,
        expiresAt: expiresInHours ? Date.now() + (expiresInHours * 60 * 60 * 1000) : undefined,
      };
    } catch (error: any) {
      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  /**
   * Download a shared file using share token and key
   * 
   * @note Browser-only: Triggers file download dialog
   * 
   * @param shareToken - Share token from URL
   * @param shareKey - Share key for decryption
   */
  async function downloadShared(
    shareToken: string,
    shareKey: string
  ): Promise<DownloadResult> {
    if (!isBrowser()) {
      return {
        success: false,
        error: {
          type: 'validation',
          message: 'Browser-only function',
          userMessage: 'downloadShared() only works in browser.',
        },
      };
    }

    try {
      const result = await client.downloadSharedFile(shareToken);

      if (!result.success || !result.encryptedContent || !result.metadata) {
        return {
          success: false,
          error: {
            type: 'storage',
            message: result.error || 'Download failed',
            userMessage: 'Failed to download shared file. Link may be expired.',
          },
        };
      }

      // Decrypt with share key
      const decryptedData = await decryptFile(
        result.encryptedContent,
        result.metadata,
        shareKey
      );

      downloadDecryptedFile(decryptedData);

      return {
        success: true,
        name: decryptedData.name,
        size: decryptedData.size,
        mimeType: decryptedData.mimeType,
      };
    } catch (error: any) {
      if (error.message.includes('Decryption failed')) {
        return {
          success: false,
          error: {
            type: 'encryption',
            message: error.message,
            userMessage: 'Invalid share key. Please check the link.',
          },
        };
      }

      return {
        success: false,
        error: {
          type: 'unknown',
          message: error.message || 'Unknown error',
          userMessage: 'An unexpected error occurred. Please try again.',
        },
      };
    }
  }

  return {
    // Browser-only functions
    uploadFile,
    downloadFile,
    downloadFileByCid,
    downloadShared,
    // Universal functions (browser + Node.js)
    uploadContent,
    downloadFileContent,
    listFiles,
    deleteFile,
    shareFile,
    // Re-export utilities
    formatFileSize,
    getIPFSGatewayUrl: client.getIPFSGatewayUrl,
  };
}

// Export a default service for convenience
export const defaultService = createStorageService();

// Re-export individual functions from default service
export const {
  // Browser-only
  uploadFile,
  downloadFile,
  downloadFileByCid,
  downloadShared,
  // Universal
  uploadContent,
  downloadFileContent,
  listFiles,
  deleteFile,
  shareFile,
} = defaultService;

/**
 * @zkterm/zkstorage - Storage Client
 * 
 * Handles communication with storage backend:
 * - Uploading encrypted files
 * - Downloading encrypted files
 * - Listing and managing files
 * - Creating share links
 */

import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  type EncryptedFileData,
  type EncryptionMetadata,
} from './crypto';

import {
  type StorageConfig,
  type StorageUploadResult,
  type StorageDownloadResult,
  type StorageListResult,
  type StoredFile,
  DEFAULT_CONFIG,
} from './types';

/**
 * Create a configured storage client
 * 
 * @param config - Configuration options
 * @returns Storage client instance
 */
export function createStorageClient(config: StorageConfig = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const fetchFn = cfg.fetchFn;
  
  /**
   * Upload encrypted file to storage backend
   */
  async function uploadToStorage(
    encryptedData: EncryptedFileData
  ): Promise<StorageUploadResult> {
    try {
      const formData = new FormData();
      
      // Convert encrypted content to blob
      const encryptedBlob = new Blob([encryptedData.encryptedContent], {
        type: 'application/octet-stream'
      });
      formData.append('file', encryptedBlob, 'encrypted.bin');
      
      // Add encryption metadata
      const metadata: EncryptionMetadata = {
        iv: encryptedData.iv,
        salt: encryptedData.salt,
        iterations: encryptedData.iterations,
        originalName: encryptedData.originalName,
        originalSize: encryptedData.originalSize,
        mimeType: encryptedData.mimeType,
        checksum: encryptedData.checksum,
        encryptedAt: Date.now(),
        version: '1.0',
      };
      formData.append('metadata', JSON.stringify(metadata));

      const response = await fetchFn(`${cfg.apiBaseUrl}/upload`, {
        method: 'POST',
        credentials: 'include',
        body: formData,
      });

      if (!response.ok) {
        const error = await response.json();
        return {
          success: false,
          error: error.message || 'Upload failed',
        };
      }

      const result = await response.json();
      return {
        success: true,
        cid: result.cid,
        metadataCid: result.metadataCid,
        fileId: result.fileId || result.id,
        gateway: result.gateway,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Network error during upload',
      };
    }
  }

  /**
   * Download encrypted file from storage by file ID
   */
  async function downloadFromStorage(
    fileId: string
  ): Promise<StorageDownloadResult> {
    try {
      // First get file metadata
      const metaResponse = await fetchFn(`${cfg.apiBaseUrl}/files/${fileId}`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!metaResponse.ok) {
        const error = await metaResponse.json();
        return {
          success: false,
          error: error.message || 'Failed to get file metadata',
        };
      }

      const metaResult = await metaResponse.json();
      const file = metaResult.file;

      // Then download the encrypted content
      const contentResponse = await fetchFn(`${cfg.apiBaseUrl}/files/${fileId}/content`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!contentResponse.ok) {
        const error = await contentResponse.json();
        return {
          success: false,
          error: error.message || 'Download failed',
        };
      }

      const contentResult = await contentResponse.json();
      
      // Build metadata object
      const metadata: EncryptionMetadata = {
        iv: file.iv || contentResult.metadata?.iv,
        salt: file.salt || contentResult.metadata?.salt,
        iterations: file.iterations || contentResult.metadata?.iterations || 200000,
        originalName: file.originalName,
        originalSize: file.originalSize,
        mimeType: file.mimeType,
        checksum: file.checksum,
        encryptedAt: file.encryptedAt || Date.now(),
        version: '1.0',
      };
      
      return {
        success: true,
        encryptedContent: base64ToArrayBuffer(contentResult.content),
        metadata,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Network error during download',
      };
    }
  }

  /**
   * Download encrypted file by CID (legacy method)
   */
  async function downloadByCid(
    cid: string,
    metadataCid: string
  ): Promise<StorageDownloadResult> {
    try {
      const response = await fetchFn(`${cfg.apiBaseUrl}/download/${cid}`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'X-Metadata-CID': metadataCid,
        },
      });

      if (!response.ok) {
        const error = await response.json();
        return {
          success: false,
          error: error.message || 'Download failed',
        };
      }

      const result = await response.json();
      
      return {
        success: true,
        encryptedContent: base64ToArrayBuffer(result.content),
        metadata: result.metadata,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Network error during download',
      };
    }
  }

  /**
   * List all stored files for the current user
   */
  async function listStoredFiles(): Promise<StorageListResult> {
    try {
      const response = await fetchFn(`${cfg.apiBaseUrl}/files`, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        const error = await response.json();
        return {
          success: false,
          error: error.message || 'Failed to list files',
        };
      }

      const result = await response.json();
      return {
        success: true,
        files: result.files,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Network error',
      };
    }
  }

  /**
   * Delete a stored file
   */
  async function deleteStoredFile(fileId: string): Promise<{ success: boolean; error?: string }> {
    try {
      const response = await fetchFn(`${cfg.apiBaseUrl}/files/${fileId}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (!response.ok) {
        const error = await response.json();
        return {
          success: false,
          error: error.message || 'Delete failed',
        };
      }

      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Network error',
      };
    }
  }

  /**
   * Create a shareable link for a file
   */
  async function createShareLink(
    fileId: string,
    shareKey: string,
    expiresIn?: number
  ): Promise<{ success: boolean; shareToken?: string; shareUrl?: string; error?: string }> {
    try {
      const response = await fetchFn(`${cfg.apiBaseUrl}/share`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fileId,
          shareKey,
          expiresIn,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        return {
          success: false,
          error: error.message || 'Failed to create share link',
        };
      }

      const result = await response.json();
      return {
        success: true,
        shareToken: result.shareToken,
        shareUrl: result.shareUrl,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Network error',
      };
    }
  }

  /**
   * Download a shared file using share token
   */
  async function downloadSharedFile(
    shareToken: string
  ): Promise<StorageDownloadResult & { shareKey?: string }> {
    try {
      const response = await fetchFn(`${cfg.apiBaseUrl}/shared/${shareToken}`, {
        method: 'GET',
      });

      if (!response.ok) {
        const error = await response.json();
        return {
          success: false,
          error: error.message || 'Failed to download shared file',
        };
      }

      const result = await response.json();
      
      return {
        success: true,
        encryptedContent: base64ToArrayBuffer(result.content),
        metadata: result.metadata,
        shareKey: result.shareKey,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Network error',
      };
    }
  }

  /**
   * Get IPFS gateway URL for a CID
   */
  function getIPFSGatewayUrl(cid: string): string {
    return cfg.ipfsGateway.replace('{cid}', cid);
  }

  /**
   * Get alternative IPFS gateway URLs
   */
  function getAlternativeGateways(cid: string): string[] {
    return [
      `https://nftstorage.link/ipfs/${cid}`,
      `https://cloudflare-ipfs.com/ipfs/${cid}`,
      `https://ipfs.io/ipfs/${cid}`,
      `https://gateway.pinata.cloud/ipfs/${cid}`,
    ];
  }

  return {
    uploadToStorage,
    downloadFromStorage,
    downloadByCid,
    listStoredFiles,
    deleteStoredFile,
    createShareLink,
    downloadSharedFile,
    getIPFSGatewayUrl,
    getAlternativeGateways,
  };
}

// Export a default client for convenience (uses default config)
export const defaultClient = createStorageClient();

// Re-export individual functions from default client for easier imports
export const {
  uploadToStorage,
  downloadFromStorage,
  downloadByCid,
  listStoredFiles,
  deleteStoredFile,
  createShareLink,
  downloadSharedFile,
  getIPFSGatewayUrl,
  getAlternativeGateways,
} = defaultClient;

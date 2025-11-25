"use strict";
/**
 * @zkterm/zkstorage - Type Definitions
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_CONFIG = void 0;
/**
 * Default storage configuration
 */
exports.DEFAULT_CONFIG = {
    apiBaseUrl: '/api/storage',
    ipfsGateway: 'https://nftstorage.link/ipfs/{cid}',
    maxFileSize: 100 * 1024 * 1024, // 100MB
    fetchFn: typeof fetch !== 'undefined' ? fetch : (() => { throw new Error('fetch not available'); }),
};

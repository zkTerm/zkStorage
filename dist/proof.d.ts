/**
 * @zkterm/zkstorage - Zero-Knowledge Proof Module
 *
 * Uses Groth16 zkSNARK to prove password knowledge without revealing the password.
 * This module provides cryptographic proof generation and verification for zkStorage.
 *
 * Flow:
 * 1. On upload: Generate commitment = Poseidon(SHA256(password), salt), create ZK proof
 * 2. Store commitment alongside encrypted file
 * 3. On download: Generate new ZK proof proving password knowledge
 * 4. Backend verifies proof against stored commitment
 *
 * Security Features:
 * - Full 256-bit SHA-256 password hashing (no truncation)
 * - Password split into two 128-bit field elements for BN254 compatibility
 * - Poseidon hash for efficient ZK-friendly commitment
 * - Groth16 proofs (~200 bytes, fast verification)
 *
 * Requirements:
 * - Circuit files must be hosted at configurable paths (WASM, zkey, verification key)
 * - snarkjs and circomlibjs are peer dependencies
 */
export interface ZKProof {
    proof: {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
        protocol: string;
        curve: string;
    };
    publicSignals: string[];
}
export interface ZKStorageProofResult {
    proof: ZKProof;
    commitment: string;
    salt: string;
}
export interface ZKProofConfig {
    wasmPath: string;
    zkeyPath: string;
    vkeyPath: string;
}
/**
 * Configure circuit file paths
 * Call this before using any proof functions if your circuit files are hosted elsewhere
 *
 * @example
 * configureCircuitPaths({
 *   wasmPath: '/my-circuits/password_proof.wasm',
 *   zkeyPath: '/my-circuits/password_proof_final.zkey',
 *   vkeyPath: '/my-circuits/verification_key.json',
 * });
 */
export declare function configureCircuitPaths(config: Partial<ZKProofConfig>): void;
/**
 * Get current circuit configuration
 */
export declare function getCircuitConfig(): ZKProofConfig;
/**
 * Reset circuit configuration to defaults
 */
export declare function resetCircuitConfig(): void;
/**
 * Generate random salt as field element (31 bytes to fit in BN254 field)
 */
export declare function generateSaltFieldElement(): bigint;
/**
 * Compute Poseidon hash commitment: Poseidon(password_low, password_high, salt)
 * This commitment is stored with the file and used for verification
 *
 * Note: Password is SHA-256 pre-hashed and split into two 128-bit field elements
 * to ensure ALL 256 bits contribute to the commitment (no truncation)
 *
 * @param password - The password to commit
 * @param saltBigInt - Salt as BigInt (use generateSaltFieldElement() to create)
 * @returns Commitment as BigInt
 */
export declare function computeCommitment(password: string, saltBigInt: bigint): Promise<bigint>;
/**
 * Generate ZK proof that proves knowledge of password without revealing it
 *
 * The proof demonstrates: "I know password P such that Poseidon(SHA256(P), salt) = commitment"
 *
 * @param password - The password to prove knowledge of
 * @param existingSalt - Optional existing salt (for download verification)
 * @param existingCommitment - Optional existing commitment (for download verification)
 * @param config - Optional circuit config override
 * @returns ZK proof, commitment, and salt
 *
 * @example
 * // Generate proof for new file upload
 * const result = await generateStorageProof('my-secure-password');
 * console.log('Commitment:', result.commitment);
 * console.log('Salt:', result.salt);
 *
 * // Verify password on download (proves you know the password)
 * const downloadProof = await generateStorageProof(
 *   'my-secure-password',
 *   storedSalt,
 *   storedCommitment
 * );
 */
export declare function generateStorageProof(password: string, existingSalt?: string, existingCommitment?: string, config?: Partial<ZKProofConfig>): Promise<ZKStorageProofResult>;
/**
 * Verify ZK proof locally (for testing/debugging)
 * In production, verification should happen on the backend
 *
 * @param proof - The ZK proof to verify
 * @param commitment - Expected commitment value
 * @param config - Optional circuit config override
 * @returns true if proof is valid
 */
export declare function verifyStorageProofLocal(proof: ZKProof, commitment: string, config?: Partial<ZKProofConfig>): Promise<boolean>;
/**
 * Verify ZK proof using verification key object directly
 * Useful for Node.js environments where you have the vkey loaded
 *
 * @param proof - The ZK proof to verify
 * @param commitment - Expected commitment value
 * @param vkey - Verification key object (JSON parsed)
 * @returns true if proof is valid
 */
export declare function verifyStorageProofWithKey(proof: ZKProof, commitment: string, vkey: any): Promise<boolean>;
/**
 * Format proof for API submission
 * Converts the proof result to a format suitable for sending to backend
 */
export declare function formatProofForAPI(result: ZKStorageProofResult): {
    proof: string;
    commitment: string;
    salt: string;
    publicSignals: string[];
};
/**
 * Parse proof from API format back to ZKProof object
 */
export declare function parseProofFromAPI(data: {
    proof: string;
    publicSignals: string[];
}): ZKProof;
/**
 * Check if ZK proof circuit files are available at configured paths
 */
export declare function checkCircuitFilesAvailable(config?: Partial<ZKProofConfig>): Promise<{
    available: boolean;
    missing: string[];
}>;
/**
 * Preload circuit files to improve first proof generation time
 * Call this early in your app initialization
 */
export declare function preloadCircuitFiles(config?: Partial<ZKProofConfig>): Promise<void>;

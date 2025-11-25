"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.configureCircuitPaths = configureCircuitPaths;
exports.getCircuitConfig = getCircuitConfig;
exports.resetCircuitConfig = resetCircuitConfig;
exports.generateSaltFieldElement = generateSaltFieldElement;
exports.computeCommitment = computeCommitment;
exports.generateStorageProof = generateStorageProof;
exports.verifyStorageProofLocal = verifyStorageProofLocal;
exports.verifyStorageProofWithKey = verifyStorageProofWithKey;
exports.formatProofForAPI = formatProofForAPI;
exports.parseProofFromAPI = parseProofFromAPI;
exports.checkCircuitFilesAvailable = checkCircuitFilesAvailable;
exports.preloadCircuitFiles = preloadCircuitFiles;
// @ts-ignore - snarkjs doesn't have complete types
const snarkjs = __importStar(require("snarkjs"));
// @ts-ignore - circomlibjs doesn't have complete types
const circomlibjs_1 = require("circomlibjs");
const DEFAULT_CIRCUIT_CONFIG = {
    wasmPath: '/circuits/password_proof.wasm',
    zkeyPath: '/circuits/password_proof_final.zkey',
    vkeyPath: '/circuits/verification_key.json',
};
let currentConfig = { ...DEFAULT_CIRCUIT_CONFIG };
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
function configureCircuitPaths(config) {
    currentConfig = { ...currentConfig, ...config };
}
/**
 * Get current circuit configuration
 */
function getCircuitConfig() {
    return { ...currentConfig };
}
/**
 * Reset circuit configuration to defaults
 */
function resetCircuitConfig() {
    currentConfig = { ...DEFAULT_CIRCUIT_CONFIG };
}
async function passwordToFieldElements(password) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const hashBytes = new Uint8Array(hashBuffer);
    let low = BigInt(0);
    for (let i = 0; i < 16; i++) {
        low = low * BigInt(256) + BigInt(hashBytes[i]);
    }
    let high = BigInt(0);
    for (let i = 16; i < 32; i++) {
        high = high * BigInt(256) + BigInt(hashBytes[i]);
    }
    return { low, high };
}
/**
 * Generate random salt as field element (31 bytes to fit in BN254 field)
 */
function generateSaltFieldElement() {
    const bytes = crypto.getRandomValues(new Uint8Array(31));
    let result = BigInt(0);
    for (let i = 0; i < bytes.length; i++) {
        result = result * BigInt(256) + BigInt(bytes[i]);
    }
    return result;
}
let poseidonInstance = null;
async function getPoseidon() {
    if (!poseidonInstance) {
        poseidonInstance = await (0, circomlibjs_1.buildPoseidon)();
    }
    return poseidonInstance;
}
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
async function computeCommitment(password, saltBigInt) {
    const poseidon = await getPoseidon();
    const { low, high } = await passwordToFieldElements(password);
    const hash = poseidon([low, high, saltBigInt]);
    return poseidon.F.toObject(hash);
}
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
async function generateStorageProof(password, existingSalt, existingCommitment, config) {
    const effectiveConfig = config
        ? { ...currentConfig, ...config }
        : currentConfig;
    try {
        const { low: passwordLow, high: passwordHigh } = await passwordToFieldElements(password);
        const saltBigInt = existingSalt
            ? BigInt(existingSalt)
            : generateSaltFieldElement();
        const commitment = await computeCommitment(password, saltBigInt);
        if (existingCommitment) {
            const expectedCommitment = BigInt(existingCommitment);
            if (commitment !== expectedCommitment) {
                throw new Error('Password verification failed - commitment mismatch');
            }
        }
        const input = {
            password_low: passwordLow.toString(),
            password_high: passwordHigh.toString(),
            salt: saltBigInt.toString(),
            commitment: commitment.toString(),
        };
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, effectiveConfig.wasmPath, effectiveConfig.zkeyPath);
        return {
            proof: {
                proof: {
                    pi_a: proof.pi_a,
                    pi_b: proof.pi_b,
                    pi_c: proof.pi_c,
                    protocol: proof.protocol,
                    curve: proof.curve,
                },
                publicSignals,
            },
            commitment: commitment.toString(),
            salt: saltBigInt.toString(),
        };
    }
    catch (error) {
        console.error('ZK proof generation failed:', error);
        throw new Error(`ZK proof generation failed: ${error.message}`);
    }
}
/**
 * Verify ZK proof locally (for testing/debugging)
 * In production, verification should happen on the backend
 *
 * @param proof - The ZK proof to verify
 * @param commitment - Expected commitment value
 * @param config - Optional circuit config override
 * @returns true if proof is valid
 */
async function verifyStorageProofLocal(proof, commitment, config) {
    const effectiveConfig = config
        ? { ...currentConfig, ...config }
        : currentConfig;
    try {
        const response = await fetch(effectiveConfig.vkeyPath);
        if (!response.ok) {
            throw new Error(`Failed to fetch verification key: ${response.status}`);
        }
        const vkey = await response.json();
        if (proof.publicSignals[0] !== commitment) {
            return false;
        }
        return await snarkjs.groth16.verify(vkey, proof.publicSignals, proof.proof);
    }
    catch (error) {
        console.error('Local proof verification failed:', error);
        return false;
    }
}
/**
 * Verify ZK proof using verification key object directly
 * Useful for Node.js environments where you have the vkey loaded
 *
 * @param proof - The ZK proof to verify
 * @param commitment - Expected commitment value
 * @param vkey - Verification key object (JSON parsed)
 * @returns true if proof is valid
 */
async function verifyStorageProofWithKey(proof, commitment, vkey) {
    try {
        if (proof.publicSignals[0] !== commitment) {
            return false;
        }
        return await snarkjs.groth16.verify(vkey, proof.publicSignals, proof.proof);
    }
    catch (error) {
        console.error('Proof verification failed:', error);
        return false;
    }
}
/**
 * Format proof for API submission
 * Converts the proof result to a format suitable for sending to backend
 */
function formatProofForAPI(result) {
    return {
        proof: JSON.stringify(result.proof.proof),
        commitment: result.commitment,
        salt: result.salt,
        publicSignals: result.proof.publicSignals,
    };
}
/**
 * Parse proof from API format back to ZKProof object
 */
function parseProofFromAPI(data) {
    const proofObj = typeof data.proof === 'string'
        ? JSON.parse(data.proof)
        : data.proof;
    return {
        proof: proofObj,
        publicSignals: data.publicSignals,
    };
}
/**
 * Check if ZK proof circuit files are available at configured paths
 */
async function checkCircuitFilesAvailable(config) {
    const effectiveConfig = config
        ? { ...currentConfig, ...config }
        : currentConfig;
    const missing = [];
    try {
        const [wasmResponse, zkeyResponse, vkeyResponse] = await Promise.all([
            fetch(effectiveConfig.wasmPath, { method: 'HEAD' }).catch(() => null),
            fetch(effectiveConfig.zkeyPath, { method: 'HEAD' }).catch(() => null),
            fetch(effectiveConfig.vkeyPath, { method: 'HEAD' }).catch(() => null),
        ]);
        if (!wasmResponse?.ok)
            missing.push('wasm');
        if (!zkeyResponse?.ok)
            missing.push('zkey');
        if (!vkeyResponse?.ok)
            missing.push('vkey');
        return {
            available: missing.length === 0,
            missing,
        };
    }
    catch {
        return {
            available: false,
            missing: ['wasm', 'zkey', 'vkey'],
        };
    }
}
/**
 * Preload circuit files to improve first proof generation time
 * Call this early in your app initialization
 */
async function preloadCircuitFiles(config) {
    const effectiveConfig = config
        ? { ...currentConfig, ...config }
        : currentConfig;
    await Promise.all([
        fetch(effectiveConfig.wasmPath).then(r => r.arrayBuffer()),
        fetch(effectiveConfig.zkeyPath).then(r => r.arrayBuffer()),
        getPoseidon(),
    ]);
}

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

// @ts-ignore - snarkjs doesn't have complete types
import * as snarkjs from 'snarkjs';
// @ts-ignore - circomlibjs doesn't have complete types
import { buildPoseidon } from 'circomlibjs';

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

const DEFAULT_CIRCUIT_CONFIG: ZKProofConfig = {
  wasmPath: '/circuits/password_proof.wasm',
  zkeyPath: '/circuits/password_proof_final.zkey',
  vkeyPath: '/circuits/verification_key.json',
};

let currentConfig: ZKProofConfig = { ...DEFAULT_CIRCUIT_CONFIG };

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
export function configureCircuitPaths(config: Partial<ZKProofConfig>): void {
  currentConfig = { ...currentConfig, ...config };
}

/**
 * Get current circuit configuration
 */
export function getCircuitConfig(): ZKProofConfig {
  return { ...currentConfig };
}

/**
 * Reset circuit configuration to defaults
 */
export function resetCircuitConfig(): void {
  currentConfig = { ...DEFAULT_CIRCUIT_CONFIG };
}

/**
 * Password field elements from SHA-256 pre-hash
 * Splits the full 256-bit SHA-256 digest into two 128-bit field elements
 * 
 * Security: The entire 256 bits of SHA-256(password) are committed:
 * - password_low: bytes 0-15 (128 bits) 
 * - password_high: bytes 16-31 (128 bits)
 * 
 * This prevents any truncation attacks - all bits contribute to the commitment.
 */
interface PasswordFieldElements {
  low: bigint;
  high: bigint;
}

async function passwordToFieldElements(password: string): Promise<PasswordFieldElements> {
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
export function generateSaltFieldElement(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  let result = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    result = result * BigInt(256) + BigInt(bytes[i]);
  }
  return result;
}

let poseidonInstance: any = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
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
export async function computeCommitment(
  password: string,
  saltBigInt: bigint
): Promise<bigint> {
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
export async function generateStorageProof(
  password: string,
  existingSalt?: string,
  existingCommitment?: string,
  config?: Partial<ZKProofConfig>
): Promise<ZKStorageProofResult> {
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
    
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      effectiveConfig.wasmPath,
      effectiveConfig.zkeyPath
    );
    
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
  } catch (error: any) {
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
export async function verifyStorageProofLocal(
  proof: ZKProof,
  commitment: string,
  config?: Partial<ZKProofConfig>
): Promise<boolean> {
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
    
    return await snarkjs.groth16.verify(
      vkey,
      proof.publicSignals,
      proof.proof
    );
  } catch (error) {
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
export async function verifyStorageProofWithKey(
  proof: ZKProof,
  commitment: string,
  vkey: any
): Promise<boolean> {
  try {
    if (proof.publicSignals[0] !== commitment) {
      return false;
    }
    
    return await snarkjs.groth16.verify(
      vkey,
      proof.publicSignals,
      proof.proof
    );
  } catch (error) {
    console.error('Proof verification failed:', error);
    return false;
  }
}

/**
 * Format proof for API submission
 * Converts the proof result to a format suitable for sending to backend
 */
export function formatProofForAPI(result: ZKStorageProofResult): {
  proof: string;
  commitment: string;
  salt: string;
  publicSignals: string[];
} {
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
export function parseProofFromAPI(data: {
  proof: string;
  publicSignals: string[];
}): ZKProof {
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
export async function checkCircuitFilesAvailable(
  config?: Partial<ZKProofConfig>
): Promise<{ available: boolean; missing: string[] }> {
  const effectiveConfig = config 
    ? { ...currentConfig, ...config }
    : currentConfig;
    
  const missing: string[] = [];
  
  try {
    const [wasmResponse, zkeyResponse, vkeyResponse] = await Promise.all([
      fetch(effectiveConfig.wasmPath, { method: 'HEAD' }).catch(() => null),
      fetch(effectiveConfig.zkeyPath, { method: 'HEAD' }).catch(() => null),
      fetch(effectiveConfig.vkeyPath, { method: 'HEAD' }).catch(() => null),
    ]);
    
    if (!wasmResponse?.ok) missing.push('wasm');
    if (!zkeyResponse?.ok) missing.push('zkey');
    if (!vkeyResponse?.ok) missing.push('vkey');
    
    return {
      available: missing.length === 0,
      missing,
    };
  } catch {
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
export async function preloadCircuitFiles(
  config?: Partial<ZKProofConfig>
): Promise<void> {
  const effectiveConfig = config 
    ? { ...currentConfig, ...config }
    : currentConfig;
    
  await Promise.all([
    fetch(effectiveConfig.wasmPath).then(r => r.arrayBuffer()),
    fetch(effectiveConfig.zkeyPath).then(r => r.arrayBuffer()),
    getPoseidon(),
  ]);
}

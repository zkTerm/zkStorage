/**
 * ZK Proof Example - @zkterm/zkstorage
 * 
 * Demonstrates zero-knowledge password proof generation and verification.
 * 
 * Prerequisites:
 * 1. Circuit files must be hosted at /circuits/ (or configured path)
 * 2. snarkjs and circomlibjs are installed as dependencies
 * 
 * Run: npx ts-node examples/zk-proof-example.ts
 */

import {
  generateStorageProof,
  verifyStorageProofLocal,
  computeCommitment,
  formatProofForAPI,
  configureCircuitPaths,
  checkCircuitFilesAvailable,
  preloadCircuitFiles,
  type ZKStorageProofResult,
} from '../src';

async function main() {
  console.log('=== @zkterm/zkstorage ZK Proof Example ===\n');

  // Configure circuit paths (if not at default /circuits/)
  configureCircuitPaths({
    wasmPath: '/circuits/password_proof.wasm',
    zkeyPath: '/circuits/password_proof_final.zkey',
    vkeyPath: '/circuits/verification_key.json',
  });

  // Check if circuit files are available
  console.log('1. Checking circuit files...');
  const { available, missing } = await checkCircuitFilesAvailable();
  if (!available) {
    console.error('Missing circuit files:', missing);
    console.log('\nPlease ensure circuit files are hosted at the configured paths.');
    console.log('Required files:');
    console.log('  - password_proof.wasm');
    console.log('  - password_proof_final.zkey');
    console.log('  - verification_key.json');
    return;
  }
  console.log('Circuit files available!\n');

  // Preload circuit files for faster proof generation
  console.log('2. Preloading circuit files...');
  await preloadCircuitFiles();
  console.log('Preloaded!\n');

  const password = 'MySecurePassword123!';

  // Generate proof on upload
  console.log('3. Generating ZK proof for password...');
  const startTime = Date.now();
  const result: ZKStorageProofResult = await generateStorageProof(password);
  const elapsed = Date.now() - startTime;
  
  console.log(`Proof generated in ${elapsed}ms`);
  console.log('Commitment:', result.commitment);
  console.log('Salt:', result.salt);
  console.log('Public signals:', result.proof.publicSignals);
  console.log();

  // Format for API
  console.log('4. Formatting proof for API submission...');
  const apiPayload = formatProofForAPI(result);
  console.log('API payload keys:', Object.keys(apiPayload));
  console.log('Proof size:', apiPayload.proof.length, 'bytes');
  console.log();

  // Verify proof locally
  console.log('5. Verifying proof locally...');
  const isValid = await verifyStorageProofLocal(result.proof, result.commitment);
  console.log('Proof valid:', isValid);
  console.log();

  // Simulate download verification (prove password knowledge)
  console.log('6. Simulating download verification...');
  console.log('   (Proving password knowledge without revealing it)');
  
  try {
    const downloadProof = await generateStorageProof(
      password,
      result.salt,       // Use stored salt
      result.commitment  // Use stored commitment
    );
    console.log('Password verified! New proof generated.');
    console.log('Commitment matches stored:', downloadProof.commitment === result.commitment);
  } catch (error: any) {
    console.error('Password verification failed:', error.message);
  }
  console.log();

  // Test wrong password
  console.log('7. Testing wrong password...');
  try {
    await generateStorageProof(
      'WrongPassword',
      result.salt,
      result.commitment
    );
    console.log('ERROR: Should have thrown!');
  } catch (error: any) {
    console.log('Correctly rejected wrong password:', error.message);
  }
  console.log();

  // Compute commitment directly
  console.log('8. Computing commitment directly...');
  const saltBigInt = BigInt(result.salt);
  const commitment = await computeCommitment(password, saltBigInt);
  console.log('Computed commitment:', commitment.toString());
  console.log('Matches original:', commitment.toString() === result.commitment);

  console.log('\n=== Example Complete ===');
}

main().catch(console.error);

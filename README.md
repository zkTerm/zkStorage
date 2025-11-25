# @zkterm/zkstorage

Privacy-first decentralized file storage with client-side AES-256-GCM encryption and zkSNARK password proofs. Files never leave your browser unencrypted - only the password holder can decrypt.

## Features

- **Client-Side Encryption**: AES-256-GCM encryption happens entirely in browser/Node.js
- **Zero-Knowledge Proofs**: Groth16 zkSNARK proofs verify password knowledge without revealing it
- **Password Protection**: PBKDF2 key derivation with 200,000 iterations
- **Unique Keys Per File**: Each file gets unique IV and salt for maximum security
- **File Integrity**: SHA-256 checksum validation on decrypt
- **Secure Sharing**: Re-encrypt files with share keys (without revealing password)
- **Browser & Node.js**: Core crypto works in both environments
- **IPFS Storage**: Files stored on IPFS via Pinata with real CIDs (bafyxxx format)

## Zero-Knowledge Password Proofs

zkStorage now includes **real zkSNARK proofs** (Groth16 + Poseidon hash) that prove password knowledge without revealing the password itself.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     ZK PROOF FLOW                                │
├─────────────────────────────────────────────────────────────────┤
│  UPLOAD:                                                         │
│  1. User enters password                                         │
│  2. Generate random salt (field element)                         │
│  3. Compute commitment = Poseidon(password, salt)                │
│  4. Generate Groth16 proof of knowledge                          │
│  5. Store commitment with file (not password!)                   │
├─────────────────────────────────────────────────────────────────┤
│  DOWNLOAD:                                                       │
│  1. User enters password                                         │
│  2. Retrieve salt from stored metadata                           │
│  3. Generate new Groth16 proof                                   │
│  4. Backend verifies proof against stored commitment             │
│  5. If valid, allow file access (password never transmitted)     │
└─────────────────────────────────────────────────────────────────┘
```

### Circuit Specification

- **Hash Function**: Poseidon (snark-friendly, 240 constraints)
- **Proof System**: Groth16 (most efficient, ~200 byte proofs)
- **Curve**: BN254 (ethereum-compatible)
- **Public Inputs**: 1 (commitment)
- **Private Inputs**: 2 (password, salt)

### Circuit Code (password_proof.circom)

```circom
pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template PasswordProof() {
    signal input password;
    signal input salt;
    signal input commitment;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== password;
    hasher.inputs[1] <== salt;
    
    commitment === hasher.out;
}

component main {public [commitment]} = PasswordProof();
```

### Circuit Files Setup

The ZK proof module requires circuit files to generate proofs. You need to host these files at accessible paths.

**Required Files:**
- `password_proof.wasm` - Compiled circuit (WASM)
- `password_proof_final.zkey` - Proving key
- `verification_key.json` - Verification key

**Option 1: Host in public folder (Browser)**
```bash
# Copy circuit files to your public folder
cp circuits/*.wasm public/circuits/
cp circuits/*.zkey public/circuits/
cp circuits/*.json public/circuits/
```

**Option 2: Configure custom paths**
```typescript
import { configureCircuitPaths } from '@zkterm/zkstorage';

configureCircuitPaths({
  wasmPath: '/my-circuits/password_proof.wasm',
  zkeyPath: '/my-circuits/password_proof_final.zkey',
  vkeyPath: '/my-circuits/verification_key.json',
});
```

**Check circuit availability:**
```typescript
import { checkCircuitFilesAvailable } from '@zkterm/zkstorage';

const { available, missing } = await checkCircuitFilesAvailable();
if (!available) {
  console.log('Missing circuit files:', missing);
}
```

### ZK Proof API

```typescript
import { 
  generateStorageProof, 
  verifyStorageProofLocal,
  formatProofForAPI,
  computeCommitment,
} from '@zkterm/zkstorage';

// Generate proof on upload
const result = await generateStorageProof(password);
console.log('Commitment:', result.commitment);
console.log('Salt:', result.salt);
console.log('Proof:', result.proof);

// Verify proof locally (optional - backend does verification)
const isValid = await verifyStorageProofLocal(result.proof, result.commitment);
console.log('Valid:', isValid);

// Format proof for API submission
const apiPayload = formatProofForAPI(result);
await fetch('/api/storage/upload', {
  method: 'POST',
  body: JSON.stringify(apiPayload),
});

// Verify password on download (proves knowledge without revealing password)
const downloadProof = await generateStorageProof(
  password,
  storedSalt,        // Salt from upload
  storedCommitment   // Commitment from upload
);
// If password is wrong, this throws "commitment mismatch" error
```

### Preloading Circuit Files

For better UX, preload circuit files early in your app:

```typescript
import { preloadCircuitFiles } from '@zkterm/zkstorage';

// Call on app initialization
await preloadCircuitFiles();
// Now generateStorageProof() will be faster
```

### Security Properties

1. **Zero-Knowledge**: Verifier learns nothing about password except that prover knows it
2. **Soundness**: Cannot forge valid proof without knowing the password
3. **Non-Interactivity**: Single proof, no back-and-forth required
4. **Succinct**: Proofs are ~200 bytes regardless of password complexity
5. **Full Password Commitment**: Password is SHA-256 pre-hashed and split into two 128-bit field elements, ensuring ALL 256 bits contribute to the commitment:
   - **Before fix**: Direct encoding truncated at 31 bytes, allowing trivial prefix collisions
   - **After fix**: SHA-256(password) split into password_low (bytes 0-15) + password_high (bytes 16-31)
   - **Commitment**: `Poseidon(password_low, password_high, salt)` - all 256 bits enforced
   - **Security level**: Full 2^128 collision resistance - no truncation, all bits contribute
   - **Circuit**: 261 constraints (Poseidon with 3 inputs)

## Production Backend

zkStorage uses **Pinata** for decentralized IPFS storage:

- **Real IPFS CIDs**: Files return genuine Content Identifiers (`bafybeig...`)
- **Gateway**: Files served from `https://gateway.pinata.cloud/ipfs/{cid}`
- **Retry Logic**: 3 attempts with linear backoff for all IPFS operations
- **Timeout Handling**: 30s for downloads, 60s for uploads
- **Metadata Fallback**: Complete encryption metadata stored in database when IPFS gateway fails

### Architecture Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (Browser)                          │
├─────────────────────────────────────────────────────────────────┤
│  1. User selects file + enters password                          │
│  2. PBKDF2 derives encryption key (200k iterations)              │
│  3. AES-256-GCM encrypts file with unique IV/salt                │
│  4. SHA-256 checksum generated                                   │
│  5. Encrypted blob sent to backend                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SERVER (Backend)                          │
├─────────────────────────────────────────────────────────────────┤
│  1. Receives encrypted blob (server never sees plaintext)        │
│  2. Uploads to Pinata API                                        │
│  3. Returns real IPFS CID (bafyxxx...)                           │
│  4. Stores metadata in PostgreSQL (iv, salt, checksum)           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        IPFS (Pinata)                             │
├─────────────────────────────────────────────────────────────────┤
│  • Encrypted files stored permanently on IPFS                    │
│  • Accessible via multiple gateways                              │
│  • Content-addressed (CID = hash of encrypted content)           │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
npm install @zkterm/zkstorage
```

## Environment Support

| Function | Browser | Node.js 18+ |
|----------|---------|-------------|
| `encryptContent()` | Yes | Yes |
| `decryptFile()` | Yes | Yes |
| `encryptFile()` | Yes | Yes (with `createFileLike()`) |
| `createFileLike()` | N/A | Yes |
| `uploadFile()` | Yes | No (use backend storage API) |
| `downloadFile()` | Yes | No (use `downloadFileContent()`) |
| `downloadFileContent()` | Yes | Yes |
| `listFiles()` | Yes | Yes |
| `deleteFile()` | Yes | Yes |
| `shareFile()` | Yes | Yes |
| `generateStorageProof()` | Yes | Yes (requires circuit files) |
| `verifyStorageProofLocal()` | Yes | Yes (requires verification key) |
| `verifyStorageProofWithKey()` | Yes | Yes |
| `computeCommitment()` | Yes | Yes |

## Quick Start

### Browser Usage

```typescript
import { uploadFile, downloadFile, listFiles } from '@zkterm/zkstorage';

// Upload and encrypt a file
const fileInput = document.querySelector('input[type="file"]');
const file = fileInput.files[0];
const password = 'MySecurePassword123!';

const result = await uploadFile(file, password);
console.log('Uploaded:', result.fileId);

// Download and decrypt
await downloadFile(result.fileId, password);

// List all files
const { files } = await listFiles();
console.log('Files:', files);
```

### Node.js Usage

```typescript
import {
  encryptContent,
  encryptFile,
  decryptFile,
  createFileLike,
  formatFileSize
} from '@zkterm/zkstorage';
import { readFileSync, writeFileSync } from 'fs';

const password = 'MySecurePassword123!';

// Method 1: Using encryptContent (direct ArrayBuffer)
const buffer = readFileSync('./myfile.pdf');
const encrypted = await encryptContent(
  buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength),
  password,
  { name: 'myfile.pdf', mimeType: 'application/pdf' }
);
console.log('Encrypted size:', formatFileSize(encrypted.encryptedContent.byteLength));

// Method 2: Using createFileLike + encryptFile
const fileBuffer = readFileSync('./secret.txt');
const fileLike = createFileLike(fileBuffer, 'secret.txt', 'text/plain');
const encrypted2 = await encryptFile(fileLike, password);

// Decrypt
const metadata = {
  iv: encrypted.iv,
  salt: encrypted.salt,
  iterations: encrypted.iterations,
  originalName: encrypted.originalName,
  originalSize: encrypted.originalSize,
  mimeType: encrypted.mimeType,
  checksum: encrypted.checksum,
  encryptedAt: Date.now(),
  version: '1.0',
};
const decrypted = await decryptFile(encrypted.encryptedContent, metadata, password);
writeFileSync('./decrypted.pdf', Buffer.from(decrypted.content));
```

## API Documentation

### High-Level Service Functions

These functions handle encryption + storage in one step.

#### `uploadFile(file, password, onProgress?)` [Browser-only]

Upload and encrypt a file using the browser File API.

**Parameters:**
- `file: File | FileLike` - File object to upload
- `password: string` - Password for encryption
- `onProgress?: (progress: number) => void` - Optional progress callback (0-100)

**Returns:** `Promise<UploadResult>`

#### `uploadContent(content, metadata, password, onProgress?)` [Universal]

Upload and encrypt raw content (works in Node.js).

**Parameters:**
- `content: ArrayBuffer` - Content to upload
- `metadata: { name: string; mimeType: string }` - File metadata
- `password: string` - Password for encryption

**Returns:** `Promise<UploadResult>`

#### `downloadFile(fileId, password)` [Browser-only]

Download, decrypt, and trigger browser download dialog.

#### `downloadFileContent(fileId, password)` [Universal]

Download and decrypt, returning the decrypted content as ArrayBuffer.

**Returns:** `Promise<DownloadContentResult>` with `content: ArrayBuffer`

#### `listFiles()` [Universal]

List all stored files for current user.

#### `deleteFile(fileId)` [Universal]

Delete a stored file.

#### `shareFile(fileId, password, expiresInHours?)` [Universal]

Create a shareable link for a file.

### Core Crypto Functions

#### `encryptContent(content, password, metadata)` [Universal]

Encrypt raw content (ArrayBuffer).

```typescript
const encrypted = await encryptContent(
  arrayBuffer,
  'password',
  { name: 'file.txt', mimeType: 'text/plain' }
);
```

#### `encryptFile(file, password)` [Universal with FileLike]

Encrypt a File or FileLike object.

#### `decryptFile(encryptedContent, metadata, password)` [Universal]

Decrypt content.

**Throws:** Error if password is incorrect or file is corrupted

#### `createFileLike(content, name, mimeType)` [Node.js helper]

Create a FileLike object from Buffer/ArrayBuffer for Node.js compatibility.

```typescript
import { readFileSync } from 'fs';
const buffer = readFileSync('./file.pdf');
const file = createFileLike(buffer, 'file.pdf', 'application/pdf');
const encrypted = await encryptFile(file, 'password');
```

### Utility Functions

#### `formatFileSize(bytes)`

```typescript
formatFileSize(1024);      // "1 KB"
formatFileSize(1048576);   // "1 MB"
```

#### `generateShareKey()`

Generate a random share key for file sharing.

#### `isBrowser()` / `isNode()`

Environment detection helpers.

## Configuration

Create a custom storage client with configuration:

```typescript
import { createStorageService } from '@zkterm/zkstorage';

const storage = createStorageService({
  apiBaseUrl: 'https://api.myapp.com/storage',
  ipfsGateway: 'https://gateway.pinata.cloud/ipfs/{cid}', // Default gateway
  maxFileSize: 50 * 1024 * 1024, // 50MB
});

const result = await storage.uploadFile(file, password);
console.log('IPFS CID:', result.cid); // bafybeig...
```

### Default Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `apiBaseUrl` | `/api/storage` | Backend API endpoint |
| `ipfsGateway` | `https://gateway.pinata.cloud/ipfs/{cid}` | IPFS gateway URL template |
| `maxFileSize` | 100MB | Maximum file size limit |

### Alternative IPFS Gateways

If the primary gateway is slow, the client provides fallback options:

```typescript
import { getAlternativeGateways } from '@zkterm/zkstorage';

const cid = 'bafybeig...';
const gateways = getAlternativeGateways(cid);
// [
//   'https://gateway.pinata.cloud/ipfs/bafybeig...',
//   'https://cloudflare-ipfs.com/ipfs/bafybeig...',
//   'https://ipfs.io/ipfs/bafybeig...',
//   'https://dweb.link/ipfs/bafybeig...',
// ]
```

## Examples

### Complete Upload/Download Flow (Browser)

```typescript
import { uploadFile, downloadFile, formatFileSize } from '@zkterm/zkstorage';

async function handleFileUpload(file: File, password: string) {
  const result = await uploadFile(file, password, (progress) => {
    console.log(`Progress: ${progress}%`);
  });

  if (!result.success) {
    console.error('Upload failed:', result.error?.userMessage);
    return;
  }

  console.log('File ID:', result.fileId);
  console.log('IPFS CID:', result.cid);        // bafybeig...
  console.log('Gateway:', result.gateway);      // https://gateway.pinata.cloud/ipfs/bafybeig...
  console.log('Size:', formatFileSize(result.size!));
  
  // Later, download the file
  await downloadFile(result.fileId!, password);
}
```

### Encrypt/Decrypt in Node.js

```typescript
import {
  encryptContent,
  decryptFile,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from '@zkterm/zkstorage';

// Encrypt
const content = Buffer.from('Secret data');
const encrypted = await encryptContent(
  content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength),
  'password',
  { name: 'secret.txt', mimeType: 'text/plain' }
);

// Serialize for storage
const serialized = {
  content: arrayBufferToBase64(encrypted.encryptedContent),
  metadata: {
    iv: encrypted.iv,
    salt: encrypted.salt,
    iterations: encrypted.iterations,
    originalName: encrypted.originalName,
    originalSize: encrypted.originalSize,
    mimeType: encrypted.mimeType,
    checksum: encrypted.checksum,
    encryptedAt: Date.now(),
    version: '1.0',
  },
};

// Decrypt
const decrypted = await decryptFile(
  base64ToArrayBuffer(serialized.content),
  serialized.metadata,
  'password'
);
console.log('Decrypted:', Buffer.from(decrypted.content).toString());
```

### Custom Backend Integration

```typescript
import { encryptFile, decryptFile, createFileLike } from '@zkterm/zkstorage';

// Browser: encrypt and send to your backend
async function uploadToMyBackend(file: File, password: string) {
  const encrypted = await encryptFile(file, password);
  
  await fetch('/my-api/upload', {
    method: 'POST',
    body: encrypted.encryptedContent,
    headers: {
      'X-Metadata': JSON.stringify({
        iv: encrypted.iv,
        salt: encrypted.salt,
        iterations: encrypted.iterations,
        originalName: encrypted.originalName,
        originalSize: encrypted.originalSize,
        mimeType: encrypted.mimeType,
        checksum: encrypted.checksum,
      }),
    },
  });
}
```

## Security Model

1. **Client-Side Encryption**: All encryption happens in browser/Node.js before upload
2. **No Server Access**: Server never sees plaintext files or passwords
3. **Strong Key Derivation**: PBKDF2 with 200,000 iterations + 32-byte salt
4. **Unique Keys**: Each file gets unique IV (12 bytes) and salt (32 bytes)
5. **Integrity Verification**: SHA-256 checksum validated on decrypt
6. **Memory Safety**: Use ArrayBuffer (can be zeroed) for sensitive data
7. **IPFS Immutability**: Content-addressed storage ensures files cannot be tampered with
8. **Decentralized Storage**: Files stored across IPFS network, not single server

### What the Server Stores

The backend stores **only encrypted data** and **encryption metadata**:

| Field | Description | Purpose |
|-------|-------------|---------|
| `cid` | IPFS Content Identifier | Locate encrypted file on IPFS |
| `iv` | Initialization Vector (base64) | Required for AES-GCM decryption |
| `salt` | Key derivation salt (base64) | Required for PBKDF2 key derivation |
| `iterations` | PBKDF2 iteration count | Always 200,000 |
| `checksum` | SHA-256 hash of original file | Verify integrity after decrypt |
| `originalName` | Filename | Display purposes |
| `originalSize` | File size in bytes | Display purposes |
| `mimeType` | MIME type | Set correct Content-Type on download |

**The server cannot decrypt your files** - it lacks your password.

## Requirements

- **Browser**: Modern browser with Web Crypto API support
- **Node.js**: Version 18+ (for native Web Crypto API)

## License

MIT

## Author

zkTerm

## Links

- [zkTerm](https://zkterm.io)
- [GitHub](https://github.com/zkterm/zkstorage)
- [NPM](https://www.npmjs.com/package/@zkterm/zkstorage)

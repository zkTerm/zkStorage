# @zkterm/zkstorage

Privacy-first decentralized file storage with client-side AES-256-GCM encryption. Files never leave your browser unencrypted - only the password holder can decrypt.

## Features

- **Client-Side Encryption**: AES-256-GCM encryption happens entirely in browser/Node.js
- **Password Protection**: PBKDF2 key derivation with 200,000 iterations
- **Unique Keys Per File**: Each file gets unique IV and salt for maximum security
- **File Integrity**: SHA-256 checksum validation on decrypt
- **Secure Sharing**: Re-encrypt files with share keys (without revealing password)
- **Browser & Node.js**: Core crypto works in both environments

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
  ipfsGateway: 'https://gateway.pinata.cloud/ipfs/{cid}',
  maxFileSize: 50 * 1024 * 1024, // 50MB
});

const result = await storage.uploadFile(file, password);
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

  console.log('Uploaded:', result.fileId);
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

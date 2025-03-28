# PCR Verification System

This document describes the PCR (Platform Configuration Register) verification system used to validate Nitro Enclave measurements.

## Overview

The system uses an append-only history of signed PCR measurements that allows the frontend to verify enclave measurements even when they're not in the default list. This provides:

1. **Transparency**: Full history of all deployed enclave measurements
2. **Security**: Each PCR measurement is cryptographically signed
3. **Auditability**: Changes to PCR values over time are tracked
4. **Flexibility**: New PCR values can be added without requiring frontend updates

## Backend Commands

The following commands are available in the justfile:

### Generate Keys

```bash
just generate-pcr-keys
```

This generates an ECDSA key pair (using the P-384 curve) for signing PCR measurements and outputs them to the console:
- Private key in PEM format
- Public key in PEM format
- Private key as base64-encoded string (for setting environment variable)
- Public key in PEM format as base64-encoded string (for verification)
- Public key in DER format as base64-encoded string (for Web Crypto API)

It also outputs ready-to-use commands for:
- Setting the SIGNING_PRIVATE_KEY and SIGNING_PUBLIC_KEY environment variables
- Verifying PCR history signatures

No files are created on disk - all keys are generated in memory and output to the console.

### Sign and Append PCR Measurements

```bash
# First set the environment variable with the base64-encoded private key
export SIGNING_PRIVATE_KEY='your-base64-encoded-private-key'

# Then run one of these commands
just update-pcr-dev     # For development PCRs
just update-pcr-prod    # For production PCRs
```

These commands:
1. Copy the latest PCR measurements from the build
2. Sign the measurements with your private key (from SIGNING_PRIVATE_KEY environment variable)
3. Append the signed measurements to the history file (if they don't already exist)

Duplicate PCR0 values are automatically detected and skipped to prevent redundancy.

### Verify PCR History

```bash
# First set the environment variable with the base64-encoded public key
export SIGNING_PUBLIC_KEY='your-base64-encoded-public-key'

# Then run one of these commands
just verify-pcr-history dev     # For development PCRs
just verify-pcr-history prod    # For production PCRs
```

This verifies all signatures in a PCR history file against the public key in the SIGNING_PUBLIC_KEY environment variable.

## Deployment Workflow

1. Generate keys:
   ```bash
   just generate-pcr-keys
   ```

2. Set the environment variables for the private and public keys:
   ```bash
   export SIGNING_PRIVATE_KEY='base64-encoded-private-key-from-previous-step'
   export SIGNING_PUBLIC_KEY='base64-encoded-public-key-from-previous-step'
   ```

3. Build and update PCR values:
   ```bash
   just update-pcr-dev
   ```

4. Commit and push `pcrDevHistory.json` to your repository:
   ```bash
   git add pcrDevHistory.json
   git commit -m "Update PCR history with latest measurements"
   git push
   ```

5. Deploy as usual:
   ```bash
   just deploy-dev-nix
   ```

## Frontend/SDK Integration

These are the steps needed to implement PCR history verification in the SDK:

1. Store the public key in your frontend code:

```typescript
// Base64-encoded DER public key for verifying PCR signatures
const PCR_VERIFICATION_PUBLIC_KEY_B64 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsT4fLLWwA2IyUQbRjhsjz46Ts14mxVzvu8eC68rM7r9b3tZ1yYX311WaQcDOhNbT5vCYivkqA0EXN3aDFSmXHyFzKKxqyOEGBgnRxSBpMQNrc2yumBMDvseiEdCSpQwR";
```

2. Add a helper function to fetch PCR history:

```typescript
async function getPcrHistoryList(env: 'dev' | 'prod'): Promise<Array<PcrEntry>> {
  const url = env === 'dev'
    ? "https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/pcrDevHistory.json"
    : "https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/pcrProdHistory.json";
  
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Couldn't fetch PCR list: ${resp.status}`);
  return resp.json();
}

// Define the PCR entry interface
interface PcrEntry {
  HashAlgorithm: string;
  PCR0: string;
  PCR1: string;
  PCR2: string;
  signature: string;
  timestamp: number;
}
```

3. Add a function to verify PCR signatures:

```typescript
async function verifyPcrSignature(
  entry: PcrEntry,
  publicKey: CryptoKey
): Promise<boolean> {
  const encoder = new TextEncoder();
  
  // Create the same message format that was signed on the backend
  // Note: To match our signature implementation, we need to exclude the signature field
  const dataToSign = {
    HashAlgorithm: entry.HashAlgorithm,
    PCR0: entry.PCR0,
    PCR1: entry.PCR1,
    PCR2: entry.PCR2,
    timestamp: entry.timestamp
  };
  
  // Convert to JSON string - must match the exact format used when signing
  const message = encoder.encode(JSON.stringify(dataToSign));
  
  // Decode the base64 signature
  const signatureBuf = decodeBase64(entry.signature);
  
  // Verify using Web Crypto API
  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-384' } },
    publicKey,
    signatureBuf,
    message
  );
}

// Function to decode base64 to ArrayBuffer
function decodeBase64(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}
```

4. Add a function to import the public key:

```typescript
async function loadPublicKey(): Promise<CryptoKey> {
  // Use the base64 public key from step 1
  const publicKeyB64 = PCR_VERIFICATION_PUBLIC_KEY_B64;
  
  // Decode the base64 key
  const binaryDer = decodeBase64(publicKeyB64);
  
  // Import the key
  return await crypto.subtle.importKey(
    'spki', // SubjectPublicKeyInfo format
    binaryDer,
    {
      name: 'ECDSA',
      namedCurve: 'P-384' // Must match the curve used to generate the key
    },
    true, // extractable
    ['verify'] // only need verification
  );
}
```

5. Extend your existing PCR validation function:

```typescript
async function validatePcr(pcr: { PCR0: string, PCR1: string, PCR2: string }): Promise<boolean> {
  // First try local validation with hardcoded values
  if (isKnownPcr(pcr)) {
    return true;
  }
  
  // If local validation fails, try the PCR history
  try {
    const env = isDev() ? 'dev' : 'prod';
    const history = await getPcrHistoryList(env);
    const publicKey = await loadPublicKey();
    
    for (const entry of history) {
      // Check if PCRs match
      if (entry.PCR0 === pcr.PCR0 && 
          entry.PCR1 === pcr.PCR1 && 
          entry.PCR2 === pcr.PCR2) {
        // Verify signature
        const isValid = await verifyPcrSignature(entry, publicKey);
        if (isValid) {
          return true;
        }
      }
    }
  } catch (error) {
    console.error("Error validating PCR against history:", error);
  }
  
  return false;
}
```

## Security Considerations

1. Keep your private key secure and offline when possible
2. Only the public key should be accessible to the frontend
3. The history files are append-only; never remove entries
4. Always verify signatures before trusting PCR values
5. Duplicate PCR0 values are automatically prevented on the backend

## GitHub Hosting Considerations

The PCR history files are hosted on GitHub at these URLs:
- Dev: `https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/pcrDevHistory.json`
- Prod: `https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/pcrProdHistory.json`

Keep in mind:

1. **Rate Limiting**: GitHub applies rate limits of 60 requests per hour per IP address for raw content. This is usually sufficient for most applications, as the limit applies per user, not globally.

2. **Caching**: GitHub's CDN may cache content for a short period. After pushing updates to the history files, there may be a delay (typically minutes) before the changes are available at the raw URL.

3. **Error Handling**: Your frontend should implement proper error handling if GitHub is temporarily unavailable or if rate limits are exceeded. Consider implementing local caching of the history file to reduce the number of requests.

## Important Implementation Details

- Signatures are created using ECDSA with the P-384 curve and SHA-384 hash
- The signed data is the JSON string of the PCR entry (without the signature field)
- The signature in the history file is base64-encoded
- The frontend must decode this base64 signature before verification
- We use the Web Crypto API for verification with the importKey() and verify() methods

## Testing

During development, you can verify that signatures in a PCR history file are valid by running:

```bash
export SIGNING_PUBLIC_KEY='your-base64-encoded-public-key'
just verify-pcr-history dev
```

This will check all signatures in the history file and report any invalid entries.
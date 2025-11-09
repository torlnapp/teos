# Torln Encrypted Object Specification (TEOS)

TEOS defines a portable envelope for sharing encrypted application objects inside Torln. This package exposes helpers to build, sign, serialize, and verify TEOS envelopes with either pre-shared keys (PSK) or MLS-based sessions.

## Installation

```bash
# Bun
bun add @torlnapp/teos
```

> The library relies on the Web Crypto API (`globalThis.crypto`). In Node.js 18+ the API is available by default; in older runtimes you must polyfill it.

## Core Concepts

- **AAD (Additional Authenticated Data)** captures routing context (group, channel, epoch, sender, sequence, timestamp, object id). AAD values are never encrypted but are authenticated as part of the signature.
- **BaseTEOS** is the canonical payload with version metadata, AES-GCM ciphertext, nonce, and tag.
- **Envelope** adds authentication metadata. `PSKEnvelope` carries a `pskId` (and optional expiry/generation). `MLSEnvelope` references the MLS ciphersuite.
- **Mode** indicates whether the envelope is `psk` or `mls`; consumers must only interpret envelopes they expect.

## Quick Start

```ts
import {
  createPskTEOS,
  extractTEOS,
  type AAD,
} from '@torlnapp/teos';
import { encode, decode } from '@msgpack/msgpack';

const aad: AAD = {
  groupId: 'group-123',
  channelId: 'channel-1',
  epochId: 42,
  senderClientId: 'client-7',
  messageSequence: 3,
  timestamp: Date.now(),
  objectId: crypto.randomUUID(),
};

const aesKey = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  true,
  ['encrypt', 'decrypt'],
);
const senderKeyPair = await crypto.subtle.generateKey('Ed25519', true, [
  'sign',
  'verify',
]) as CryptoKeyPair;

const plaintext = { message: 'hello world' };
const payload = new Uint8Array(encode(plaintext)).buffer;

const teos = await createPskTEOS(aad, aesKey, senderKeyPair, payload);
// distribute `teos` and the sender public key to recipients

const recovered = await extractTEOS<typeof plaintext>(
  teos,
  aesKey,
  senderKeyPair.publicKey,
);
console.log(recovered.message); // "hello world"
```

### MLS Flow

Use `createMlsTEOS` instead of `createPskTEOS`. The function produces an `MLSEnvelope` with suite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`. Signature verification and decryption through `extractTEOS` are identical.

## API Reference

| Function | Description |
| --- | --- |
| `createPskTEOS(aad, aesKey, senderKeyPair, data)` | Encrypts `data` with AES-GCM and signs the canonical payload with Ed25519. Returns a PSK TEOS envelope. |
| `createMlsTEOS(aad, aesKey, senderKeyPair, data)` | Same as PSK but wraps the MLS ciphersuite metadata. |
| `extractTEOS(payload, aesKey, publicKey)` | Verifies the signature, decrypts the ciphertext, and decodes the plaintext buffer. Accepts a TEOS object or serialized ArrayBuffer. |
| `generateBaseTEOSHash(teos)` | Canonicalizes the base payload and returns the SHA-256 digest that is signed inside the envelope. |
| `generateNonce()` | Produces a 12-byte nonce suitable for AES-GCM. |
| `processCiphertext(payload)` | Splits an AES-GCM result buffer into ciphertext and 16-byte authentication tag. |
| `generateSignature(key, data)` / `verifySignature(key, data, sig)` | Thin Ed25519 helpers the high-level APIs rely on. |
| `serializeTEOS(teos)` / `deserializeTEOS(buffer)` | Encode/decode TEOS envelopes via MessagePack for transport. |
| `verifyTEOS(teos)` | Validates an envelope’s signature using the embedded sender public key. |

## Data Shapes

```ts
type TEOS = PSK_TEOS | MLS_TEOS;

interface BaseTEOS {
  type: 'torln.teos.v1';
  version: string;          // comes from package.json
  algorithm: 'AES-GCM';
  aad: AAD;
  nonce: Uint8Array;        // 12 bytes
  tag: Uint8Array;          // 16 bytes
  ciphertext: Uint8Array;   // encrypted payload
}
```

Both envelope flavors share:

- `envelope.auth.publicKey`: exported Ed25519 public key (JWK) for recipients to import.
- `envelope.auth.signature`: signature over the canonicalized `BaseTEOS`.

PSK-specific fields: `pskId`, optional `expiresAt`, optional `pskGeneration`. MLS-specific fields: ciphersuite `suite`.

## Usage Notes

- **Payload encoding:** `create*TEOS` accepts an `ArrayBuffer`. Use MessagePack (as in the tests) or JSON encoded via `TextEncoder`.
- **Key management:** Recipients must possess the correct AES key and the sender public key (PSK) or current MLS group public key.
- **Replay protection:** Include monotonically increasing `messageSequence` or timestamps in AAD and reject duplicates at the application layer.
- **Tamper detection:** `extractTEOS` throws when signature verification fails; handle and log these errors as security events.

## Validation & Testing

- Run unit tests: `bun test`
- The test suite (`tests/teos.test.ts`) demonstrates PSK, MLS, and tampering scenarios—treat it as executable documentation.

## Serialization Workflow

When storing or relaying envelopes, serialize them with `serializeTEOS(teos)` and send the resulting `Uint8Array`. Recipients can call `deserializeTEOS(buffer)` before `extractTEOS`.

## Troubleshooting

- **`Invalid TEOS signature`:** the sender key or ciphertext was altered. Re-fetch the sender public key and ensure the transport layer preserves binary data.
- **`Failed to canonicalize TEOS payload`:** indicates the input object is missing required base fields; always pass envelopes built by this library or match the schema above.
- **Web Crypto not available:** run under Node.js 18+, Bun, Deno, or browsers that expose `crypto.subtle`; otherwise polyfill with `@peculiar/webcrypto` before importing the library.

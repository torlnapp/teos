import { encode } from '@msgpack/msgpack';
import type { AADPayload } from '../src/types/teos';

export const defaultAAD: AADPayload = {
  contextId: 'group-123',
  epochId: 42,
  senderClientId: 'client-7',
  messageSequence: 3,
  scopeId: 'channel-1',
};

export const encodePayload = (value: unknown): ArrayBuffer => {
  const encoded = new Uint8Array(encode(value));
  return encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  );
};

export const encryptPayloadForMls = async (
  key: CryptoKey,
  plaintext: ArrayBuffer,
): Promise<ArrayBuffer> => {
  const nonce = new Uint8Array(12);
  return crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    plaintext,
  );
};

export async function createCryptoContext(): Promise<{
  aesKey: CryptoKey;
  senderKeyPair: CryptoKeyPair;
  pskBytes: ArrayBuffer;
}> {
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const ed25519Key = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  if (!('privateKey' in ed25519Key) || !('publicKey' in ed25519Key)) {
    throw new Error('Failed to generate Ed25519 key pair');
  }

  const pskSeed = crypto.getRandomValues(new Uint8Array(32));
  const pskBytes = pskSeed.buffer.slice(
    pskSeed.byteOffset,
    pskSeed.byteOffset + pskSeed.byteLength,
  );

  return {
    aesKey,
    senderKeyPair: ed25519Key,
    pskBytes,
  };
}

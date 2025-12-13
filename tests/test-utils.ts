import {
  AES,
  type AESKey,
  Ed25519,
  type Ed25519KeyPair,
  encodeMsgPack,
} from '@torlnapp/crypto-utils';
import type { AADPayload } from '../src/types/teos';

export const defaultAAD: AADPayload = {
  contextId: 'group-123',
  epochId: 42,
  senderClientId: 'client-7',
  messageSequence: 3,
  scopes: ['scope1'],
};

export const encodePayload = (value: unknown): Uint8Array<ArrayBuffer> => {
  return new Uint8Array(encodeMsgPack(value));
};

export const encryptPayloadForMls = async (
  key: AESKey,
  plaintext: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
  const result = await AES.encrypt(key, plaintext, nonce);

  return new Uint8Array(result);
};

export async function createCryptoContext(): Promise<{
  aesKey: AESKey;
  senderKeyPair: Ed25519KeyPair;
  pskBytes: Uint8Array<ArrayBuffer>;
}> {
  const aesKey = await AES.generateKey(true);

  const senderKeyPair = await Ed25519.generateKeyPair(true);

  const pskSeed = crypto.getRandomValues(new Uint8Array(32));
  const pskBytes = new Uint8Array(pskSeed);

  return {
    aesKey,
    senderKeyPair,
    pskBytes,
  };
}

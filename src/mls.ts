import {
  AES,
  type AESKey,
  type Binary,
  decodeMsgPack,
  Ed25519,
  type Ed25519PrivateKey,
  type Ed25519PublicKey,
} from '@torlnapp/crypto-utils';
import { deserializeTEOS, generateBaseTEOSHash } from './lib/teos';
import type {
  AADPayload,
  EnvelopeAuth,
  MLS_TEOS,
  MLSEnvelope,
  TEOS,
} from './types/teos';
import { createBaseMlsTEOS } from './utils/teos';

export async function createMlsTEOS(
  identifier: string,
  aad: AADPayload,
  signerPrivateKey: Ed25519PrivateKey,
  data: Binary,
  nonce: Binary,
): Promise<MLS_TEOS> {
  const base = await createBaseMlsTEOS(identifier, aad, data, nonce);
  const hash = await generateBaseTEOSHash(base);
  const auth: EnvelopeAuth = {
    signature: await Ed25519.sign(signerPrivateKey, hash),
  };

  const envelope: MLSEnvelope = {
    suite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
    auth,
  };

  const teos: MLS_TEOS = {
    ...base,
    mode: 'mls',
    envelope,
  };

  return teos;
}

export async function extractTEOS<T>(
  payload: TEOS | Binary,
  aesKey: AESKey,
  signerPublicKey: Ed25519PublicKey,
): Promise<T> {
  if (payload instanceof Uint8Array) {
    payload = deserializeTEOS(payload);
  }

  const hash = await generateBaseTEOSHash(payload);
  const isValid = await Ed25519.verify(
    signerPublicKey,
    hash,
    payload.envelope.auth.signature,
  );
  if (!isValid) {
    throw new Error('[TEOS] Invalid TEOS signature');
  }

  const result = await AES.decrypt(
    aesKey,
    new Uint8Array([...payload.ciphertext, ...payload.tag]),
    payload.nonce,
  );

  return decodeMsgPack(result) as T;
}

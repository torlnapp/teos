import {
  AES,
  type AESKey,
  type Binary,
  Ed25519,
  type Ed25519PublicKey,
  generateNonce,
  processCiphertext,
} from '@torlnapp/crypto-utils';
import { version } from '../lib/common';
import { generateBaseTEOSHash } from '../lib/teos';
import type { AADPayload, BaseTEOS, TEOS } from '../types/teos';

export async function createBasePskTEOS(
  identifier: string,
  aad: AADPayload,
  aesKey: AESKey,
  data: Binary,
): Promise<BaseTEOS> {
  const nonce = generateNonce();
  const payload = await AES.encrypt(aesKey, data, nonce);

  const { ciphertext, tag } = processCiphertext(payload);
  const baseResult: BaseTEOS = {
    type: 'torln.teos.v1',
    version,
    algorithm: 'AES-GCM',
    aad: {
      identifier,
      timestamp: Date.now(),
      ...aad,
    },
    nonce,
    tag,
    ciphertext,
  };

  return baseResult;
}

export async function createBaseMlsTEOS(
  identifier: string,
  aad: AADPayload,
  data: Binary,
  nonce: Binary,
): Promise<BaseTEOS> {
  const { ciphertext, tag } = processCiphertext(data);

  const baseResult: BaseTEOS = {
    type: 'torln.teos.v1',
    version,
    algorithm: 'ChaCha20-Poly1305',
    aad: {
      identifier,
      timestamp: Date.now(),
      ...aad,
    },
    nonce,
    tag,
    ciphertext,
  };

  return baseResult;
}

export async function verifyTEOS(
  teos: TEOS,
  authorPublicKey: Ed25519PublicKey,
): Promise<boolean> {
  const hash = await generateBaseTEOSHash(teos);

  const isSignatureValid = await Ed25519.verify(
    authorPublicKey,
    hash,
    teos.envelope.auth.signature,
  );

  return isSignatureValid;
}

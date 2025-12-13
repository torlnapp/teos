import {
  AES,
  type AESKey,
  type Binary,
  decodeMsgPack,
  Ed25519,
  type Ed25519PrivateKey,
  type Ed25519PublicKey,
  encodeUTF8,
  generateUUID,
  HKDF,
  SHA256,
} from '@torlnapp/crypto-utils';
import { generateBaseTEOSHash } from './lib/teos';
import type {
  AADPayload,
  EnvelopeAuth,
  PSK_TEOS,
  PSKEnvelope,
} from './types/teos';
import { createBasePskTEOS } from './utils/teos';

interface PskAADParams {
  identifier: string;
  groupId: string;
  epochId: number;
  pskGeneration: number;
  senderClientId: string;
  messageSequence: number;
}

async function derivePskCryptoKey(
  aad: PskAADParams,
  pskBytes: Binary,
): Promise<AESKey> {
  const hkdfBase = await HKDF.importKey(pskBytes);

  const saltInput = encodeUTF8(
    `${aad.groupId}|${aad.epochId}|${aad.pskGeneration}`,
  );
  const saltHashBuffer = await SHA256.hash(saltInput);
  const salt = new Uint8Array(saltHashBuffer);

  const infoKey = encodeUTF8(
    `torln-teos-v1:key|${aad.identifier}|${aad.senderClientId}|${aad.messageSequence}`,
  );

  const keyBitsBuffer = await HKDF.deriveBits(hkdfBase, salt, infoKey);
  const keyBytes = new Uint8Array(keyBitsBuffer);

  const aesKey = await AES.importKey(keyBytes, false);

  return aesKey;
}

export async function createPskTEOS(
  aad: AADPayload,
  pskBytes: Binary,
  signerPrivateKey: Ed25519PrivateKey,
  data: Binary,
): Promise<PSK_TEOS> {
  const identifier = generateUUID();
  const aesKey = await derivePskCryptoKey(
    {
      identifier,
      groupId: aad.contextId,
      epochId: aad.epochId,
      pskGeneration: 1,
      senderClientId: aad.senderClientId,
      messageSequence: aad.messageSequence,
    },
    pskBytes,
  );
  const base = await createBasePskTEOS(identifier, aad, aesKey, data);
  const hash = await generateBaseTEOSHash(base);
  const auth: EnvelopeAuth = {
    signature: await Ed25519.sign(signerPrivateKey, hash),
  };

  const envelope: PSKEnvelope = {
    suite: 'PSK+AES-256-GCM',
    auth,
    pskGeneration: 1,
  };

  const teos: PSK_TEOS = {
    ...base,
    mode: 'psk',
    envelope,
  };

  return teos;
}

export async function extractPskTEOS<T>(
  teos: PSK_TEOS,
  pskBytes: Binary,
  signerPublicKey: Ed25519PublicKey,
): Promise<T> {
  const aesKey = await derivePskCryptoKey(
    {
      identifier: teos.aad.identifier,
      groupId: teos.aad.contextId,
      epochId: teos.aad.epochId,
      pskGeneration: teos.envelope.pskGeneration,
      senderClientId: teos.aad.senderClientId,
      messageSequence: teos.aad.messageSequence,
    },
    pskBytes,
  );

  const hash = await generateBaseTEOSHash(teos);
  const isValid = await Ed25519.verify(
    signerPublicKey,
    hash,
    teos.envelope.auth.signature,
  );
  if (!isValid) {
    throw new Error('[TEOS] Invalid TEOS signature');
  }

  const result = await AES.decrypt(
    aesKey,
    new Uint8Array([...teos.ciphertext, ...teos.tag]),
    teos.nonce,
  );

  return decodeMsgPack(result) as T;
}

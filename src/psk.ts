import { decode } from '@msgpack/msgpack';
import { generateSignature, verifySignature } from './lib/signature';
import { generateBaseTEOSHash } from './lib/teos';
import type {
  AADPayload,
  EnvelopeAuth,
  PSK_TEOS,
  PSKEnvelope,
} from './types/teos';
import { createBasePskTEOS } from './utils/teos';
import { encodeText } from './utils/text';

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
  pskBytes: ArrayBuffer,
): Promise<CryptoKey> {
  const hkdfBase = await crypto.subtle.importKey(
    'raw',
    pskBytes,
    'HKDF',
    false,
    ['deriveBits'],
  );

  const saltInput = encodeText(
    `${aad.groupId}|${aad.epochId}|${aad.pskGeneration}`,
  );
  const saltHashBuffer = await crypto.subtle.digest('SHA-256', saltInput);
  const salt = new Uint8Array(saltHashBuffer);

  const infoKey = encodeText(
    `torln-teos-v1:key|${aad.identifier}|${aad.senderClientId}|${aad.messageSequence}`,
  );
  const keyBitsBuffer = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: infoKey,
    },
    hkdfBase,
    256,
  );
  const keyBytes = new Uint8Array(keyBitsBuffer);

  const aesKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );

  return aesKey;
}

export async function createPskTEOS(
  aad: AADPayload,
  pskBytes: ArrayBuffer,
  signerPrivateKey: CryptoKey,
  data: ArrayBuffer,
): Promise<PSK_TEOS> {
  const identifier = crypto.randomUUID();

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
    signature: await generateSignature(signerPrivateKey, hash.buffer),
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
  pskBytes: ArrayBuffer,
  signerPublicKey: CryptoKey,
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
  const isValid = await verifySignature(
    signerPublicKey,
    hash.buffer,
    teos.envelope.auth.signature.buffer,
  );
  if (!isValid) {
    throw new Error('[TEOS] Invalid TEOS signature');
  }

  const result = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: teos.nonce,
    },
    aesKey,
    new Uint8Array([...teos.ciphertext, ...teos.tag]).buffer,
  );

  return decode(result) as T;
}

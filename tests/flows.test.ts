import { beforeAll, describe, expect, test } from 'bun:test';
import {
  AES,
  type AESKey,
  type Binary,
  Ed25519,
  type Ed25519KeyPair,
  type Ed25519PublicKey,
  encodeMsgPack,
} from '@torlnapp/crypto-utils';
import initOpenMls, {
  Group,
  Identity,
  Provider,
} from '@torlnapp/torln-openmls-wasm';
import { generateBaseTEOSHash } from '../src/lib/teos';
import { createMlsTEOS, extractTEOS } from '../src/mls';
import { createPskTEOS, extractPskTEOS } from '../src/psk';
import type { PSK_TEOS } from '../src/types/teos';
import { verifyTEOS } from '../src/utils/teos';
import {
  defaultAAD as aad,
  createCryptoContext,
  encryptPayloadForMls,
} from './test-utils';

let senderKeyPair: Ed25519KeyPair;
let pskBytes: Uint8Array<ArrayBuffer>;
let authorPublicKey: Ed25519PublicKey;
let mlsAesKey: AESKey;
let aliceExportedMlsKey: Uint8Array;
let bobExportedMlsKey: Uint8Array;

beforeAll(async () => {
  ({ senderKeyPair, pskBytes } = await createCryptoContext());
  authorPublicKey = senderKeyPair.publicKey;

  await initOpenMls();

  const aliceProvider = new Provider();
  const bobProvider = new Provider();

  const alice = new Identity(aliceProvider, 'alice');
  const bob = new Identity(bobProvider, 'bob');

  const aliceGroup = Group.createNew(aliceProvider, alice, 'teos-group');
  const bobKeyPackage = bob.getKeyPackage(bobProvider);

  const addMsgs = aliceGroup.proposeAndCommitAdd(
    aliceProvider,
    alice,
    bobKeyPackage,
  );

  aliceGroup.mergePendingCommit(aliceProvider);

  const ratchetTree = aliceGroup.exportRatchetTree();
  const bobGroup = Group.join(bobProvider, addMsgs.welcome, ratchetTree);

  const label = 'teos_payload_key';
  const context = new Uint8Array(32).fill(0x30);

  aliceExportedMlsKey = aliceGroup.exportSecret(
    aliceProvider,
    label,
    context,
    32,
  );
  bobExportedMlsKey = bobGroup.exportSecret(bobProvider, label, context, 32);

  mlsAesKey = await AES.importKey(
    new Uint8Array(aliceExportedMlsKey) satisfies Binary,
    true,
  );
});

describe('TEOS flows', () => {
  test('createTEOS (psk) encrypts payload, signs envelope, and extractTEOS restores plaintext', async () => {
    const original = {
      message: 'hello world',
      count: 5,
      nested: { active: true },
    };

    const teos = await createPskTEOS(
      aad,
      pskBytes,
      senderKeyPair.privateKey,
      encodeMsgPack(original),
    );

    const hash = await generateBaseTEOSHash(teos);
    const directValid = await Ed25519.verify(
      senderKeyPair.publicKey,
      hash,
      teos.envelope.auth.signature,
    );
    expect(directValid).toBe(true);

    const signatureValid = await Ed25519.verify(
      senderKeyPair.publicKey,
      hash,
      teos.envelope.auth.signature,
    );
    expect(signatureValid).toBe(true);

    expect(teos.mode).toBe('psk');
    expect(teos.envelope.suite).toBe('PSK+AES-256-GCM');
    expect(teos.envelope.pskGeneration).toBe(1);
    expect(teos.nonce.length).toBe(12);
    expect(teos.tag.length).toBe(16);
    expect(teos.ciphertext.length).toBeGreaterThan(0);

    const recovered = await extractPskTEOS<typeof original>(
      teos,
      pskBytes,
      senderKeyPair.publicKey,
    );
    expect(recovered).toEqual(original);
  });

  test('createTEOS (mls) produces MLS envelope and extractTEOS succeeds', async () => {
    expect(aliceExportedMlsKey.length).toBe(32);
    expect([...aliceExportedMlsKey]).toEqual([...bobExportedMlsKey]);

    const original = { status: 'ok', items: [1, 2, 3] };
    const encoded = encodeMsgPack(original);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const identifier = crypto.randomUUID();

    const encryptedPayload = await encryptPayloadForMls(
      mlsAesKey,
      encoded,
      nonce,
    );

    const manuallyDecrypted = await AES.decrypt(
      mlsAesKey,
      encryptedPayload,
      nonce,
    );
    expect(new Uint8Array(manuallyDecrypted)).toEqual(encoded);

    const teos = await createMlsTEOS(
      identifier,
      aad,
      senderKeyPair.privateKey,
      encryptedPayload,
      nonce,
    );

    expect(Array.from(teos.nonce)).toEqual(Array.from(nonce));
    expect([...teos.ciphertext, ...teos.tag]).toEqual(
      Array.from(encryptedPayload),
    );
    expect(teos.aad.identifier).toBe(identifier);

    const hash = await generateBaseTEOSHash(teos);
    const signatureValid = await Ed25519.verify(
      senderKeyPair.publicKey,
      hash,
      teos.envelope.auth.signature,
    );
    expect(signatureValid).toBe(true);

    expect(teos.mode).toBe('mls');
    expect(teos.envelope.suite).toBe(
      'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
    );

    const recovered = await extractTEOS<typeof original>(
      teos,
      mlsAesKey,
      senderKeyPair.publicKey,
    );
    expect(recovered).toEqual(original);
  });

  test('verifyTEOS reports valid and invalid signatures', async () => {
    const teos = await createPskTEOS(
      aad,
      pskBytes,
      senderKeyPair.privateKey,
      encodeMsgPack({ payload: 'data' }),
    );

    await expect(verifyTEOS(teos, authorPublicKey)).resolves.toBe(true);

    const tamperedSignature = new Uint8Array(teos.envelope.auth.signature);
    const firstByte = tamperedSignature.at(0);
    if (firstByte === undefined) {
      throw new Error('Signature unexpectedly empty');
    }
    tamperedSignature[0] = firstByte ^ 0xff;

    const tamperedTeos: PSK_TEOS = {
      ...teos,
      envelope: {
        ...teos.envelope,
        auth: {
          ...teos.envelope.auth,
          signature: tamperedSignature,
        },
      },
    };

    await expect(verifyTEOS(tamperedTeos, authorPublicKey)).resolves.toBe(
      false,
    );
  });

  test('extractTEOS rejects tampered signatures', async () => {
    const teos = await createPskTEOS(
      aad,
      pskBytes,
      senderKeyPair.privateKey,
      encodeMsgPack({ compromised: true }),
    );

    const tamperedSignature = new Uint8Array(teos.envelope.auth.signature);
    const firstByte = tamperedSignature.at(0);
    if (firstByte === undefined) {
      throw new Error('Signature unexpectedly empty');
    }
    tamperedSignature[0] = firstByte ^ 0xff;

    const tampered: PSK_TEOS = {
      ...teos,
      envelope: {
        ...teos.envelope,
        auth: {
          ...teos.envelope.auth,
          signature: tamperedSignature,
        },
      },
    };

    await expect(
      extractPskTEOS(tampered, pskBytes, senderKeyPair.publicKey),
    ).rejects.toThrow('Invalid TEOS signature');
  });
});

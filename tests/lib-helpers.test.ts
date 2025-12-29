import { beforeAll, describe, expect, test } from 'bun:test';
import {
  AES,
  type AESKey,
  Ed25519,
  type Ed25519KeyPair,
  encodeMsgPack,
  generateNonce,
  processCiphertext,
} from '@torlnapp/crypto-utils';
import { deserializeTEOS, getTEOSDto, serializeTEOS } from '../src/lib/teos';
import { createPskTEOS } from '../src/psk';
import { defaultAAD as aad, createCryptoContext } from './test-utils';

let aesKey: AESKey;
let senderKeyPair: Ed25519KeyPair;
let pskBytes: Uint8Array<ArrayBuffer>;

beforeAll(async () => {
  ({ aesKey, senderKeyPair, pskBytes } = await createCryptoContext());
});

describe('lib helpers', () => {
  test('generateNonce returns 12 random bytes', () => {
    const nonce = generateNonce();
    expect(nonce).toBeInstanceOf(Uint8Array);
    expect(nonce.length).toBe(12);
    expect(Array.from(nonce).some((value) => value !== 0)).toBe(true);
  });

  test('processCiphertext splits AES-GCM payload', async () => {
    const iv = new Uint8Array(12);
    const payload = await AES.encrypt(
      aesKey,
      encodeMsgPack({ sample: true }),
      iv,
    );

    const { ciphertext, tag } = processCiphertext(new Uint8Array(payload));
    const totalLength = new Uint8Array(payload).length;

    expect(ciphertext.length + tag.length).toBe(totalLength);
    expect(tag.length).toBe(16);
    expect(ciphertext.length).toBeGreaterThan(0);
  });

  test('generateSignature output passes verifySignature', async () => {
    const data = new TextEncoder().encode('sign me');
    const signature = await Ed25519.sign(senderKeyPair.privateKey, data);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);

    const valid = await Ed25519.verify(
      senderKeyPair.publicKey,
      data,
      signature,
    );
    expect(valid).toBe(true);
  });

  test('serializeTEOS and deserializeTEOS round-trip the payload', async () => {
    const teos = await createPskTEOS(
      aad,
      pskBytes,
      senderKeyPair.privateKey,
      encodeMsgPack({ foo: 'bar' }),
    );

    const serialized = serializeTEOS(teos);
    expect(serialized).toBeInstanceOf(Uint8Array);

    const parsed = deserializeTEOS(serialized);
    expect(parsed).toEqual(teos);
  });

  test('getTEOSDto mirrors TEOS metadata', async () => {
    const teos = await createPskTEOS(
      aad,
      pskBytes,
      senderKeyPair.privateKey,
      encodeMsgPack({ hello: 'world' }),
    );

    const serialized = serializeTEOS(teos);
    const dto = getTEOSDto(teos);

    expect(dto.type).toBe('torln.teos.dto.v1');
    expect(dto.id).toBe(teos.aad.identifier);
    expect(dto.mode).toBe(teos.mode);
    expect(dto.ciphersuite).toBe(teos.envelope.suite);
    expect(dto.blob).toEqual(serialized);
    expect(dto.timestamp.getTime()).toBe(teos.aad.timestamp);
  });
});

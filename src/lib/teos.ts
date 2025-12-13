import {
  type Binary,
  cm,
  decodeMsgPack,
  encodeMsgPack,
  SHA256,
} from '@torlnapp/crypto-utils';
import type { TEOSDto } from '../types/dto';
import type { BaseTEOS, TEOS } from '../types/teos';

export async function generateBaseTEOSHash(payload: TEOS | BaseTEOS) {
  const data: BaseTEOS = {
    type: 'torln.teos.v1',
    version: payload.version,
    algorithm: payload.algorithm,
    aad: payload.aad,
    nonce: payload.nonce,
    tag: payload.tag,
    ciphertext: payload.ciphertext,
  };

  return SHA256.hash(cm(data));
}

export function serializeTEOS(teos: TEOS) {
  return encodeMsgPack(teos);
}

export function deserializeTEOS(buffer: Binary): TEOS {
  const data = decodeMsgPack(buffer);
  if (
    typeof data === 'object' &&
    data !== null &&
    'type' in data &&
    data.type === 'torln.teos.v1'
  ) {
    return data as TEOS;
  }
  throw new Error('[TEOS] Invalid TEOS format');
}

export function getTEOSDto(teos: TEOS): TEOSDto {
  return {
    type: 'torln.teos.dto.v1',
    id: teos.aad.identifier,
    mode: teos.mode,
    ciphersuite: teos.envelope.suite,
    blob: serializeTEOS(teos),
    timestamp: new Date(teos.aad.timestamp),
  };
}

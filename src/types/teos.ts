/**
 * Torln Encrypted Object Specification
 */
export type TEOS = PSK_TEOS | MLS_TEOS;

export type Mode = 'psk' | 'mls';

export interface BaseTEOS {
  type: 'torln.teos.v1';
  version: string;
  algorithm: string;
  aad: AAD;
  nonce: Uint8Array<ArrayBuffer>;
  tag: Uint8Array<ArrayBuffer>;
  ciphertext: Uint8Array<ArrayBuffer>;
}

export interface PSK_TEOS extends BaseTEOS {
  mode: 'psk';
  envelope: PSKEnvelope;
}

export interface MLS_TEOS extends BaseTEOS {
  mode: 'mls';
  envelope: MLSEnvelope;
}

/**
 * Additional Authenticated Data
 */
export interface AAD {
  groupId: string;
  channelId?: string | null;
  epochId: number;
  senderClientId: string;
  messageSequence: number;
  timestamp: number;
  objectId: string;
}

export type Envelope = PSKEnvelope | MLSEnvelope;

export interface EnvelopeAuth {
  publicKey: globalThis.JsonWebKey;
  signature: Uint8Array<ArrayBuffer>;
}

export interface PSKEnvelope {
  suite?: string | null;
  auth: EnvelopeAuth;
  pskId: string;
  expiresAt?: number | null;
  pskGeneration?: number | null;
}

export interface MLSEnvelope {
  suite?: string | null;
  auth: EnvelopeAuth;
}

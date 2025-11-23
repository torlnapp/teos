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
export interface AAD extends AADPayload {
  identifier: string;
  timestamp: number;
}

export interface AADPayload {
  contextId: string;
  scopeId?: string;
  epochId: number;
  senderClientId: string;
  messageSequence: number;
}

export type Envelope = PSKEnvelope | MLSEnvelope;

export interface EnvelopeAuth {
  signature: Uint8Array<ArrayBuffer>;
}

export interface PSKEnvelope {
  suite: string;
  auth: EnvelopeAuth;
  pskGeneration: number;
  expiresAt?: number | null;
}

export interface MLSEnvelope {
  suite: string;
  auth: EnvelopeAuth;
}

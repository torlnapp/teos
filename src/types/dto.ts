import type { Binary } from '@torlnapp/crypto-utils';
import type { Mode } from './teos';

export interface TEOSDto {
  type: 'torln.teos.dto.v1';
  id: string;
  mode: Mode;
  ciphersuite: string;
  blob: Binary;
  timestamp: Date;
}

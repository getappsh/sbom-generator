export { SbomFormat, SbomTargetType } from '@app/common/database/entities';
import { SbomFormat, SbomTargetType } from '@app/common/database/entities';

export interface SbomScanOptions {
  scanId: string;
  target: string;
  targetType: SbomTargetType;
  format?: SbomFormat;
}

export interface SbomScanResult {
  raw: Buffer;
  format: SbomFormat;
}

export const SBOM_ENGINE = 'SBOM_ENGINE';

export interface ISbomEngine {
  generateReport(options: SbomScanOptions): Promise<SbomScanResult>;
}

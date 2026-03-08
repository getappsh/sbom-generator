export enum SbomFormat {
  SYFT_JSON = 'syft-json',
  SPDX_JSON = 'spdx-json',
  CYCLONEDX_JSON = 'cyclonedx-json',
  TABLE = 'table',
  TEXT = 'text',
}

export enum SbomTargetType {
  DOCKER_IMAGE = 'docker',
  REGISTRY = 'registry',
  FILE = 'file',
  DIR = 'dir',
  OCI_ARCHIVE = 'oci-archive',
}

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

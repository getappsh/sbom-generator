import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { spawn } from 'child_process';
import * as os from 'os';
import { ISbomEngine, SbomFormat, SbomScanOptions, SbomScanResult, SbomTargetType } from '../interfaces/sbom-engine.interface';

@Injectable()
export class SyftEngine implements ISbomEngine {
  private readonly logger = new Logger(SyftEngine.name);
  private readonly useDocker: boolean;
  private readonly syftVersion: string;
  private readonly grypeVersion: string;
  private readonly enableVulnScan: boolean;

  constructor(private readonly configService: ConfigService) {
    this.useDocker = configService.get('USE_DOCKER_FOR_SYFT') === 'true';
    this.syftVersion = configService.get('SYFT_VERSION') ?? 'latest';
    this.grypeVersion = configService.get('GRYPE_VERSION') ?? 'latest';
    this.enableVulnScan = configService.get('ENABLE_VULNERABILITY_SCAN') !== 'false';
  }

  async generateReport(options: SbomScanOptions): Promise<SbomScanResult> {
    const format = options.format ?? SbomFormat.CYCLONEDX_JSON;
    const syftTarget = this.buildSyftTarget(options.targetType, options.target);
    this.logger.log(`[${options.scanId}] Starting Syft scan: target=${syftTarget}, format=${format}`);

    const raw = await (this.useDocker
      ? this.runWithDocker(syftTarget, format, options.scanId)
      : this.runBinary(syftTarget, format, options.scanId));

    this.logger.log(`[${options.scanId}] Syft scan completed, output size=${raw.length}`);

    // Enrich CycloneDX output with Grype vulnerability data
    if (this.enableVulnScan && format === SbomFormat.CYCLONEDX_JSON) {
      return { raw: await this.enrichWithVulnerabilities(raw, syftTarget, options.scanId), format };
    }

    return { raw, format };
  }

  /**
   * Runs Grype against the same target and merges its `vulnerabilities` array
   * into the Syft-generated CycloneDX JSON.
   */
  private async enrichWithVulnerabilities(sbomRaw: Buffer, target: string, scanId: string): Promise<Buffer> {
    this.logger.log(`[${scanId}] Running Grype vulnerability scan`);
    try {
      const grypeRaw = await (this.useDocker
        ? this.runGrypeWithDocker(target, scanId)
        : this.runGrypeBinary(target, scanId));

      const sbom = JSON.parse(sbomRaw.toString('utf8'));
      const grypeResult = JSON.parse(grypeRaw.toString('utf8'));

      if (Array.isArray(grypeResult.vulnerabilities) && grypeResult.vulnerabilities.length > 0) {
        sbom.vulnerabilities = grypeResult.vulnerabilities;
        this.logger.log(`[${scanId}] Merged ${grypeResult.vulnerabilities.length} vulnerabilities into SBOM`);
      } else {
        this.logger.log(`[${scanId}] Grype found no vulnerabilities`);
      }

      return Buffer.from(JSON.stringify(sbom, null, 2), 'utf8');
    } catch (err) {
      // Vulnerability scan failure must not block the SBOM from being saved
      this.logger.warn(`[${scanId}] Grype scan failed — returning SBOM without vulnerability data: ${(err as Error).message}`);
      return sbomRaw;
    }
  }

  private buildSyftTarget(type: SbomTargetType, target: string): string {
    switch (type) {
      case SbomTargetType.DOCKER_IMAGE:
        return `docker:${target}`;
      case SbomTargetType.REGISTRY:
        return `registry:${target}`;
      case SbomTargetType.FILE:
        return `file:${target}`;
      case SbomTargetType.DIR:
        return `dir:${target}`;
      case SbomTargetType.OCI_ARCHIVE:
        return `oci-archive:${target}`;
      default:
        return target;
    }
  }

  private runBinary(target: string, format: SbomFormat, scanId: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const args = [target, '-o', format, '--quiet'];
      this.logger.debug(`[${scanId}] Running: syft ${args.join(' ')}`);

      const proc = spawn('syft', args);
      const chunks: Buffer[] = [];
      const errChunks: Buffer[] = [];

      proc.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
      proc.stderr.on('data', (chunk: Buffer) => errChunks.push(chunk));

      proc.on('close', (code) => {
        if (code !== 0) {
          const errMsg = Buffer.concat(errChunks).toString();
          this.logger.error(`[${scanId}] syft exited with code ${code}: ${errMsg}`);
          return reject(new Error(`Syft exited with code ${code}: ${errMsg}`));
        }
        resolve(Buffer.concat(chunks));
      });

      proc.on('error', (err) => {
        this.logger.error(`[${scanId}] Failed to spawn syft: ${err.message}`);
        reject(new Error(`Failed to spawn syft binary: ${err.message}`));
      });
    });
  }

  private runWithDocker(target: string, format: SbomFormat, scanId: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const tmpDir = os.tmpdir();
      const args = [
        'run', '--rm',
        '-v', '/var/run/docker.sock:/var/run/docker.sock',
        '-v', `${tmpDir}:${tmpDir}:ro`,
        `anchore/syft:${this.syftVersion}`,
        target,
        '-o', format,
        '--quiet',
      ];
      this.logger.debug(`[${scanId}] Running: docker ${args.join(' ')}`);

      const proc = spawn('docker', args);
      const chunks: Buffer[] = [];
      const errChunks: Buffer[] = [];

      proc.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
      proc.stderr.on('data', (chunk: Buffer) => errChunks.push(chunk));

      proc.on('close', (code) => {
        if (code !== 0) {
          const errMsg = Buffer.concat(errChunks).toString();
          this.logger.error(`[${scanId}] docker/syft exited with code ${code}: ${errMsg}`);
          return reject(new Error(`Syft (docker) exited with code ${code}: ${errMsg}`));
        }
        resolve(Buffer.concat(chunks));
      });

      proc.on('error', (err) => {
        this.logger.error(`[${scanId}] Failed to spawn docker: ${err.message}`);
        reject(new Error(`Failed to spawn docker for syft: ${err.message}`));
      });
    });
  }

  private runGrypeBinary(target: string, scanId: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const args = [target, '-o', 'cyclonedx-json', '--quiet'];
      this.logger.debug(`[${scanId}] Running: grype ${args.join(' ')}`);

      const proc = spawn('grype', args);
      const chunks: Buffer[] = [];
      const errChunks: Buffer[] = [];

      proc.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
      proc.stderr.on('data', (chunk: Buffer) => errChunks.push(chunk));

      proc.on('close', (code) => {
        if (code !== 0) {
          const errMsg = Buffer.concat(errChunks).toString();
          return reject(new Error(`Grype exited with code ${code}: ${errMsg}`));
        }
        resolve(Buffer.concat(chunks));
      });

      proc.on('error', (err) => reject(new Error(`Failed to spawn grype binary: ${err.message}`)));
    });
  }

  private runGrypeWithDocker(target: string, scanId: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const tmpDir = os.tmpdir();
      const args = [
        'run', '--rm',
        '-v', '/var/run/docker.sock:/var/run/docker.sock',
        '-v', `${tmpDir}:${tmpDir}:ro`,
        `anchore/grype:${this.grypeVersion}`,
        target,
        '-o', 'cyclonedx-json',
        '--quiet',
      ];
      this.logger.debug(`[${scanId}] Running: docker ${args.join(' ')}`);

      const proc = spawn('docker', args);
      const chunks: Buffer[] = [];
      const errChunks: Buffer[] = [];

      proc.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
      proc.stderr.on('data', (chunk: Buffer) => errChunks.push(chunk));

      proc.on('close', (code) => {
        if (code !== 0) {
          const errMsg = Buffer.concat(errChunks).toString();
          return reject(new Error(`Grype (docker) exited with code ${code}: ${errMsg}`));
        }
        resolve(Buffer.concat(chunks));
      });

      proc.on('error', (err) => reject(new Error(`Failed to spawn docker for grype: ${err.message}`)));
    });
  }
}

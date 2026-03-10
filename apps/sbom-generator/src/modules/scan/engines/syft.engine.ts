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

    this.logger.log(`[${options.scanId}] Starting Syft scan — target=${syftTarget}, format=${format}, mode=${this.useDocker ? 'docker' : 'binary'}`);
    const syftStart = Date.now();

    const raw = await (this.useDocker
      ? this.runWithDocker(syftTarget, format, options.scanId)
      : this.runBinary(syftTarget, format, options.scanId));

    this.logger.log(`[${options.scanId}] Syft scan completed in ${Date.now() - syftStart}ms, output size=${raw.length} bytes`);

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
    this.logger.log(`[${scanId}] Starting Grype vulnerability scan — target=${target}, mode=${this.useDocker ? 'docker' : 'binary'}`);
    const grypeStart = Date.now();
    try {
      const grypeRaw = await (this.useDocker
        ? this.runGrypeWithDocker(target, scanId)
        : this.runGrypeBinary(target, scanId));

      this.logger.log(`[${scanId}] Grype scan completed in ${Date.now() - grypeStart}ms`);

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
      this.logger.warn(`[${scanId}] Grype scan failed after ${Date.now() - grypeStart}ms — returning SBOM without vulnerability data: ${(err as Error).message}`);
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

  /**
   * Spawns a process, streams stderr line-by-line to the logger in real-time,
   * collects stdout into a Buffer, and rejects with a rich error on non-zero exit.
   */
  private spawnAndCapture(
    cmd: string,
    args: string[],
    label: string,
    scanId: string,
  ): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      this.logger.log(`[${scanId}] [${label}] Spawning: ${cmd} ${args.join(' ')}`);

      const proc = spawn(cmd, args);
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];

      proc.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));

      // Log stderr chunks in real-time as they arrive
      proc.stderr.on('data', (chunk: Buffer) => {
        stderrChunks.push(chunk);
        this.logger.debug(`[${scanId}] [${label}] stderr: ${chunk.toString('utf8').trimEnd()}`);
      });

      proc.on('close', (code, signal) => {
        this.logger.log(`[${scanId}] [${label}] Process exited — code=${code}, signal=${signal ?? 'none'}`);

        if (code !== 0) {
          const stderrSummary = Buffer.concat(stderrChunks).toString('utf8').trim() || '(no stderr output)';
          const stdoutPreview = Buffer.concat(stdoutChunks).toString('utf8').slice(0, 500).trim() || '(no stdout output)';
          const msg =
            `[${label}] exited with code ${code}` +
            `\n--- stderr ---\n${stderrSummary}` +
            `\n--- stdout (first 500 chars) ---\n${stdoutPreview}`;
          this.logger.error(`[${scanId}] ${msg}`);
          return reject(new Error(msg));
        }

        resolve(Buffer.concat(stdoutChunks));
      });

      proc.on('error', (err) => {
        const msg = `[${label}] failed to spawn '${cmd}': ${err.message}`;
        this.logger.error(`[${scanId}] ${msg}`);
        reject(new Error(msg));
      });
    });
  }

  private runBinary(target: string, format: SbomFormat, scanId: string): Promise<Buffer> {
    return this.spawnAndCapture('syft', [target, '-o', format, '--quiet'], 'syft', scanId);
  }

  private runWithDocker(target: string, format: SbomFormat, scanId: string): Promise<Buffer> {
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
    return this.spawnAndCapture('docker', args, `syft@${this.syftVersion}`, scanId);
  }

  private runGrypeBinary(target: string, scanId: string): Promise<Buffer> {
    return this.spawnAndCapture('grype', [target, '-o', 'cyclonedx-json', '--quiet'], 'grype', scanId);
  }

  private runGrypeWithDocker(target: string, scanId: string): Promise<Buffer> {
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
    return this.spawnAndCapture('docker', args, `grype@${this.grypeVersion}`, scanId);
  }
}

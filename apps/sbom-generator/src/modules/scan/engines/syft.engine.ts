import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as https from 'https';
import * as os from 'os';
import * as path from 'path';
import { ISbomEngine, SbomFormat, SbomScanOptions, SbomScanResult, SbomTargetType } from '../interfaces/sbom-engine.interface';

@Injectable()
export class SyftEngine implements ISbomEngine {
  private readonly logger = new Logger(SyftEngine.name);
  private readonly useDocker: boolean;
  private readonly syftVersion: string;

  constructor(private readonly configService: ConfigService) {
    this.useDocker = configService.get('USE_DOCKER_FOR_SYFT') === 'true';
    this.syftVersion = configService.get('SYFT_VERSION') ?? 'latest';
  }

  async generateReport(options: SbomScanOptions): Promise<SbomScanResult> {
    const format = options.format ?? SbomFormat.CYCLONEDX_JSON;

    if (/^https?:\/\//i.test(options.target)) {
      this.logger.log(`[${options.scanId}] URL target detected, downloading to temp file: ${options.target}`);
      const tmpPath = await this.downloadToTemp(options.target, options.scanId);
      try {
        const syftTarget = `file:${tmpPath}`;
        this.logger.log(`[${options.scanId}] Starting Syft scan on temp file: ${syftTarget}`);
        const raw = await (this.useDocker
          ? this.runWithDocker(syftTarget, format, options.scanId)
          : this.runBinary(syftTarget, format, options.scanId));
        this.logger.log(`[${options.scanId}] Syft scan completed, output size=${raw.length}`);
        return { raw, format };
      } finally {
        fs.unlink(tmpPath, (err) => {
          if (err) this.logger.warn(`[${options.scanId}] Failed to delete temp file ${tmpPath}: ${err.message}`);
        });
      }
    }

    const syftTarget = this.buildSyftTarget(options.targetType, options.target);
    this.logger.log(`[${options.scanId}] Starting Syft scan: target=${syftTarget}, format=${format}`);

    const raw = await (this.useDocker
      ? this.runWithDocker(syftTarget, format, options.scanId)
      : this.runBinary(syftTarget, format, options.scanId));

    this.logger.log(`[${options.scanId}] Syft scan completed, output size=${raw.length}`);
    return { raw, format };
  }

  /** Downloads a URL to a temporary file and returns its path. */
  private downloadToTemp(url: string, scanId: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const ext = path.extname(new URL(url).pathname) || '';
      const tmpPath = path.join(os.tmpdir(), `syft-${scanId}${ext}`);
      const file = fs.createWriteStream(tmpPath);

      const get = url.startsWith('https') ? https.get : http.get;
      get(url, (res) => {
        if (res.statusCode && res.statusCode >= 400) {
          res.resume();
          file.destroy();
          fs.unlink(tmpPath, () => {});
          return reject(new Error(`HTTP ${res.statusCode} fetching URL: ${url}`));
        }
        res.pipe(file);
        file.on('finish', () => file.close(() => {
          this.logger.debug(`[${scanId}] Downloaded to temp file: ${tmpPath}`);
          resolve(tmpPath);
        }));
        file.on('error', (err) => {
          fs.unlink(tmpPath, () => {});
          reject(err);
        });
      }).on('error', (err) => {
        fs.unlink(tmpPath, () => {});
        reject(err);
      });
    });
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
}

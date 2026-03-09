import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { Subject } from 'rxjs';
import * as fs from 'fs';
import * as http from 'http';
import * as https from 'https';
import * as os from 'os';
import * as path from 'path';
import { MinioClientService } from '@app/common/AWS/minio-client.service';
import { SbomScanOptions, SBOM_ENGINE, ISbomEngine, SbomFormat, SbomTargetType } from './interfaces/sbom-engine.interface';
import { SbomScanJobEntity, ScanStatus } from './scan.entity';
import { CreateScanDto, ScanFileUploadedEventDto } from './dto/create-scan.dto';
import { ScanQueuedDto, ScanStatusDto } from './dto/scan-status.dto';

export interface ScanCompleteEvent {
  scanId: string;
  status: ScanStatus;
  error?: string;
}

@Injectable()
export class ScanService implements OnModuleDestroy {
  private readonly logger = new Logger(ScanService.name);
  private readonly bucketName: string;
  private readonly maxConcurrent: number;
  private readonly maxArtifactSizeBytes: number;

  /** Active running scan count */
  private running = 0;
  /** Pending scan queue when max concurrency is reached */
  private readonly queue: Array<() => void> = [];
  /** Per-scan SSE subjects: scanId -> Subject */
  private readonly subjects = new Map<string, Subject<ScanCompleteEvent>>();

  constructor(
    @Inject(SBOM_ENGINE) private readonly engine: ISbomEngine,
    @InjectRepository(SbomScanJobEntity) private readonly scanRepo: Repository<SbomScanJobEntity>,
    private readonly minioClient: MinioClientService,
    private readonly configService: ConfigService,
  ) {
    this.bucketName = configService.get('BUCKET_NAME') ?? '';
    this.maxConcurrent = Number(configService.get('SCAN_MAX_CONCURRENT') ?? 3);
    this.maxArtifactSizeBytes = Number(configService.get('SBOM_MAX_ARTIFACT_SIZE_BYTES') ?? 0);
  }

  onModuleDestroy() {
    this.subjects.forEach((s) => s.complete());
  }

  async queueScan(dto: CreateScanDto): Promise<ScanQueuedDto> {
    const entity = this.scanRepo.create({
      target: dto.target,
      targetType: dto.targetType,
      format: dto.format ?? SbomFormat.CYCLONEDX_JSON,
      triggeredBy: dto.triggeredBy,
      status: ScanStatus.QUEUED,
    });
    const saved = await this.scanRepo.save(entity);
    this.logger.log(`Queued scan job ${saved.id} for target: ${saved.target}`);

    // Run without awaiting - controlled by semaphore
    this.runWithSemaphore(saved.id);

    return { scanId: saved.id, status: ScanStatus.QUEUED };
  }

  async queueScanForUploadedFile(event: ScanFileUploadedEventDto): Promise<void> {
    // If a full URL is provided, use it directly. Otherwise generate a presigned
    // URL so the engine can download the file from MinIO (objectKey alone is not
    // a valid local filesystem path).
    let target = event.objectKey;
    if (!/^https?:\/\//i.test(target)) {
      const bucket = event.bucketName ?? this.bucketName;
      target = await this.minioClient.generatePresignedDownloadUrl(bucket, target);
    }

    const dto: CreateScanDto = {
      target,
      targetType: SbomTargetType.FILE,
      format: event.format ?? SbomFormat.CYCLONEDX_JSON,
      triggeredBy: event.triggeredBy ?? 'upload-service',
    };
    await this.queueScan(dto);
  }

  async getScanStatus(scanId: string): Promise<ScanStatusDto> {
    const entity = await this.findOrFail(scanId);
    return ScanStatusDto.fromEntity(entity);
  }

  async listScans(limit = 50, offset = 0): Promise<ScanStatusDto[]> {
    const entities = await this.scanRepo.find({
      order: { createdAt: 'DESC' },
      take: limit,
      skip: offset,
    });
    return entities.map(ScanStatusDto.fromEntity);
  }

  async getReportDownloadUrl(scanId: string): Promise<string> {
    const entity = await this.findOrFail(scanId);
    if (entity.status !== ScanStatus.COMPLETE || !entity.minioKey) {
      throw new Error(`Scan ${scanId} is not complete yet (status: ${entity.status})`);
    }
    return this.minioClient.generatePresignedDownloadUrl(this.bucketName, entity.minioKey);
  }

  /** Subscribe to SSE events for a specific scan. Client gets one event then stream closes. */
  subscribeToScanEvents(scanId: string): Subject<ScanCompleteEvent> {
    if (!this.subjects.has(scanId)) {
      this.subjects.set(scanId, new Subject<ScanCompleteEvent>());
    }
    return this.subjects.get(scanId)!;
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  private runWithSemaphore(scanId: string): void {
    if (this.running < this.maxConcurrent) {
      this.running++;
      this.executeScan(scanId).finally(() => {
        this.running--;
        if (this.queue.length > 0) {
          const next = this.queue.shift();
          this.running++;
          next!();
        }
      });
    } else {
      this.logger.log(`Scan ${scanId} queued (running=${this.running}/${this.maxConcurrent})`);
      this.queue.push(() => {
        this.executeScan(scanId).finally(() => {
          this.running--;
          if (this.queue.length > 0) {
            const next = this.queue.shift();
            this.running++;
            next!();
          }
        });
      });
    }
  }

  private async executeScan(scanId: string): Promise<void> {
    this.logger.log(`Executing scan ${scanId}`);
    const entity = await this.scanRepo.findOneBy({ id: scanId });
    if (!entity) {
      this.logger.error(`Scan ${scanId} not found in DB`);
      return;
    }

    // Mark running
    entity.status = ScanStatus.RUNNING;
    await this.scanRepo.save(entity);

    let tmpPath: string | undefined;
    try {
      if (/^https?:\/\//i.test(entity.target)) {
        tmpPath = await this.downloadToTemp(entity.target, scanId);
      }

      const options: SbomScanOptions = {
        scanId,
        target: tmpPath ?? entity.target,
        targetType: tmpPath ? SbomTargetType.FILE : entity.targetType,
        format: entity.format,
      };

      const result = await this.engine.generateReport(options);

      // Upload to MinIO
      const minioKey = `sbom-reports/${scanId}.${this.formatExtension(entity.format)}`;
      await this.ensureBucketExists();
      await this.uploadReportToMinio(minioKey, result.raw);

      // Mark complete
      entity.status = ScanStatus.COMPLETE;
      entity.minioKey = minioKey;
      entity.completedAt = new Date();
      await this.scanRepo.save(entity);

      this.logger.log(`Scan ${scanId} completed. Report saved at ${minioKey}`);
      this.notifySubscribers(scanId, { scanId, status: ScanStatus.COMPLETE });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.logger.error(`Scan ${scanId} failed: ${errorMessage}`);

      entity.status = ScanStatus.FAILED;
      entity.error = errorMessage;
      entity.failureReason = errorMessage;
      entity.completedAt = new Date();
      await this.scanRepo.save(entity);

      this.notifySubscribers(scanId, { scanId, status: ScanStatus.FAILED, error: errorMessage });
    } finally {
      if (tmpPath) {
        fs.unlink(tmpPath, (err) => {
          if (err) this.logger.warn(`[${scanId}] Failed to delete temp file ${tmpPath}: ${err.message}`);
        });
      }
    }
  }

  private notifySubscribers(scanId: string, event: ScanCompleteEvent): void {
    const subject = this.subjects.get(scanId);
    if (subject) {
      subject.next(event);
      subject.complete();
      this.subjects.delete(scanId);
    }
  }

  private async ensureBucketExists(): Promise<void> {
    const exists = await this.minioClient.bucketExists(this.bucketName);
    if (!exists) {
      this.logger.warn(`Bucket "${this.bucketName}" does not exist — please create it manually or via MinIO admin.`);
    }
  }

  private uploadReportToMinio(key: string, data: Buffer): Promise<void> {
    return this.minioClient.putBuffer(this.bucketName, key, data);
  }

  private formatExtension(format: SbomFormat): string {
    switch (format) {
      case SbomFormat.SYFT_JSON:
      case SbomFormat.SPDX_JSON:
      case SbomFormat.CYCLONEDX_JSON:
        return 'json';
      case SbomFormat.TABLE:
      case SbomFormat.TEXT:
        return 'txt';
      default:
        return 'json';
    }
  }

  private async findOrFail(scanId: string): Promise<SbomScanJobEntity> {
    const entity = await this.scanRepo.findOneBy({ id: scanId });
    if (!entity) {
      throw new Error(`Scan job not found: ${scanId}`);
    }
    return entity;
  }

  private downloadToTemp(url: string, scanId: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const ext = path.extname(new URL(url).pathname) || '';
      const tmpPath = path.join(os.tmpdir(), `sbom-${scanId}${ext}`);
      const file = fs.createWriteStream(tmpPath);

      const get = url.startsWith('https') ? https.get : http.get;
      get(url, (res) => {
        if (res.statusCode && res.statusCode >= 400) {
          res.resume();
          file.destroy();
          fs.unlink(tmpPath, () => {});
          return reject(new Error(`HTTP ${res.statusCode} fetching URL: ${url}`));
        }

        if (this.maxArtifactSizeBytes > 0) {
          const contentLengthHeader = res.headers['content-length'];
          if (contentLengthHeader) {
            const contentLength = parseInt(contentLengthHeader, 10);
            if (contentLength > this.maxArtifactSizeBytes) {
              const fileMB = (contentLength / (1024 * 1024)).toFixed(2);
              const limitMB = (this.maxArtifactSizeBytes / (1024 * 1024)).toFixed(2);
              res.resume();
              file.destroy();
              fs.unlink(tmpPath, () => {});
              return reject(new Error(
                `File size is ${contentLength} bytes (${fileMB} MB), which exceeds the configured limit of ${this.maxArtifactSizeBytes} bytes (${limitMB} MB)`,
              ));
            }
          }
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
}

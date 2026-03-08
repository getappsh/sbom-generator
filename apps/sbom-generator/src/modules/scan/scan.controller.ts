import { Controller, Logger } from '@nestjs/common';
import { EventPattern, MessagePattern } from '@nestjs/microservices';
import { RpcPayload } from '@app/common/microservice-client';
import { SbomTopics, SbomTopicsEmit } from '@app/common/microservice-client/topics';
import { ScanService } from './scan.service';
import { CreateScanDto, ScanFileUploadedEventDto } from './dto/create-scan.dto';
import { ScanQueuedDto, ScanStatusDto } from './dto/scan-status.dto';

@Controller()
export class ScanController {
  private readonly logger = new Logger(ScanController.name);

  constructor(private readonly scanService: ScanService) {}

  /**
   * Request-response: queue a new SBOM scan and return the scan ID immediately.
   * Callers: API gateway or any microservice.
   */
  @MessagePattern(SbomTopics.SCAN_REQUEST)
  async requestScan(@RpcPayload() dto: CreateScanDto): Promise<ScanQueuedDto> {
    this.logger.log(`Received scan request for target: ${dto.target} (${dto.targetType})`);
    return this.scanService.queueScan(dto);
  }

  /**
   * Request-response: get current status/metadata of a scan by ID.
   */
  @MessagePattern(SbomTopics.GET_SCAN_STATUS)
  async getScanStatus(@RpcPayload('scanId') scanId: string): Promise<ScanStatusDto> {
    this.logger.log(`Get scan status: ${scanId}`);
    return this.scanService.getScanStatus(scanId);
  }

  /**
   * Request-response: get a presigned download URL for a completed scan's report.
   */
  @MessagePattern(SbomTopics.GET_SCAN_RESULT)
  async getScanResult(@RpcPayload('scanId') scanId: string): Promise<{ url: string }> {
    this.logger.log(`Get scan result: ${scanId}`);
    const url = await this.scanService.getReportDownloadUrl(scanId);
    return { url };
  }

  /**
   * Request-response: list recent scan jobs.
   */
  @MessagePattern(SbomTopics.GET_SCANS)
  async getScans(@RpcPayload() params: { limit?: number; offset?: number }): Promise<ScanStatusDto[]> {
    return this.scanService.listScans(params?.limit, params?.offset);
  }

  /**
   * Fire-and-forget: triggered by upload service when a file is uploaded to MinIO.
   * Starts SBOM scan for the uploaded artifact.
   */
  @EventPattern(SbomTopicsEmit.SCAN_FILE)
  async onFileUploaded(@RpcPayload() event: ScanFileUploadedEventDto): Promise<void> {
    this.logger.log(`Received file-uploaded event: objectKey=${event.objectKey}`);
    await this.scanService.queueScanForUploadedFile(event);
  }

  /**
   * Health check.
   */
  @MessagePattern(SbomTopics.CHECK_HEALTH)
  healthCheck(): boolean {
    return true;
  }
}

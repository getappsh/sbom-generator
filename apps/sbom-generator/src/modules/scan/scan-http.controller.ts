import {
  Controller, Get, Post, Body, Param, Logger,
  NotFoundException, Res, Sse, MessageEvent,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam, ApiOkResponse, ApiCreatedResponse, ApiBody } from '@nestjs/swagger';
import { Observable, fromEvent } from 'rxjs';
import { map, take } from 'rxjs/operators';
import { Response } from 'express';
import { ScanService } from './scan.service';
import { CreateScanDto } from './dto/create-scan.dto';
import { ScanQueuedDto, ScanStatusDto } from './dto/scan-status.dto';

@ApiTags('SBOM')
@Controller('sbom')
export class ScanHttpController {
  private readonly logger = new Logger(ScanHttpController.name);

  constructor(private readonly scanService: ScanService) {}

  @Post('scans')
  @ApiOperation({ summary: 'Queue a new SBOM scan', description: 'Accepts a scan target and queues it. Returns a scanId immediately.' })
  @ApiBody({ type: CreateScanDto })
  @ApiCreatedResponse({ type: ScanQueuedDto })
  async queueScan(@Body() dto: CreateScanDto): Promise<ScanQueuedDto> {
    this.logger.log(`HTTP: Queue scan for ${dto.target}`);
    return this.scanService.queueScan(dto);
  }

  @Get('scans')
  @ApiOperation({ summary: 'List recent SBOM scan jobs' })
  @ApiOkResponse({ type: [ScanStatusDto] })
  async listScans(): Promise<ScanStatusDto[]> {
    return this.scanService.listScans();
  }

  @Get('scans/:id')
  @ApiOperation({ summary: 'Get scan status and metadata by ID' })
  @ApiParam({ name: 'id', description: 'Scan job UUID' })
  @ApiOkResponse({ type: ScanStatusDto })
  async getScanStatus(@Param('id') id: string): Promise<ScanStatusDto> {
    try {
      return await this.scanService.getScanStatus(id);
    } catch {
      throw new NotFoundException(`Scan ${id} not found`);
    }
  }

  /**
   * SSE endpoint — client receives one event when the scan reaches a terminal
   * state (complete or failed), then the connection closes.
   *
   * Connect with: EventSource('/sbom/scans/:id/events')
   */
  @Sse('scans/:id/events')
  @ApiOperation({ summary: 'SSE stream — fires once when scan completes or fails' })
  @ApiParam({ name: 'id', description: 'Scan job UUID' })
  sseEvents(@Param('id') id: string): Observable<MessageEvent> {
    this.logger.log(`SSE client subscribed for scan ${id}`);
    const subject = this.scanService.subscribeToScanEvents(id);

    return new Observable<MessageEvent>((subscriber) => {
      const sub = subject.subscribe({
        next: (event) => {
          subscriber.next({ data: event } as MessageEvent);
          subscriber.complete();
        },
        error: (err) => subscriber.error(err),
        complete: () => subscriber.complete(),
      });
      return () => sub.unsubscribe();
    });
  }

  @Get('scans/:id/report')
  @ApiOperation({ summary: 'Redirect to presigned MinIO download URL for the scan report' })
  @ApiParam({ name: 'id', description: 'Scan job UUID' })
  async downloadReport(@Param('id') id: string, @Res() res: Response): Promise<void> {
    try {
      const url = await this.scanService.getReportDownloadUrl(id);
      res.redirect(302, url);
    } catch (err) {
      throw new NotFoundException(err.message);
    }
  }
}

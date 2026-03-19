import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SbomFormat, SbomTargetType, ScanStatus, SbomScanJobEntity } from '../../database/entities/sbom-scan-job.entity';

export class ScanStatusDto {
  @ApiProperty()
  id: string;

  @ApiProperty({ enum: ScanStatus })
  status: ScanStatus;

  @ApiProperty()
  target: string;

  @ApiProperty({ enum: SbomTargetType })
  targetType: SbomTargetType;

  @ApiProperty({ enum: SbomFormat })
  format: SbomFormat;

  @ApiPropertyOptional()
  triggeredBy?: string;

  @ApiPropertyOptional()
  error?: string;

  @ApiPropertyOptional()
  failureReason?: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;

  @ApiPropertyOptional()
  completedAt?: Date;

  static fromEntity(entity: SbomScanJobEntity): ScanStatusDto {
    const dto = new ScanStatusDto();
    dto.id = entity.id;
    dto.status = entity.status;
    dto.target = entity.target;
    dto.targetType = entity.targetType;
    dto.format = entity.format;
    dto.triggeredBy = entity.triggeredBy;
    dto.error = entity.error;
    dto.failureReason = entity.failureReason;
    dto.createdAt = entity.createdAt;
    dto.updatedAt = entity.updatedAt;
    dto.completedAt = entity.completedAt;
    return dto;
  }
}

export class ScanQueuedDto {
  @ApiProperty()
  scanId: string;

  @ApiProperty({ enum: ScanStatus })
  status: ScanStatus;
}

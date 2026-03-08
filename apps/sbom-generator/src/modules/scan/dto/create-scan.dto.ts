import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { SbomFormat, SbomTargetType } from '../interfaces/sbom-engine.interface';

export class CreateScanDto {
  @ApiProperty({ description: 'Scan target (image name, file path, registry URL, etc.)' })
  @IsString()
  @IsNotEmpty()
  target: string;

  @ApiProperty({ enum: SbomTargetType, description: 'Type of the scan target' })
  @IsEnum(SbomTargetType)
  targetType: SbomTargetType;

  @ApiPropertyOptional({ enum: SbomFormat, description: 'SBOM output format', default: SbomFormat.CYCLONEDX_JSON })
  @IsEnum(SbomFormat)
  @IsOptional()
  format?: SbomFormat;

  @ApiPropertyOptional({ description: 'Who or what triggered this scan (user ID, service name, etc.)' })
  @IsString()
  @IsOptional()
  triggeredBy?: string;
}

export class ScanFileUploadedEventDto {
  objectKey: string;
  bucketName?: string;
  triggeredBy?: string;
  format?: SbomFormat;
}

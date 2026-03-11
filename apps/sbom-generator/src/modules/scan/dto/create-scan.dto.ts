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

  @ApiPropertyOptional({
    description:
      'Set to true when `target` is a raw object key inside the configured MinIO bucket ' +
      '(e.g. upload/release/1/file.msi). sbom-generator will generate a fresh presigned URL ' +
      'at execution time, so the stored key never expires. Also used by retry logic.',
  })
  @IsOptional()
  isStoredInBucket?: boolean;
}

export class ScanFileUploadedEventDto {
  objectKey: string;
  bucketName?: string;
  triggeredBy?: string;
  format?: SbomFormat;
}

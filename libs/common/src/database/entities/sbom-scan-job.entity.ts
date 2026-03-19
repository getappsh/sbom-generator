import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';

export enum ScanStatus {
  QUEUED = 'queued',
  RUNNING = 'running',
  COMPLETE = 'complete',
  FAILED = 'failed',
}

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

@Entity('sbom_scan_jobs')
export class SbomScanJobEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'enum', enum: ScanStatus, default: ScanStatus.QUEUED })
  status: ScanStatus;

  @Column()
  target: string;

  @Column({ type: 'enum', enum: SbomTargetType })
  targetType: SbomTargetType;

  @Column({ type: 'enum', enum: SbomFormat, default: SbomFormat.CYCLONEDX_JSON })
  format: SbomFormat;

  @Column({ nullable: true })
  minioKey: string;

  @Column({ default: false })
  isStoredInBucket: boolean;

  @Column({ nullable: true, type: 'text' })
  error: string;

  @Column({ nullable: true })
  failureReason: string;

  @Column({ nullable: true })
  triggeredBy: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ nullable: true, type: 'timestamptz' })
  completedAt: Date;
}

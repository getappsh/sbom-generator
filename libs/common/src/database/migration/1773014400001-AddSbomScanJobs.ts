import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddSbomScanJobs1773014400001 implements MigrationInterface {
  name = 'AddSbomScanJobs1773014400001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DO $$ BEGIN
        CREATE TYPE "public"."sbom_scan_jobs_status_enum" AS ENUM ('queued', 'running', 'complete', 'failed');
      EXCEPTION WHEN duplicate_object THEN null;
      END $$;
    `);
    await queryRunner.query(`
      DO $$ BEGIN
        CREATE TYPE "public"."sbom_scan_jobs_targettype_enum" AS ENUM ('docker', 'registry', 'file', 'dir', 'oci-archive');
      EXCEPTION WHEN duplicate_object THEN null;
      END $$;
    `);
    await queryRunner.query(`
      DO $$ BEGIN
        CREATE TYPE "public"."sbom_scan_jobs_format_enum" AS ENUM ('syft-json', 'spdx-json', 'cyclonedx-json', 'table', 'text');
      EXCEPTION WHEN duplicate_object THEN null;
      END $$;
    `);
    await queryRunner.query(`
      CREATE TABLE "sbom_scan_jobs" (
        "id"            UUID NOT NULL DEFAULT uuid_generate_v4(),
        "status"        "public"."sbom_scan_jobs_status_enum" NOT NULL DEFAULT 'queued',
        "target"        character varying NOT NULL,
        "targetType"    "public"."sbom_scan_jobs_targettype_enum" NOT NULL,
        "format"        "public"."sbom_scan_jobs_format_enum" NOT NULL DEFAULT 'cyclonedx-json',
        "minioKey"      character varying,
        "error"         text,
        "failureReason" character varying,
        "triggeredBy"   character varying,
        "createdAt"     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
        "updatedAt"     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
        "completedAt"   TIMESTAMP WITH TIME ZONE,
        CONSTRAINT "PK_sbom_scan_jobs" PRIMARY KEY ("id")
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "sbom_scan_jobs"`);
    await queryRunner.query(`DROP TYPE "public"."sbom_scan_jobs_format_enum"`);
    await queryRunner.query(`DROP TYPE "public"."sbom_scan_jobs_targettype_enum"`);
    await queryRunner.query(`DROP TYPE "public"."sbom_scan_jobs_status_enum"`);
  }
}

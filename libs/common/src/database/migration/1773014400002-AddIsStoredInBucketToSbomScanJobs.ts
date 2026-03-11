import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddIsStoredInBucketToSbomScanJobs1773014400002 implements MigrationInterface {
  name = 'AddIsStoredInBucketToSbomScanJobs1773014400002';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "sbom_scan_jobs"
      ADD COLUMN IF NOT EXISTS "isStoredInBucket" boolean NOT NULL DEFAULT false
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "sbom_scan_jobs"
      DROP COLUMN IF EXISTS "isStoredInBucket"
    `);
  }
}

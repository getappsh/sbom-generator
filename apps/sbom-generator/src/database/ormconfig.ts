import 'dotenv/config';
import { DataSource } from 'typeorm';
import { SbomScanJobEntity } from '../modules/scan/scan.entity';
import { AddSbomScanJobs1773014400001 } from '@app/common/database/migration/1773014400001-AddSbomScanJobs';
import { AddIsStoredInBucketToSbomScanJobs1773014400002 } from '@app/common/database/migration/1773014400002-AddIsStoredInBucketToSbomScanJobs';

const region = process.env.REGION ? `_${process.env.REGION}` : '';
let migrationsRun = true;
if (process.env.MIGRATION_RUN) {
  migrationsRun = process.env.MIGRATION_RUN === 'true';
}

const ormConfig = new DataSource({
  type: 'postgres',
  host: process.env.POSTGRES_HOST ?? 'localhost',
  port: Number(process.env.POSTGRES_PORT ?? 5432),
  database: `${process.env.POSTGRES_DB ?? 'get_app'}${region}`,
  username: process.env.POSTGRES_USER ?? 'postgres',
  password: process.env.POSTGRES_PASSWORD,
  entities: [SbomScanJobEntity],
  migrations: [AddSbomScanJobs1773014400001, AddIsStoredInBucketToSbomScanJobs1773014400002],
  migrationsRun,
  synchronize: false,
});

export default ormConfig;

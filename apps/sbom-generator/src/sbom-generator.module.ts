import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { LoggerModule } from '@app/common/logger/logger.module';
import { ApmModule } from '@app/common/apm/apm.module';
import { ScanModule } from './modules/scan/scan.module';
import { SbomScanJobEntity } from '@app/common/database/entities';
import { AddSbomScanJobs1773014400001 } from '@app/common/database/migration/1773014400001-AddSbomScanJobs';
import { AddIsStoredInBucketToSbomScanJobs1773014400002 } from '@app/common/database/migration/1773014400002-AddIsStoredInBucketToSbomScanJobs';
import { AddSbomReportPathToReleaseArtifact1773110000000 } from '@app/common/database/migration/1773110000000-AddSbomReportPathToReleaseArtifact';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    LoggerModule.forRoot({
      httpCls: false,
      jsonLogger: process.env.LOGGER_FORMAT === 'JSON',
      name: 'SbomGenerator',
    }),
    ApmModule,
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => {
        const region = config.get('REGION') ? `_${config.get('REGION')}` : '';
        return {
          type: 'postgres',
          host: config.get('POSTGRES_HOST') ?? 'localhost',
          port: Number(config.get('POSTGRES_PORT') ?? 5432),
          database: `${config.get('POSTGRES_DB') ?? 'get_app'}${region}`,
          username: config.get('POSTGRES_USER') ?? 'postgres',
          password: config.get('POSTGRES_PASSWORD'),
          entities: [SbomScanJobEntity],
          migrations: [AddSbomScanJobs1773014400001, AddIsStoredInBucketToSbomScanJobs1773014400002, AddSbomReportPathToReleaseArtifact1773110000000],
          migrationsRun: config.get('MIGRATION_RUN') !== 'false',
          synchronize: false,
        };
      },
      inject: [ConfigService],
    }),
    ScanModule,
  ],
})
export class SbomGeneratorModule {}

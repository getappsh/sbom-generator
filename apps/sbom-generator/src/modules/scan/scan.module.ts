import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { ScanService } from './scan.service';
import { ScanController } from './scan.controller';
import { SbomScanJobEntity } from './scan.entity';
import { SyftEngine } from './engines/syft.engine';
import { SBOM_ENGINE } from './interfaces/sbom-engine.interface';
import { MinioClientService } from '@app/common/AWS/minio-client.service';

@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forFeature([SbomScanJobEntity]),
  ],
  controllers: [ScanController],
  providers: [
    ScanService,
    MinioClientService,
    {
      provide: SBOM_ENGINE,
      useClass: SyftEngine,
    },
  ],
})
export class ScanModule {}

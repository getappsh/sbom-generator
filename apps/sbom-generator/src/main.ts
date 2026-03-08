import * as dotenv from 'dotenv';
dotenv.config();
import apm from 'nestjs-elastic-apm';

import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions } from '@nestjs/microservices';
import { SbomGeneratorModule } from './sbom-generator.module';
import { CustomRpcExceptionFilter } from './rpc-exception.filter';
import { MSType, MicroserviceName, MicroserviceType, getClientConfig } from '@app/common/microservice-client';
import { GET_APP_LOGGER } from '@app/common/logger/logger.module';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    SbomGeneratorModule,
    {
      ...getClientConfig(
        {
          type: MicroserviceType.SBOM_GENERATOR,
          name: MicroserviceName.SBOM_GENERATOR_SERVICE,
        },
        MSType[process.env.MICRO_SERVICE_TYPE ?? ''],
      ),
      bufferLogs: true,
    },
  );

  app.useLogger(app.get(GET_APP_LOGGER));
  app.useGlobalFilters(new CustomRpcExceptionFilter());
  app.listen();
}

bootstrap();

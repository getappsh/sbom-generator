import * as dotenv from 'dotenv';
dotenv.config();
import apm from 'nestjs-elastic-apm';

import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions } from '@nestjs/microservices';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { SbomGeneratorModule } from './sbom-generator.module';
import { CustomRpcExceptionFilter } from './rpc-exception.filter';
import { MSType, MicroserviceName, MicroserviceType, getClientConfig } from '@app/common/microservice-client';
import { GET_APP_LOGGER } from '@app/common/logger/logger.module';

async function bootstrap() {
  // Hybrid application: handles both HTTP (REST/SSE) and microservice (Kafka/Socket) transports
  const app = await NestFactory.create(SbomGeneratorModule);

  // Connect microservice transport (Kafka or TCP Socket depending on MICRO_SERVICE_TYPE)
  app.connectMicroservice<MicroserviceOptions>({
    ...getClientConfig(
      {
        type: MicroserviceType.SBOM_GENERATOR,
        name: MicroserviceName.SBOM_GENERATOR_SERVICE,
      },
      MSType[process.env.MICRO_SERVICE_TYPE ?? ''],
    ),
  });

  app.useLogger(app.get(GET_APP_LOGGER));
  app.useGlobalFilters(new CustomRpcExceptionFilter());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  // Swagger
  const config = new DocumentBuilder()
    .setTitle('SBOM Generator')
    .setDescription('REST API for SBOM report generation')
    .setVersion('1.0.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  await app.startAllMicroservices();
  await app.listen(Number(process.env.SBOM_GENERATOR_HTTP_PORT ?? 3008));

  console.log(`SBOM Generator is running on port ${process.env.SBOM_GENERATOR_HTTP_PORT ?? 3008}`);
}

bootstrap();

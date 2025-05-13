import { ConfigService } from '@nestjs/config'; // Import ConfigService
import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser'; // For cookie-based auth
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  const port = configService.get<number>('PORT') || 3001;
  const frontendUrl = configService.get<string>('FRONTEND_URL');
  const nodeEnv = configService.get<string>('NODE_ENV');

  app.use(cookieParser());

  if (frontendUrl) {
    app.enableCors({
      origin: frontendUrl,
      credentials: true,
    });
  } else if (nodeEnv === 'development') {
    app.enableCors({
      origin: true,
      credentials: true,
    });
    console.warn(
      'WARN: FRONTEND_URL not set. Using lenient CORS settings for development.',
    );
  }

  await app.listen(port);
  console.log(`Application is running on: ${await app.getUrl()}`);
  console.log(`Environment: ${nodeEnv}`);
  if (frontendUrl) {
    console.log(`CORS enabled for: ${frontendUrl}`);
  }
}
// eslint-disable-next-line @typescript-eslint/no-floating-promises
bootstrap();

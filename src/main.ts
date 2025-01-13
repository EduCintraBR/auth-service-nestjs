import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as session from 'express-session';


async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('OAuth2 Server')
    .setDescription('Servidor de autenticação OAuth2')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));

  // Session Middleware
  app.use(
    session({  // se estiver usando `import * as session`
      secret: process.env.COOKIE_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: Number(process.env.MILISSECONDS_AGE_SESSION_COOKIE),
        httpOnly: true,
        secure: false, // true se estiver usando HTTPS em produção
      },
    }),
  );

  await app.listen(process.env.PORT ?? 3000);
}

bootstrap();

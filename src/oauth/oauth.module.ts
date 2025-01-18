import { Module } from '@nestjs/common';
import { OauthService } from './oauth.service';
import { OauthController } from './oauth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { UsersModule } from '../users/users.module';
import { ClientsModule } from '../clients/clients.module';
import { AuditLogModule } from '../audit-log/audit-log.module';
import { UsersService } from '../users/users.service';
import { ClientsService } from '../clients/clients.service';
import { AuditLogService } from '../audit-log/audit-log.service';
import { AuthController } from './auth.controller';

@Module({
  imports: [PrismaModule, UsersModule, ClientsModule, AuditLogModule],
  providers: [OauthService, UsersService, ClientsService, AuditLogService],
  controllers: [OauthController, AuthController],
})
export class OauthModule {}

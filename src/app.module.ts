import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { RolesModule } from './roles/roles.module';
import { ClientsModule } from './clients/clients.module';
import { OauthModule } from './oauth/oauth.module';
import { AuditLogModule } from './audit-log/audit-log.module';

@Module({
  imports: [UsersModule, RolesModule, ClientsModule, OauthModule, AuditLogModule],
  controllers: [],
  providers: [],
})
export class AppModule {}

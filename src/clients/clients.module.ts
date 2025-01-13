import { Module } from '@nestjs/common';
import { ClientsService } from './clients.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  providers: [ClientsService]
})

export class ClientsModule {}

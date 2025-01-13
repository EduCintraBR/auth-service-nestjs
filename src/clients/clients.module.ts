import { Module } from '@nestjs/common';
import { ClientsService } from './clients.service';

@Module({
  providers: [ClientsService]
})
export class ClientsModule {}

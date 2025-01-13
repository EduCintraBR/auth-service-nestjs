import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { randomBytes } from 'crypto';

@Injectable()
export class ClientsService {
  constructor(private readonly prisma: PrismaService) {}

  // Cria um novo client
  async createClient(name: string, grantTypes: string[], redirectUris: string[]) {
    // Gera um clientId aleatório
    const clientId = this.generateRandomString(20);
    // Gera um clientSecret (se for confiável)
    const clientSecret = this.generateRandomString(30);

    // Salva no banco
    const client = await this.prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecret,
        redirectUris,
        grants: grantTypes,
      },
    });

    // Retorna o client com secrets
    return client;
  }

  // Busca client por clientId
  async findByClientId(clientId: string) {
    return this.prisma.oAuthClient.findUnique({
      where: { clientId },
    });
  }

  // Se for querer atualizar
  async updateClient(clientId: string, updates: { grants?: string[]; redirectUris?: string[] }) {
    const client = await this.findByClientId(clientId);
    
    if (!client) {
      throw new NotFoundException('Client não encontrado');
    }

    return this.prisma.oAuthClient.update({
      where: { clientId },
      data: {
        grants: updates.grants ?? client.grants,
        redirectUris: updates.redirectUris ?? client.redirectUris,
      },
    });
  }

  private generateRandomString(length: number) {
    return randomBytes(length).toString('hex').slice(0, length);
  }
}
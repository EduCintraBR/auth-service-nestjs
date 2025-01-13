import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class RolesService {
  constructor(private readonly prisma: PrismaService) {}

  // Cria uma nova role (ex.: 'ADMIN', 'USER')
  async createRole(name: string) {
    // Checar se já existe
    const existing = await this.prisma.role.findUnique({
      where: { name },
    });
    
    if (existing) {
      throw new ConflictException('Role já existe');
    }

    return this.prisma.role.create({
      data: { name },
    });
  }

  // Busca role por nome
  async findByName(name: string) {
    return this.prisma.role.findUnique({ where: { name } });
  }

  // Associa role a um usuário
  async addRoleToUser(userId: string, roleName: string) {
    // Achar role
    const role = await this.findByName(roleName);

    if (!role) {
      throw new NotFoundException('Role não encontrada');
    }

    // Criar UserRole
    return this.prisma.userRole.create({
      data: {
        userId,
        roleId: role.id,
      },
    });
  }

  // Remove role de um usuário
  async removeRoleFromUser(userId: string, roleName: string) {
    const role = await this.findByName(roleName);

    if (!role) {
      throw new NotFoundException('Role não encontrada');
    }
    
    return this.prisma.userRole.delete({
      where: {
        userId_roleId: {
          userId,
          roleId: role.id,
        },
      },
    });
  }

  // Lista roles de um usuário
  async getUserRoles(userId: string) {
    return this.prisma.userRole.findMany({
      where: { userId },
      include: {
        role: true,
      },
    });
  }
}
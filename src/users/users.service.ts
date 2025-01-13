import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  private readonly SALT_ROUNDS = 10;

  constructor(private readonly prisma: PrismaService) {}

  // Cria um novo usuário (por exemplo, se você quiser registrar pela sua aplicação)
  async createUser(email: string, plainPassword: string) {
    // Verificar se email já existe
    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictException('Email já cadastrado');
    }

    // Gerar hash da senha
    const passwordHash = await bcrypt.hash(plainPassword, this.SALT_ROUNDS);

    const user = await this.prisma.user.create({
      data: {
        email,
        passwordHash,
      },
      select: { 
            id: true, 
            email: true, 
            passwordHash: true 
        }
    });

    return user;
  }

  async findAll(onlyActive?: boolean) {
    if (onlyActive ?? true) {
        return await this.prisma.user.findMany({
            where: { isActive: onlyActive }
        });
    }

    return this.prisma.user.findMany();
  }

  // Busca usuário pelo ID
  async findById(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    return user;
  }

  // Busca usuário pelo email
  async findByEmail(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    return user; 
  }

  // Atualiza a senha do usuário
  async updatePassword(userId: string, newPassword: string) {
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    const passwordHash = await bcrypt.hash(newPassword, this.SALT_ROUNDS);

    return this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });
  }

  // Soft delete
  async deactivateUser(userId: string) {
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    return this.prisma.user.update({
      where: { id: userId },
      data: { isActive: false },
    });
  }

  // Função auxiliar para validar senha
  async validatePassword(userId: string, plainPassword: string) {
    const user = await this.findById(userId);
    if (!user) return false;
    return bcrypt.compare(plainPassword, user.passwordHash);
  }
}

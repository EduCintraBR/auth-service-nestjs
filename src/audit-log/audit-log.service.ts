import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuditLogService {
  constructor(private readonly prisma: PrismaService) {}

  async logAction(action: string, userId?: string, description?: string) {
    return this.prisma.auditLog.create({
      data: {
        action,
        userId: userId ?? null,
        description: description ?? null,
      },
    });
  }
}
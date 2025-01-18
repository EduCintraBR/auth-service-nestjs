import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { UsersService } from 'src/users/users.service';
import { ClientsService } from 'src/clients/clients.service';
import { AuditLogService } from 'src/audit-log/audit-log.service';
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { add, addMinutes } from 'date-fns';
import * as crypto from 'crypto';
import { OAuthCreateClient } from './dto/oauth-create-client.dto';

@Injectable()
export class OauthService {
  private readonly JWT_SECRET = process.env.JWT_SECRET;
  private readonly ACCESS_TOKEN_EXP = process.env.ACCESS_TOKEN_EXP || '1h';
  private readonly REFRESH_TOKEN_EXP_DAYS =
    process.env.REFRESH_TOKEN_EXP_DAYS || 10;
  private readonly AUTH_CODE_EXPIRES_MIN = process.env.AUTH_CODE_EXPIRES_MIN;

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly clientsService: ClientsService,
    private readonly auditLogService: AuditLogService,
  ) {}

  // =======================
  // CREATE CLIENT
  // =======================
  async createClient(data: OAuthCreateClient) {
    const { clientId, clientSecret, redirectUris, grants } = data;
    const result = await this.prisma.oAuthClient.create({
      data: { clientId, clientSecret, redirectUris, grants },
      select: { id: true, clientId: true, redirectUris: true },
    });

    return result;
  }

  // =======================
  // PASSWORD GRANT
  // =======================
  async passwordGrantFlow(
    clientId: string,
    clientSecret: string,
    username: string,
    password: string,
  ) {
    // 1) Validar client
    const client = await this.clientsService.findByClientId(clientId);
    if (!client) {
      throw new UnauthorizedException('Client inválido');
    }
    if (!client.grants.includes('password')) {
      throw new UnauthorizedException('Este client não suporta password grant');
    }
    if (client.clientSecret && client.clientSecret !== clientSecret) {
      throw new UnauthorizedException('Secret inválido');
    }

    // 2) Validar usuário
    const user = await this.usersService.findByEmail(username);
    if (!user || !user.isActive) {
      throw new UnauthorizedException('Usuário não encontrado ou inativo');
    }
    const isPasswordValid = await this.usersService.validatePassword(
      user.id,
      password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Senha incorreta');
    }

    // 3) Gerar tokens
    const accessToken = this.generateAccessToken(user.id, client.clientId);
    const refreshToken = await this.generateRefreshToken(
      user.id,
      client.clientId,
    );

    // Registrar log
    await this.auditLogService.logAction(
      'LOGIN',
      user.id,
      'Login via password grant',
    );

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken.token,
      expires_in: Number(this.ACCESS_TOKEN_EXP),
    };
  }

  // =======================
  // AUTHORIZATION CODE (simplificado)
  // =======================
  async createAuthCode(
    userId: string,
    clientId: string,
    redirectUri: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
  ): Promise<string> {
    // gera code random
    const code = randomBytes(16).toString('hex');
    const expiresAt = add(new Date(), {
      minutes: Number(this.AUTH_CODE_EXPIRES_MIN) || 5,
    });

    await this.prisma.authCode.create({
      data: {
        code,
        redirectUri,
        userId,
        clientId,
        expiresAt,
        codeChallenge: codeChallenge ?? null,
        codeChallengeMethod: codeChallengeMethod ?? null,
      },
    });

    return code;
  }

  async validateAuthorizeRequest(clientId: string, redirectUri: string) {
    // Verificar client
    const client = await this.clientsService.findByClientId(clientId);
    if (!client || !client.grants.includes('authorization_code')) {
      throw new UnauthorizedException('Client não suporta authorization_code');
    }
    if (redirectUri && !client.redirectUris.includes(redirectUri)) {
      throw new BadRequestException('redirectUri inválido');
    }
    // Retornar client
    return client;
  }

  // Trocar code por tokens
  async authorizationCodeFlow(
    clientId: string,
    clientSecret: string,
    redirectUri: string,
    code?: string,
    codeVerifier?: string,
  ) {
    // 1) Ver client, grants, secret
    const client = await this.clientsService.findByClientId(clientId);
    if (!client || !client.grants.includes('authorization_code')) {
      throw new UnauthorizedException('Client não suporta authorization_code');
    }
    if (client.clientSecret && client.clientSecret !== clientSecret) {
      throw new UnauthorizedException('Secret inválido');
    }

    // 2) Buscar authCode
    const authCode = await this.prisma.authCode.findUnique({ where: { code } });
    if (!authCode) {
      throw new UnauthorizedException('Código inexistente');
    }

    // Checagem PKCE
    // PKCE check
    if (authCode.codeChallenge) {
      // Se codeChallengeMethod = 'S256'
      if (authCode.codeChallengeMethod === 'S256') {
        const hashed = this.sha256base64url(codeVerifier);
        if (hashed !== authCode.codeChallenge) {
          throw new UnauthorizedException('PKCE verificação falhou');
        }
      } else {
        // 'plain'
        if (codeVerifier !== authCode.codeChallenge) {
          throw new UnauthorizedException('PKCE verificação falhou');
        }
      }
    }

    if (authCode.clientId !== client.clientId) {
      throw new UnauthorizedException('Código pertence a outro client');
    }
    if (redirectUri && authCode.redirectUri !== redirectUri) {
      throw new UnauthorizedException('redirectUri não combina');
    }
    if (authCode.expiresAt < new Date()) {
      throw new UnauthorizedException('Código expirado');
    }

    // 3) Apagar o code (pode ser single-use)
    await this.prisma.authCode.delete({ where: { code } });

    // 4) Gerar tokens
    const accessToken = await this.generateAccessToken(
      authCode.userId,
      client.clientId,
    );
    const refreshToken = await this.generateRefreshToken(
      authCode.userId,
      client.clientId,
    );

    // Log
    await this.auditLogService.logAction(
      'LOGIN',
      authCode.userId,
      'Login via authorization_code flow',
    );

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken.token,
      expires_in: this.ACCESS_TOKEN_EXP,
    };
  }

  // =======================
  // REFRESH TOKEN
  // =======================
  async refreshTokenFlow(
    clientId: string,
    clientSecret: string,
    refreshTokenStr: string,
  ) {
    const client = await this.clientsService.findByClientId(clientId);
    if (!client || !client.grants.includes('refresh_token')) {
      throw new UnauthorizedException('Client não suporta refresh_token');
    }
    if (client.clientSecret && client.clientSecret !== clientSecret) {
      throw new UnauthorizedException('Secret inválido');
    }

    const refreshToken = await this.prisma.refreshToken.findUnique({
      where: { token: refreshTokenStr },
    });
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token inválido');
    }
    if (refreshToken.clientId !== client.id) {
      throw new UnauthorizedException('Token pertence a outro client');
    }
    if (refreshToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token expirado');
    }

    // Buscar user e gera novo access token
    const accessToken = this.generateAccessToken(
      refreshToken.userId,
      client.clientId,
    );
    // Gerar um novo refresh token
    const newRefreshToken = await this.generateRefreshToken(
      refreshToken.userId,
      client.clientId,
    );

    // Log
    await this.auditLogService.logAction('REFRESH_TOKEN', refreshToken.userId);

    return {
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: newRefreshToken.token,
      expires_in: Number(this.ACCESS_TOKEN_EXP),
    };
  }

  // =======================
  // CLIENT CREDENTIALS
  // =======================
  async clientCredentialsFlow(clientId: string, clientSecret: string) {
    // 1) Validar se o client existe
    const client = await this.clientsService.findByClientId(clientId);
    if (!client) {
      throw new UnauthorizedException('Client não encontrado ou inválido.');
    }

    // 2) Verificar se o client suporta 'client_credentials' no campo grants
    if (!client.grants.includes('client_credentials')) {
      throw new UnauthorizedException(
        'Este client não suporta o fluxo client_credentials.',
      );
    }

    // 3) Comparar o client_secret (se houver)
    // (seu schema permite null se for PKCE, mas aqui exige secret)
    if (!client.clientSecret || client.clientSecret !== clientSecret) {
      throw new UnauthorizedException('client_secret inválido.');
    }

    // 4) Gerar o access_token (JWT)
    // Não há "usuário" real neste fluxo, então definimos sub=clientId ou algo do tipo
    const payload = {
      sub: clientId,
      type: 'client_credentials',
    };

    // Exemplo: se você tiver em OauthService uma variável JWT_SECRET e tempo de expiração
    const accessToken = jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.ACCESS_TOKEN_EXP, // ou o valor que você quiser
    });

    // Log
    await this.auditLogService.logAction('CLIENT_CREDENTIALS', clientId);

    // 5) Retornar o objeto no padrão OAuth (pode acrescentar o scope se quiser)
    return {
      token_type: 'Bearer',
      access_token: accessToken,
      expires_in: this.ACCESS_TOKEN_EXP,
    };
  }

  // =======================
  // VALIDATE TOKEN - INTROSPECT
  // =======================
  async introspectToken(token: string) {
    try {
      // Verificar a assinatura e decodificar o payload
      const payload = jwt.verify(token, this.JWT_SECRET) as any;

      // Montando a resposta conforme o RFC 7662
      return {
        active: true,
        client_id: payload.clientId,
        sub: payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        claims: payload.claims,
      };
    } catch (err) {
      return { active: false };
    }
  }

  async invalidateRefreshToken(userId: string) {}

  // =======================
  // Funções Auxiliares
  // =======================
  private async generateAccessToken(userId: string, clientId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        roles: {
          include: {
            role: {
              select: { name: true },
            },
          },
        },
        claims: true,
      },
    });
    if (!user || !user.isActive) {
      throw new Error('Usuário não encontrado ou inativo');
    }

    // Extrai os nomes das roles a partir do relacionamento UserRole -> Role
    const roles = user.roles.map((userRole) => userRole.role.name);

    // Caso queira transformar as claims em um objeto para facilitar o acesso
    const claims = user.claims.reduce((acc, claim) => {
      acc[claim.name] = claim.value;
      return acc;
    }, {});

    const payload = {
      id: user.id,
      email: user.email,
      clientId,
      roles,
      claims,
    };

    const token = jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.ACCESS_TOKEN_EXP,
    });
    return token;
  }

  private async generateRefreshToken(userId: string, clientId: string) {
    const token = randomBytes(32).toString('hex');
    const expiresAt = add(new Date(), {
      days: Number(this.REFRESH_TOKEN_EXP_DAYS),
    });

    const refreshToken = await this.prisma.refreshToken.create({
      data: {
        token,
        userId: userId,
        clientId: clientId,
        expiresAt,
      },
    });

    return refreshToken;
  }

  private sha256base64url(value: string): string {
    const hash = crypto.createHash('sha256').update(value).digest();

    // base64url encode
    return hash
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}

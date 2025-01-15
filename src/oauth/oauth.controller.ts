import {
  Controller,
  Post,
  Get,
  Body,
  Query,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
} from '@nestjs/common';
import { OauthService } from './oauth.service';
import { OAuthRequestBodyDto } from './dto/oauth-request-body.dto';
import { OAuthCreateClient } from './dto/oauth-create-client.dto';
import { OAuthAccessTokenIntrospectDto } from './dto/oauth-access-token-introspect.dto';

@Controller('oauth')
export class OauthController {
  constructor(private readonly oauthService: OauthService) {}

  // =============== /oauth/instrospect ===============
  @Post('introspect')
  @HttpCode(HttpStatus.OK)
  async introspect(@Body() body: OAuthAccessTokenIntrospectDto) {
    const token = body.access_token;
    if (!token) {
      return { active: false };
    }
    // Chama método no oauthService
    return this.oauthService.introspectToken(token);
  }

  // =============== /oauth/token ===============
  @Post('token')
  @HttpCode(HttpStatus.OK)
  async token(@Body() body: OAuthRequestBodyDto) {
    const { grant_type } = body;

    switch (grant_type) {
      case 'password':
        return this.oauthService.passwordGrantFlow(
          body.client_id,
          body.client_secret,
          body.username,
          body.password,
        );

      case 'authorization_code':
        return this.oauthService.authorizationCodeFlow(
          body.client_id,
          body.client_secret,
          body.redirect_uri,
          body.code,
          body.code_verifier,
        );

      case 'refresh_token':
        return this.oauthService.refreshTokenFlow(
          body.client_id,
          body.client_secret,
          body.refresh_token,
        );

      case 'client_credentials':
        return this.oauthService.clientCredentialsFlow(
          body.client_id,
          body.client_secret,
        );

      default:
        throw new UnauthorizedException('grant_type não suportado');
    }
  }

  // =============== /oauth/authorize (GET) ===============
  @Get('authorize')
  async authorize(
    @Query('response_type') responseType: string,
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('state') state: string,
    @Query('code_challenge') codeChallenge: string,
    @Query('code_challenge_method') codeChallengeMethod: string,
    @Res() res: any,
    @Req() req: any,
  ) {
    if (responseType !== 'code') {
      throw new UnauthorizedException('response_type não suportado (use code)');
    }

    const userId = req.session?.userId || null;
    if (!userId) {
      // Redirecionar para uma página de login, depois voltar
      return res.redirect(
        `/login?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=${codeChallengeMethod}`,
      );
    }

    // Validar request
    await this.oauthService.validateAuthorizeRequest(clientId, redirectUri);

    // Criar o code
    const code = await this.oauthService.createAuthCode(
      userId,
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
    );

    // Redirecionar de volta para redirectUri com o code
    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (state) {
      redirectUrl.searchParams.set('state', state);
    }

    return res.redirect(redirectUrl.toString());
  }

  // =============== /oauth/create-client ===============
  @Post('create-client')
  async createClient(@Body() data: OAuthCreateClient) {
    return await this.oauthService.createClient(data);
  }
}

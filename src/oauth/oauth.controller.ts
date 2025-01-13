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
    UnauthorizedException 
  } from '@nestjs/common';
  import { OauthService } from './oauth.service';
import { OAuthRequestBodyDto } from './dto/oauth-request-body.dto';
  
  // Crie DTOs para request se preferir (por simplicidade, uso @Body() e @Query() diretos)
  
  @Controller('oauth')
  export class OauthController {
    constructor(private readonly oauthService: OauthService) {}
  
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
            body.code,
            body.redirect_uri
          );
  
        case 'refresh_token':
          return this.oauthService.refreshTokenFlow(
            body.client_id,
            body.client_secret,
            body.refresh_token,
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
      @Res() res: any,
      @Req() req: any,
    ) {
      // Exemplo: GET /oauth/authorize?response_type=code&client_id=abc&redirect_uri=http://localhost:3000/callback&state=123
      if (responseType !== 'code') {
        throw new UnauthorizedException('response_type não suportado (use code)');
      }
  
      // Precisaria exibir uma tela de login ou, se o user já estiver logado, associar
      // AQUI estamos simplificando, assumindo que o userId=... vem de um cookie ou algo do tipo
      // Em um caso real, você teria uma UI de login e consent.
      
      const userId = req.session?.userId || null; // Exemplo simplificado
      if (!userId) {
        // Redirecionar para uma página de login, depois voltar
        return res.redirect(`/login?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}`);
      }
  
      // Validar request
      await this.oauthService.validateAuthorizeRequest(clientId, redirectUri);
  
      // Criar o code
      const code = await this.oauthService.createAuthCode(userId, clientId, redirectUri);
  
      // Redirecionar de volta para redirectUri com o code
      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.set('code', code);
      if (state) {
        redirectUrl.searchParams.set('state', state);
      }
  
      return res.redirect(redirectUrl.toString());
    }
}
  
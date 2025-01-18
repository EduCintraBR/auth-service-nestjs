import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { UsersService } from '../users/users.service';
import { OauthService } from './oauth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly usersService: UsersService,
    private readonly oauthService: OauthService,
  ) {}

  @Get('login')
  showLoginForm(
    @Query('client_id') clientId: string,
    @Query('redirect_uri') redirectUri: string,
    @Query('state') state: string,
    @Query('code_challenge') code_challenge: string,
    @Query('code_challenge_method') code_challenge_method: string,
    @Res() res: Response,
  ) {
    return res.render('login', {
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge,
      code_challenge_method,
      errorMessage: null,
    });
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async doLogin(
    @Body() body,
    @Query() query,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const {
      email,
      password,
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method,
    } = body;

    try {
      const user = await this.usersService.findByEmail(email);
      if (!user) {
        return res.status(HttpStatus.BAD_REQUEST).render('login', {
          client_id,
          redirect_uri,
          state,
          code_challenge,
          code_challenge_method,
          errorMessage: 'Credenciais inválidas. Tente novamente.',
        });
      }

      const isValid = await this.usersService.validatePassword(
        user.id,
        password,
      );
      if (!isValid) {
        return res.status(HttpStatus.BAD_REQUEST).render('login', {
          client_id,
          redirect_uri,
          state,
          code_challenge,
          code_challenge_method,
          errorMessage: 'Credenciais inválidas. Tente novamente.',
        });
      }

      // Criação da sessão
      req.session.userId = user.id;

      // Redirecionar de volta para /oauth/authorize
      const url = `/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}&code_challenge=${code_challenge}&code_challenge_method=${code_challenge_method}`;
      return res.redirect(url);
    } catch (error) {
      // Renderizar a página com mensagem genérica de erro
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).render('login', {
        client_id,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        errorMessage: 'Ocorreu um erro. Por favor, tente novamente mais tarde.',
      });
    }
  }

  @Post('logout')
  logout(@Req() req: Request, @Res() res: Response) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Erro ao destruir sessão:', err);
        return res.status(500).send('Erro ao realizar logout.');
      }
      req.session.userId = null;
      this.oauthService.invalidateRefreshToken('');
      res.status(200).send('Logout realizado com sucesso.');
    });
  }
}

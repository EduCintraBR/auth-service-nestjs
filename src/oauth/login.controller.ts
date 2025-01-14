import { BadRequestException, Body, Controller, Get, HttpCode, HttpStatus, Post, Query, Req, Res } from "@nestjs/common";
import { Response } from 'express';
import { UsersService } from "../users/users.service";

@Controller('login')
export class LoginController {

    constructor(private readonly usersService: UsersService) {}

    @Get()
    showLoginForm(
      @Query('client_id') clientId: string,
      @Query('redirect_uri') redirectUri: string,
      @Query('state') state: string,
      @Query('code_challenge') code_challenge: string,
      @Query('code_challenge_method') code_challenge_method: string,
      @Res() res: Response
    ) {
      return res.render('login', { client_id: clientId, redirect_uri: redirectUri, state, code_challenge, code_challenge_method });
    }
    
    @Post()
    @HttpCode(HttpStatus.OK)
    async doLogin(@Body() body, @Query() query, @Req() req, @Res() res) {
      const { email, password, client_id, redirect_uri, state, code_challenge, code_challenge_method } = body;

      // Validar user
      const user = await this.usersService.findByEmail(email);
      if (!user) {
        throw new BadRequestException("Credenciais inválidas.");
      }
      const isValid = await this.usersService.validatePassword(user.id, password);
      if (!isValid) {
        throw new BadRequestException("Credenciais inválidas.");
      }
    
      // Cria session
      req.session.userId = user.id;
    
      // Redirecionar de volta p/ /oauth/authorize
      const url = `/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}&code_challenge=${code_challenge}&code_challenge_method=${code_challenge_method}`;
      return res.redirect(url);
    }    
}
import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query, Req, Res } from "@nestjs/common";
import { UsersService } from "../users/users.service";

@Controller('login')
export class LoginController {

    constructor(private readonly usersService: UsersService) {}

    @Get()
    async showLoginForm(@Query() query, @Res() res) {
      // Renderiza um HTML com form ou redireciona para um front-end 
      // Exemplo: res.render('login', { client_id: query.client_id, ... })
    }
    
    @Post()
    @HttpCode(HttpStatus.OK)
    async doLogin(@Body() body, @Req() req, @Res() res) {
      const { email, password, client_id, redirect_uri, state } = body;
      
      // Validar user
      const user = await this.usersService.findByEmail(email);
      if (!user) {
        // exibir erro
      }
      const isValid = await this.usersService.validatePassword(user.id, password);
      if (!isValid) {
        // erro
      }
    
      // Cria session
      req.session.userId = user.id;
      // SALVAR userId em store de sessão
    
      // Redirecionar de volta p/ /oauth/authorize
      const url = `/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&state=${state}`;
      return res.redirect(url);
    }    
}
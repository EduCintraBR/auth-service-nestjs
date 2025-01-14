import { ApiProperty } from "@nestjs/swagger";
import { IsOptional, IsString, IsStrongPassword } from "class-validator";

export class OAuthRequestBodyDto {
    @ApiProperty({
        example: 'password',
        description: 'O tipo da solicitação de autenticação'
    })
    @IsString()
    grant_type: string;

    @ApiProperty({
        example: 'teste@example.com',
        description: 'O nome de usuário. E-mail ou não.'
    })
    @IsString()
    @IsOptional()
    username: string;

    @ApiProperty({
        example: '********',
        description: 'O senha do usuário.'
    })
    @IsStrongPassword({
        minLength: 8,
        minSymbols: 1,
        minNumbers: 2
    })
    @IsOptional()
    password: string;

    @ApiProperty({
        example: '1',
        description: 'O id do client que esta fazendo a requisição.'
    })
    @IsString()
    @IsOptional()
    client_id: string;

    @ApiProperty({
        example: 'VsGvkTJC',
        description: 'O secret do client que esta fazendo a requisição.'
    })
    @IsString()
    @IsOptional()
    client_secret: string;


    @IsString()
    @IsOptional()
    code?: string;

    @IsString()
    @IsOptional()
    code_verifier?: string;

    @ApiProperty({
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        description: 'O refresh token da requisição.'
    })
    @IsString()
    @IsOptional()
    refresh_token: string;

    @IsString()
    @IsOptional()
    redirect_uri?: string;
}
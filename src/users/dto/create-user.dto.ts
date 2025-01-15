import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsOptional,
  IsString,
  IsStrongPassword,
} from 'class-validator';

export class CreateUserDto {
  @ApiProperty({
    example: 'Fulano Example',
    description: 'O nome do usuário.',
  })
  @IsString()
  nome: string;

  @ApiProperty({
    example: 'test@example.com',
    description: 'O e-mail do usuário.',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '#ghtr5214',
    description: 'A senha do usuário.',
  })
  @IsString()
  @IsStrongPassword({
    minLength: 8,
    minNumbers: 2,
    minSymbols: 1,
  })
  password: string;
}

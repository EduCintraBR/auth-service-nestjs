import { Body, Controller, DefaultValuePipe, Delete, Get, HttpCode, HttpStatus, Param, ParseBoolPipe, Patch, Post, Query } from "@nestjs/common";
import { UserResponseDto } from "./dto/user-response.dto";
import { CreateUserDto } from "./dto/create-user.dto";
import { UsersService } from "./users.service";
import { ApiQuery } from "@nestjs/swagger";

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) {}

    @Post()
    @HttpCode(HttpStatus.CREATED)
    async create(@Body() createUserDto: CreateUserDto) {
        return this.usersService.createUser(createUserDto.email, createUserDto.password);
    }

    @Get()
    @ApiQuery({
        name: 'onlyActive',
        required: false,
        description: 'Filtra apenas usuários ativos',
        type: Boolean,
        example: true,
    })
    async findAll(
        @Query('onlyActive', new DefaultValuePipe(true), ParseBoolPipe) onlyActive: boolean,
      ): Promise<UserResponseDto[]> {
        const users = await this.usersService.findAll(onlyActive);
        return users.map((u) => new UserResponseDto(u));
    }

    @Get(':email')
    async findOneByEmail(@Param('email') email: string): Promise<UserResponseDto> {
        const user = await this.usersService.findByEmail(email);
        return new UserResponseDto(user);
    }

    @Delete(':id')
    @HttpCode(HttpStatus.NO_CONTENT)
    async remove(@Param('id') id: string): Promise<void> {
        await this.usersService.deactivateUser(id);
    }
}
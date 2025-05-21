import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterAdminDto {
  @ApiProperty({ description: 'login' })
  @IsString({ message: 'Логин должен быть строкой' })
  @IsNotEmpty({ message: 'Логин не может быть пустым' })
  login: string;
  @MinLength(6, { message: 'Минимальная длина пароля - 6 символов' })
  @IsNotEmpty({ message: 'Пароль не может быть пустым' })
  @ApiProperty({ description: 'password' })
  password: string;
}

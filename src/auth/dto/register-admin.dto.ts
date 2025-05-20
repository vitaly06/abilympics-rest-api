import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterAdminDto {
  @IsString({ message: 'Логин должен быть строкой' })
  @IsNotEmpty({ message: 'Логин не может быть пустым' })
  login: string;
  @MinLength(6, { message: 'Минимальная длина пароля - 6 символов' })
  @IsNotEmpty({ message: 'Пароль не может быть пустым' })
  password: string;
}

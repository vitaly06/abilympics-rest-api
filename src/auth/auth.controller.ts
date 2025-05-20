import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAdminDto } from './dto/register-admin.dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: RegisterAdminDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  async login(
    @Body() dto: RegisterAdminDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(dto);
    res.cookie('access_token', result.access_token, {
      httpOnly: false,
      secure: false,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'strict',
    });
    return { message: 'Успешный вход' };
  }
}

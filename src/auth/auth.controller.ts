import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAdminDto } from './dto/register-admin.dto';
import { Request, Response } from 'express';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly prisma: PrismaService,
  ) {}

  @Post('register')
  @ApiOperation({ summary: 'Регистрация админа' })
  async register(@Body() dto: RegisterAdminDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @ApiOperation({ summary: 'Авторизация админа' })
  async login(
    @Body() dto: RegisterAdminDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(dto);
    res.cookie('access_token', result.access_token, {
      httpOnly: true,
      secure: false,
      maxAge: 15 * 60 * 1000,
      sameSite: 'strict',
    });
    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: false,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'strict',
    });
    return { message: 'Успешный вход' };
  }

  @Get('logout')
  @ApiOperation({ summary: 'Выход из системы' })
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      return 'Вы уже вышли';
    }

    const admin = await this.authService.findByRefresh(refreshToken);

    if (admin) {
      await this.authService.logout(admin.id);
    }

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return { message: 'Успешный выход' };
  }

  @Get('refresh')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({
    summary: 'Запрос на обновление access_token и refresh_token',
  })
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies['refresh_token'];

    const result = await this.authService.refresh(refreshToken);

    res.cookie('access_token', result.access_token, {
      httpOnly: true,
      secure: false,
      maxAge: 15 * 60 * 1000,
      sameSite: 'strict',
    });
    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: false,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'strict',
    });

    return { message: 'Токены обновлены' };
  }
}

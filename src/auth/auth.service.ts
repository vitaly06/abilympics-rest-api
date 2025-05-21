import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterAdminDto } from './dto/register-admin.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(dto: RegisterAdminDto) {
    const { login, password } = { ...dto };
    const hashPassword = await bcrypt.hash(password, 10);

    const admin = await this.prisma.admin.findUnique({
      where: { login },
    });
    if (admin?.password != null) {
      throw new ConflictException(
        'Пользователь с таким логином уже существует',
      );
    }

    return await this.prisma.admin.create({
      data: {
        login,
        password: hashPassword,
      },
    });
  }

  async login(dto: RegisterAdminDto) {
    const { login, password } = { ...dto };

    const admin = await this.prisma.admin.findUnique({
      where: { login },
    });
    if (!admin) {
      throw new BadRequestException('Пользователь с таким логином не найден');
    }

    const isValidPassword = await bcrypt.compare(password, admin.password);

    if (!isValidPassword) {
      throw new UnauthorizedException('Неверный пароль');
    }

    const payload = { sub: admin.id, login: admin.login };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });
    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '30d',
    });

    await this.prisma.admin.update({
      where: { id: admin.id },
      data: {
        refreshToken,
      },
    });
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async refresh(refreshToken: string) {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token не предоставлен');
    }
    const admin = await this.prisma.admin.findFirst({
      where: {
        refreshToken,
      },
    });

    if (!admin) {
      throw new UnauthorizedException('Недействительный refresh');
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const payload = await this.jwtService.verifyAsync(refreshToken);
      const newPayload = { sub: admin.id, login: admin.login };

      const accessToken = await this.jwtService.signAsync(newPayload, {
        expiresIn: '15m',
      });

      const newRefreshToken = await this.jwtService.signAsync(newPayload, {
        expiresIn: '30d',
      });

      await this.prisma.admin.update({
        where: { id: admin.id },
        data: {
          refreshToken: newRefreshToken,
        },
      });

      return {
        access_token: accessToken,
        refresh_token: newRefreshToken,
      };
    } catch (e) {
      console.log(e);
      throw new UnauthorizedException('Недействительный refresh token');
    }
  }

  async logout(adminId: number) {
    await this.prisma.admin.update({
      where: { id: adminId },
      data: { refreshToken: null },
    });
  }

  async validateAdmin(payload: any) {
    const admin = await this.prisma.admin.findUnique({
      where: { id: payload.sub },
    });
    if (!admin) {
      throw new UnauthorizedException('Пользователь не найден');
    }
  }

  async findByRefresh(refreshToken: string) {
    const admin = await this.prisma.admin.findFirst({
      where: { refreshToken },
    });
    return admin;
  }
}

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

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }
}

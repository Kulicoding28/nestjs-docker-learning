import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(dto.password);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      // agar tidak muncul ketika di post di console hashnya
      delete user.hash;

      // return he saved user
      // return user;
      return this.signToken((await user).id, (await user).email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          // mengatasi error 500 server // ket code P2002 artinya duplicate
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }

    // save the new user in the db
  }

  async signin(dto: AuthDto) {
    // find the user by email
    const user = this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if user doest not exist throw exception
    if (!user) {
      throw new ForbiddenException('credential incorrect');
    }
    // compare password
    const pwMatches = await argon.verify((await user).hash, dto.password);
    // if password incorrect throw exception
    if (!pwMatches) throw new ForbiddenException('credential incorrect');
    // send back the user
    // delete (await user).hash;
    // return user;
    return this.signToken((await user).id, (await user).email);
  }

  // pakai jwt dan config service bawaan nest base on dotenv
  // karna menggunakan promise jadi tidak perlu async
  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });
    return {
      access_token: token,
    };
  }
}

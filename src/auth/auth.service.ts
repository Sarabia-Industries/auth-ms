import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';

import * as bcrypt from 'bcrypt';

import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JsonWebTokenError, JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'config';
import { VerifyTokenDto } from './dto/verify-token.dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Connected to database');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    try {
      const { email, name, password } = registerUserDto;

      const user = await this.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new RpcException({
          status: HttpStatus.CONFLICT,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          name,
          password: bcrypt.hashSync(password, 10),
        },
      });

      const { password: _, ...result } = newUser;

      return {
        user: result,
        token: await this.signToken(result),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    try {
      const { email, password } = loginUserDto;

      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: HttpStatus.NOT_FOUND,
          message: 'Invalid credentials',
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Invalid credentials',
        });
      }

      const { password: _, ...result } = user;

      return {
        user: result,
        token: await this.signToken(result),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async signToken(payload: JwtPayload) {
    return this.jwtService.signAsync(payload);
  }

  async verifyToken(verifyTokenDto: VerifyTokenDto) {
    try {
      const token = verifyTokenDto?.token ?? null;
      if (!token)
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Token not found',
        });

      const verifyOptions: JwtVerifyOptions = {
        secret: envs.jwtSecret,
      };
      const { sub, iat, exp, ...user } = await this.jwtService.verifyAsync(
        token,
        verifyOptions,
      );

      return {
        user,
        token: await this.signToken(user),
      };
    } catch (error) {
      this.logger.error(error);

      if (error instanceof JsonWebTokenError) {
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Invalid token',
        });
      } else {
        throw error;
      }
    }
  }
}

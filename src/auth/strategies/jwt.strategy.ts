import {
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { appConfiguration } from 'configuration';
import { User } from 'entities/user.entity';
import { Request } from 'express';
import {
  ExtractJwt,
  Strategy,
  StrategyOptionsWithoutRequest,
} from 'passport-jwt';
import { Repository } from 'typeorm';
import { JwtPayload } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    @Inject(appConfiguration.KEY)
    private readonly appConfig: ConfigType<typeof appConfiguration>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {
    const jwtSecret = appConfig.jwt.secret;
    const strategyOptions: StrategyOptionsWithoutRequest = {
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request): string | null => {
          let token: string | null = null;

          if (request?.cookies?.['access_token']) {
            token = (request.cookies['access_token'] as string) ?? '';
            this.logger.debug('Token extracted from cookie by JwtStrategy.');
          }

          if (!token && request?.headers?.authorization) {
            const authHeader = request.headers.authorization;
            const parts = authHeader.split(' ');
            if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
              token = parts[1];
              this.logger.debug(
                'Token extracted from Authorization header by JwtStrategy.',
              );
            }
          }

          if (!token) {
            this.logger.debug(
              'Token not found by JwtStrategy (checked cookie and Authorization header).',
            );
          }
          return token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtSecret as string,
      passReqToCallback: false,
    };
    super(strategyOptions);

    if (!jwtSecret) {
      const jwtErrorMsg =
        'CRITICAL JWT ERROR: JWT_SE1CRET is not defined for JwtStrategy. Application cannot start securely.';
      this.logger.error(jwtErrorMsg);
      throw new Error(jwtErrorMsg);
    }
  }

  async validate(payload: JwtPayload): Promise<User> {
    this.logger.debug(
      `Validating JWT payload for user ID (sub): ${payload.sub}`,
    );
    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
    });

    if (!user) {
      this.logger.warn(
        `User not found for JWT user ID (sub): ${payload.sub}. Token may be invalid or user might have been deleted.`,
      );
      throw new UnauthorizedException('User not found or token invalid.');
    }

    return user;
  }
}

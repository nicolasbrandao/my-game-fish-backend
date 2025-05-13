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
  private readonly logger: Logger;

  constructor(
    @Inject(appConfiguration.KEY)
    private readonly appConfig: ConfigType<typeof appConfiguration>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {
    const jwtSecret = appConfig.jwt.secret;

    if (!jwtSecret) {
      const jwtErrorMsg =
        'CRITICAL JWT ERROR: JWT_SECRET is not defined for JwtStrategy. ' +
        'Please ensure JWT_SECRET is set in your .env file and correctly exposed ' +
        'via appConfiguration (e.g., app.jwt.secret). Application cannot start securely.';
      new Logger(JwtStrategy.name).error(jwtErrorMsg);
      throw new Error(jwtErrorMsg);
    }

    const strategyOptions: StrategyOptionsWithoutRequest = {
      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.extractTokenFromCookie,
        JwtStrategy.extractTokenFromAuthHeader,
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
      passReqToCallback: false,
    };

    super(strategyOptions);

    this.logger = new Logger(JwtStrategy.name);
    this.logger.log('JwtStrategy initialized.');
  }

  private static extractTokenFromCookie(
    this: void,
    request: Request,
  ): string | null {
    const logger = new Logger(JwtStrategy.name + ':CookieExtractor');
    const token: unknown = request?.cookies?.['access_token'];

    if (typeof token === 'string' && token.length > 0) {
      if (process.env.NODE_ENV === 'development') {
        logger.debug('Token extracted from cookie.');
      }
      return token;
    }
    return null;
  }

  private static extractTokenFromAuthHeader(
    this: void,
    request: Request,
  ): string | null {
    const logger = new Logger(JwtStrategy.name + ':AuthHeaderExtractor');
    const authHeader = request?.headers?.authorization;

    if (!authHeader) {
      return null;
    }

    const parts = authHeader.split(' ');

    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      if (process.env.NODE_ENV === 'development') {
        logger.debug(`Invalid or non-Bearer Authorization header found.`);
      }
      return null;
    }

    const token = parts[1];

    if (token.length === 0) {
      if (process.env.NODE_ENV === 'development') {
        logger.debug('Authorization header Bearer token is empty.');
      }
      return null;
    }

    if (process.env.NODE_ENV === 'development') {
      logger.debug('Token extracted from Authorization header.');
    }
    return token;
  }

  async validate(payload: JwtPayload): Promise<User> {
    this.logger.debug(
      `Validating JWT payload for user ID (sub): ${payload.sub}`,
    );

    if (
      !payload ||
      typeof payload.sub !== 'string' ||
      payload.sub.length === 0
    ) {
      this.logger.warn(
        'Invalid JWT payload: "sub" field is missing, not a non-empty string.',
      );
      throw new UnauthorizedException('Invalid token payload.');
    }

    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
    });

    if (!user) {
      this.logger.warn(
        `User not found for JWT user ID (sub): ${payload.sub}. ` +
          'Token may be invalid or user might have been deleted.',
      );
      throw new UnauthorizedException('User not found or token invalid.');
    }

    return user;
  }
}

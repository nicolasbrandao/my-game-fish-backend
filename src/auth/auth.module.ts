import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { appConfiguration } from 'configuration';
import { User } from 'entities/user.entity';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    PassportModule,
    TypeOrmModule.forFeature([User]),
    JwtModule.registerAsync({
      inject: [appConfiguration.KEY],
      useFactory: (appCfg: ReturnType<typeof appConfiguration>) => {
        if (!appCfg.jwt.secret) {
          const jwtErrorMsg =
            'CRITICAL JWT ERROR: JWT_SECRET is not defined in the application configuration. ' +
            'Please ensure JWT_SECRET is set in your .env file and correctly exposed ' +
            'via appConfiguration (e.g., app.jwt.secret).';
          console.error(jwtErrorMsg);
          throw new Error(jwtErrorMsg);
        }
        return {
          secret: appCfg.jwt.secret,
          signOptions: { expiresIn: appCfg.jwt.expiresIn },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, GoogleStrategy, JwtStrategy],
  exports: [AuthService, JwtModule, PassportModule],
})
export class AuthModule {}

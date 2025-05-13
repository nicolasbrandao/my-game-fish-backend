import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { appConfiguration } from 'configuration';
import { User } from 'entities/user.entity';
import { DataSource, DataSourceOptions } from 'typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfiguration],
      envFilePath: '.env',
    }),
    TypeOrmModule.forRootAsync({
      inject: [appConfiguration.KEY],
      useFactory: (appCfg: ReturnType<typeof appConfiguration>) => {
        const dbOptions: DataSourceOptions = {
          type: 'postgres',
          host: appCfg.database.host,
          port: appCfg.database.port,
          username: appCfg.database.username,
          password: appCfg.database.password,
          database: appCfg.database.name,
          entities: [User],
          synchronize: appCfg.database.synchronize,
          migrationsRun: appCfg.database.migrationsRun,
          logging:
            appCfg.NODE_ENV !== 'production' ? ['query', 'error'] : ['error'],
          migrations: [__dirname + '/../migrations/*{.ts,.js}'],
        };
        return dbOptions;
      },
    }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {
  constructor(private dataSource: DataSource) {}
}

import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [],
  providers: [],
  exports: [AuthModule],
})
export class AppModule {}

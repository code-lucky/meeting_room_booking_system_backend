import { Controller, Get, Post, Body, Patch, Param, Delete, Query, Inject, UnauthorizedException, Logger, SetMetadata } from '@nestjs/common';
import { UserService } from './user.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { EmailService } from 'src/email/email.service';
import { RedisService } from 'src/redis/redis.service';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RequireLogin, RequirePermission } from 'src/custom.decorator';

@Controller('user')
export class UserController {
  private logger = new Logger();

  constructor(private readonly userService: UserService) {}

  @Post('/register')
  register(@Body() registerUser:RegisterUserDto) {
    return this.userService.register(registerUser)
  }

  @Inject(EmailService)
  private emailService: EmailService;

  @Inject(RedisService)
  private redisService: RedisService;

  @Inject(JwtService)
  private jwtService: JwtService;

  @Inject(ConfigService)
  private configService: ConfigService;

  @Get('register-captcha')
  async captcha(@Query('address') address: string) {
      const code = Math.random().toString().slice(2,8);

      await this.redisService.set(`captcha_${address}`, code, 5 * 60);

      await this.emailService.sendMail({
        to: address,
        subject: '注册验证码',
        html: `<p>你的注册验证码是 ${code}</p>`
      });
      return '发送成功';
  }

  @Get("init-data") 
  async initData() {
      await this.userService.initData();
      return 'done';
  }

  @Post('login')
  async userLogin(@Body() loginUser:LoginUserDto){
    const vo = await this.userService.login(loginUser, false);

    vo.accessToken = this.jwtService.sign({
      userId: vo.userInfo.id,
      username: vo.userInfo.username,
      roles: vo.userInfo.roles,
      permissions: vo.userInfo.permissions
    },{
      expiresIn: this.configService.get('jwt_access_token_expires_time') || '30m'
    })

    vo.refreshToken = this.jwtService.sign({
      userId: vo.userInfo.id
    }, {
      expiresIn: this.configService.get('jwt_refresh_token_expres_time') || '7d'
    });

    return vo;
  }

  @Post('admin/login')
  async adminLogin(@Body() loginUser:LoginUserDto){
    const vo = await this.userService.login(loginUser, true);
    vo.accessToken = this.jwtService.sign({
      userId: vo.userInfo.id,
      username: vo.userInfo.username,
      roles: vo.userInfo.roles,
      permissions: vo.userInfo.permissions
    },{
      expiresIn: this.configService.get('jwt_access_token_expires_time') || '30m'
    })

    vo.refreshToken = this.jwtService.sign({
      userId: vo.userInfo.id
    }, {
      expiresIn: this.configService.get('jwt_refresh_token_expres_time') || '7d'
    });
    return vo;
  }

  @Get('refresh')
  async refresh(@Query('refreshToken') refreshToken: string){
    try {
      const data = this.jwtService.verify(refreshToken, this.configService.get('jwt_secret'));

      const user = await this.userService.findUserById(data.userId, false);

      const access_token = this.jwtService.sign({
        userId: user.id,
        username: user.username,
        roles: user.roles,
        permissions: user.permissions
      }, {
        expiresIn: this.configService.get('jwt_access_token_expires_time') || '30m'
      });

      const refresh_token = this.jwtService.sign({
        userId: user.id
      }, {
        expiresIn: this.configService.get('jwt_refresh_token_expres_time') || '7d'
      });

      return {
        access_token,
        refresh_token
      }
    } catch(e) {
      throw new UnauthorizedException('token 已失效，请重新登录');
    }
  }

  @Get('admin/refresh')
  async adminRefresh(@Query('refreshToken') refreshToken: string) {
      try {
        const data = this.jwtService.verify(refreshToken);

        const user = await this.userService.findUserById(data.userId, true); 

        const access_token = this.jwtService.sign({
          userId: user.id,
          username: user.username,
          roles: user.roles,
          permissions: user.permissions
        }, {
          expiresIn: this.configService.get('jwt_access_token_expires_time') || '30m'
        });

        const refresh_token = this.jwtService.sign({
          userId: user.id
        }, {
          expiresIn: this.configService.get('jwt_refresh_token_expres_time') || '7d'
        });

        return {
          access_token,
          refresh_token
        }
      } catch(e) {
        throw new UnauthorizedException('token 已失效，请重新登录');
      }
  }

  @Get('aaa')
  @RequireLogin()
  @RequirePermission('ddd')
  aaaa() {
      return 'aaa';
  }

  @Get('bbb')
  bbb() {
      return 'bbb';
  }
}

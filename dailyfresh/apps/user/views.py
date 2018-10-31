from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import check_password, make_password
from django.urls import reverse
from django.http import HttpResponse
from django.core.mail import send_mail
from django.conf import settings

from user.models import User
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired
from celery_tasks.tasks import send_register_active_email
import time
import re

# Create your views here.
class RegisterView(View):
    '''注册'''
    def get(self, request):
        '''显示注册页面'''
        return render(request, 'register.html')

    def post(self, request):
        '''进行数据处理'''
        # 接收数据
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # 校验数据
        if not all([username, password, email]):
            render(request, 'register.html', {'errmsg': '数据不完整'})

        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱格式不正确'})

        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})

        # 检查用户名是否重复
        try:
            user = User.objects.get(username = username)
        except User.DoesNotExist:
            # 用户名不存在
            user = None

        if user:
            # 用户名已经存在
            return  render(request, 'register.html', {'errmsg': '用户名已经存在'})

        # 业务处理， 进行用户注册
        user = User.objects.create_user(username=username, email=email, password=password)
        user.password = make_password(password)
        user.is_active = 0
        user.save()
        print('password--------------%s'%(password))
        print('pwd--------------%s'%(make_password(password)))

        # 加密用户的身份信息，生成激活token
        serializer = Serializer(settings.SECRET_KEY, 3600)
        info = {'confirm': user.id}
        token = serializer.dumps(info)
        token = token.decode()

        # 发邮件
        send_register_active_email.delay(email, username, token)

        # 返回应答， 跳到首页
        return redirect(reverse('goods:index'))


class ActiveView(View):
    '''用户激活'''
    def get(self, request, token):
        '''进行用户激活'''
        # 进行解密，获取要激活的用户信息
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
            info = serializer.loads(token)
            # 获取待激活用户的id
            user_id = info['confirm']

            # 根据id获取用户信息
            user = User.objects.get(id = user_id)
            user.is_active = 1
            user.save()

            # 跳转到登录页面
            return redirect(reverse('user:login'))
        except SignatureExpired as e:
            # 激活链接已过期
            return HttpResponse('激活链接已过期')


class LoginView(View):
    '''登录'''
    def get(self, request):
        '''显示登录页面'''
        # 判断是否记住了用户名
        if 'username' in request.COOKIES:
            username = request.COOKIES.get('username')
            checked = 'checked'
        else:
            username = ''
            checked = ''

        # 使用模板
        return render(request, 'login.html', {'username': username, 'checked': checked})

    def post(self, request):
        '''登录校验'''
        # 接收数据
        username = request.POST.get('username')
        password = request.POST.get('pwd')

        # 校验数据
        if not all([username, password]):
            return render(request, 'login.html', {'errmsg': '数据不完整'})

        # 业务处理 登录校验
        try:
            user = User.objects.get(username=username)
            pwd = user.password
            # 验证用户密码
            if check_password(password, pwd):
                # 用户名密码正确
                if user.is_active:
                    # 用户已激活
                    # 记录用户的登录状态
                    login(request, user)

                    # 跳转到首页
                    response = redirect(reverse('goods:index')) # HttpResponseRedirect

                    # 判断是否需要记住用户名
                    remember = request.POST.get('remember')

                    if remember == 'on':
                        # 记住用户名
                        response.set_cookie('username', username, max_age=7*24*3600)
                    else:
                        response.delete_cookie('username')

                    # 返回response
                    return response
                else:
                    # 用户未激活
                    return render(request, 'login.html', {'errmsg': '账户未激活'})
            else:
                # 用户名或密码错误
                return render(request, 'login.html', {'errmsg': '用户名或密码错误', 'n': username, 'p': password})
        except User.DoesNotExist:
            return render(request, 'login.html', {'errmsg': '用户名或密码错误'})



from django.shortcuts import render, redirect
from django.views.generic import View
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
        password = request.POST.get('password')
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
        user = User.objects.create_user(username, email, password)
        user.is_active = 0
        user.save()

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
        return render(request, 'login.html')
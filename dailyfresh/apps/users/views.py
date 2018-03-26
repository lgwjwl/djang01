from django.shortcuts import render,redirect
from django.http import HttpResponse,JsonResponse
from django.views.generic import View
import re
from .models import User
from django.conf import settings
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired
from django.core.mail import send_mail
from celery_tasks.tasks import send_active_email
from django.contrib.auth import authenticate,login,logout

# Create your views here.

# def register(request):
#     # 返回注册页面
#     return render(request, 'register.html')


class RegisterView(View):
    """类视图,处理注册页面的get和post请求"""

    def get(self, request):
        """处理GET请求，返回注册页面"""
        return render(request, 'register.html',{'title':'注册'})

    def post(self, request):
        """处理POST请求，实现注册逻辑"""

        # 获取注册请求参数
        dict = request.POST
        print(dict)
        user_name = dict.get('user_name')
        password = dict.get('pwd')
        cpassword = dict.get('cpwd')
        email = dict.get('email')
        allow = dict.get('allow')


        # 判断是否同意协议
        if not allow:
            return render(request, 'register.html', {'err_msg': '请同意协议'})

        # 判断数据是否填写完整
        if not all([user_name, password, cpassword, email]):
            return render(request, 'register.html', {'err_msg': '请将信息填写完整'})

        # # 用户错误提示的数据
        # context = {
        #     'username': user_name,
        #     'pwd': password,
        #     'cpwd': cpassword,
        #     'email': email,
        #     'err_msg': '',
        #     'title': '注册处理'
        # }

        # 判断两次密码是否一致
        if cpassword != password:
            # context['err_msg'] = '两次密码不一致'
            return render(request, 'register.html', {'err_msg': '两次密码不一致'})

        # 判断用户名是否存在
        if User.objects.filter(username=user_name).count() > 0:
            # context['err_msg'] = '用户名已经存在'
            return render(request, 'register.html',  {'err_msg': '用户名已经存在'})

        # 判断邮箱格式是否正确
        if not re.match(r'[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}', email):
            # context['err_msg'] = '邮箱格式不正确'
            return render(request, 'register.html', {'err_msg': '邮箱格式不正确'})

        # 判断邮箱是否存在
        # if User.objects.filter(email=email).count() > 0:
        #     context['err_msg'] = '邮箱已经存在'
        #     return render(request, 'register.html', context)

        # 处理（创建用户对象）
        user = User.objects.create_user(user_name, email, password)
        # 手动的将用户认证系统默认的激活状态is_active设置成False,默认是True
        user.is_active = False
        user.save()

        print("for test")
        # 将账号信息进行加密
        # serializer = Serializer(settings.SECRET_KEY, 60 * 60 * 2)
        # value = serializer.dumps({'id': user.id})  # 返回bytes
        # value = value.decode()  # 转成字符串，用于拼接地址

        # 向用户发送邮件
        # msg='<a href="http://127.0.0.1:8000/user/active/%d">点击激活</a>'%user.id
        # msg = '<a href="http://127.0.0.1:8000/user/active/%s">点击激活</a>' % value
        # send_mail('天天生鲜账户激活', '', settings.EMAIL_FROM, [email], html_message=msg)
        # http://127.0.0.1:8000/user/active/eyJpYXQiOjE1MjE5NjY0MzYsImFsZyI6IkhTMjU2IiwiZXhwIjoxNTIxOTczNjM2fQ.eyJpZCI6NX0.ydsMDx6IrIPwxVwfXymiQXmSWEnctu93hc5wXZePHuQ

        # 生成激活token
        token = user.generate_active_token()
        print(token)  # for-test

        # 使用celery发送激活邮件
        send_active_email.delay(email, user_name, token)

        # 给出响应
        return HttpResponse('请在两个小时内，接收邮件，激活账户')

        # 返回结果：比如重定向到首页
        # return redirect('login')


def active(request, token):
    print("aaaaaaaa")
    serializer = Serializer(settings.SECRET_KEY)
    try:
        # 解析用户编号
        dict = serializer.loads(token)
        print('dict = serializer.loads(token)=',dict)
        userid = dict.get('confirm')
        print('userid:',userid)
        # 激活账户
        user = User.objects.get(pk=userid)
        user.is_active = True
        user.save()

        # 转向登录页面
        return HttpResponse("您的账户已激活,请登录!")
        # return redirect('/user/login')
    except SignatureExpired as e:
        return HttpResponse('对不起，激活链接已经过期')


def exists(request):
    '判断用户名或邮箱是否存在'
    username=request.GET.get('username')
    if username is not None:
        #查询用户名是否存在
        result=User.objects.filter(username=username).count()
    return JsonResponse({'result':result})


class LoginView(View):
    def get(self,request):
        username=request.COOKIES.get('username','')
        return render(request,'login.html',{'title':'登录','username':username})

    def post(self,request):
        #接收数据
        dict=request.POST
        username=dict.get('username')
        pwd=dict.get('pwd')
        remember=dict.get('remember')
        print("for test:", dict)

        # #构造返回值
        # context={
        #     'title':'登录处理',
        #     'username':username,
        #     'pwd':pwd,
        #     'err_msg': '请填写完成信息'
        # }

        #验证是否填写数据
        if not all([username,pwd]):
            print("用户名或密码填写不完整")
            return render(request,'login.html',{'err_msg':'用户名或密码填写不完整'})


        #验证用户名、密码是否正确
        user=authenticate(username=username,password=pwd)
        if user is None:
            # context['err_msg']='用户名或密码错误'
            print("用户名或密码错误")
            return render(request,'login.html',{'err_msg':'用户名或密码错误'})

        #判断用户是否激活
        if not user.is_active:
            print("账户没有激活")
            # context['err_msg']='请到邮箱中激活账户'
            return render(request,'login.html',{'err_msg':'账户没有激活'})

        #记录状态
        print('正在登陆')
        login(request,user)
        print("登陆成功")

        response = redirect('/user/info')
        print('登陆成功,转到用户中心')

        # 是否记住用户名
        if remember is not None:
            response.set_cookie('username', username, expires=60 * 60 * 24 * 7) # 设置cookle
        else:
            response.delete_cookie('username')  # 删除cookie

        # 转向用户中心
        return response
        # return HttpResponse("登陆成功")
        # response=redirect('/user/info')


def logout_user(request):
    """处理退出登录逻辑"""
    # 由Django用户认证系统完成：需要清理cookie和session,request参数中有user对象
    logout(request)
    print("用户退出")
    # 退出后跳转：由产品经理设计
    # response = redirect('goods/index')
    return redirect('goods/index')
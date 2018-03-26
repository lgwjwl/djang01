# !/usr/bin/env python
# _*_coding=utf-8_*_

# @Time    : 18-3-22 下午9:55
# @Author  : LiGang
# @File    : urls.py
# @Software: PyCharm

from django.conf.urls import url
from . import views


urlpatterns=[
    url('^register$', views.RegisterView.as_view()),
    url('^active/(.+)$', views.active),
    url('^exists$', views.exists),
    url('^login$', views.LoginView.as_view()),
    url(r'^logout$', views.logout_user),
]
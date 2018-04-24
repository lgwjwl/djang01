# !/usr/bin/env python
# _*_coding=utf-8_*_

# @Time    : 18-3-22 下午9:55
# @Author  : LiGang
# @File    : urls.py
# @Software: PyCharm

from django.conf.urls import url
from . import views
urlpatterns=[
	url(r'^$',views.index),
	url(r'^test$',views.test)
]
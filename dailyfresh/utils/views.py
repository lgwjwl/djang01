# !/usr/bin/env python
# _*_coding=utf-8_*_

# @Time    : 18-4-6 上午11:48
# @Author  : LiGang
# @File    : views.py
# @Software: PyCharm

from django.contrib.auth.decorators import login_required

class LoginRequiredMixin(object):
	"""验证用户是否登陆"""

	@classmethod
	def as_view(cls,**initkwargs):
		view = super().as_view(**initkwargs)
		return login_required(view)
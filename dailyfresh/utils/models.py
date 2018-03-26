# !/usr/bin/env python
# _*_coding=utf-8_*_

# @Time    : 18-3-22 下午9:59
# @Author  : LiGang
# @File    : models.py
# @Software: PyCharm


from django.db import models


class BaseModel(models.Model):
    # 添加时间
    create_time = models.DateField(auto_now_add=True)
    #
    update_time = models.DateField(auto_now=True)

    class Meta:
        abstract = True

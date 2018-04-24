# !/usr/bin/env python
# _*_coding=utf-8_*_

# @Time    : 18-3-26 下午6:42
# @Author  : LiGang
# @File    : storage.py
# @Software: PyCharm

# coding=utf-8
from django.core.files.storage import Storage
from fdfs_client.client import Fdfs_client
from django.conf import settings

#自定义的存储类，必须要继承自Storage，才能被django所识别，在settings中的配置才有效
class FdfsStorage(Storage):
    def __init__(self):
        self.client=settings.FDFS_CLIENT
        self.server=settings.FDFS_SERVER

    #读取文件不需要这个对象完成，因为文件存储在fdfs中，通过nginx读取
    def open(self, name, mode='rb'):
        pass

    #当django调用保存类进行文件保存时，这个方法会被调用
    #content就是要保存的文件数据
    def save(self, name, content, max_length=None):
        #读取文件数据
        buffer=content.read()

        # 根据配置文件创建客户端对象
        # 在配置文件中指定了tracker服务器
        client = Fdfs_client(self.client)
        try:
            # 上传文件
            result = client.upload_by_buffer(buffer)
        except:
            raise

        # 返回文件保存的信息，格式如下
        '''
        {'Local file name': '01.jpg', 'Remote file_id': 'group1/M00/00/00/wKi7hFq4XAiAc89JAAA2pLUeB60746.jpg', 'Group name': 'group1', 'Storage IP': '192.168.187.132', 'Uploaded size': '13.00KB', 'Status': 'Upload successed.'}
        '''

        if result.get('Status')=='Upload successed.':
            return result.get('Remote file_id')
        else:
            raise Exception('文件上传失败')

    #GoodsCategory==>category.image.url来获取图片文件的地址，这个属性返回的是存储对象的url方法的值
    #在表中保存的数据为group1/M00/00/00/wKi7hFq4XAiAc89JAAA2pLUeB60746.jpg
    #实际获取图片的地址是：http://localhost:8888/+name
    def url(self, name):
        # return 'http://localhost:8888/'+name
        return self.server+name

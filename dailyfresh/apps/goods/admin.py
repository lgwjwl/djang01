# Register your models here.

from django.contrib import admin
from .models import GoodsCategory,Goods,GoodsSKU,GoodsImage,IndexCategoryGoodsBanner,IndexGoodsBanner,IndexPromotionBanner
# Register your models here.

admin.site.register(GoodsCategory)
admin.site.register(Goods)
admin.site.register(GoodsSKU)
admin.site.register(GoodsImage)
admin.site.register(IndexCategoryGoodsBanner)
admin.site.register(IndexGoodsBanner)
admin.site.register(IndexPromotionBanner)

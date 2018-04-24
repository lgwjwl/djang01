from django.shortcuts import render,redirect
from django.http import HttpResponse,JsonResponse
from .models import GoodsCategory, IndexGoodsBanner, IndexPromotionBanner, IndexCategoryGoodsBanner

# from django.views.generic import View


# Create your views here.
def index(request):
	return HttpResponse("天天生鲜-首页")

def test(request):
	category = GoodsCategory.objects.get(pk=1)
	context = {'category': category}
	return render(request, 'fdfs_test.html', context)


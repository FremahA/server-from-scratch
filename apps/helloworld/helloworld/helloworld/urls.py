from django.contrib import admin
from django.urls import path

from helloworld import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('hello', views.index),
]
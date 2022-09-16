from django.urls import path,include
from django.contrib.staticfiles.storage import staticfiles_storage
from django.views.generic.base import RedirectView
from django.conf import settings


urlpatterns = [
    path('mandala_circle/',include('mandala_circle.urls')),
    path('admins/',include('admins.urls')),
    path('',include('accounts.urls')),
]

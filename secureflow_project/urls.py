from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('playbooks/', include('playbooks.urls')),
    path('incidents/', include('incidents.urls')),
    path('dashboard/', include('dashboard.urls')),
    path('', lambda request: redirect('dashboard:home')),
    path('', include('incidents.urls')),
]

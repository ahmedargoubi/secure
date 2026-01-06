from django.urls import path
from . import views

app_name = 'incidents'

urlpatterns = [
    path('', views.incident_list, name='list'),
    path('create/', views.incident_create, name='create'),
    path('<int:pk>/', views.incident_detail, name='detail'),
    path('import/', views.incident_import, name='import'),
    path('simulate/', views.incident_simulate, name='simulate'),
    path('api/incidents/import/', views.import_events_api, name='import_events'),
    path('api/import/', views.import_events_api, name='api_import'),
]


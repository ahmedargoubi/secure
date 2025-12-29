from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.home, name='home'),
    path('import-json/', views.import_json_events, name='import_json'),
    path('api/json-events/', views.json_events_list, name='json_events'),
    path('export/csv/', views.export_incidents_csv, name='export_csv'),
    path('export/pdf/', views.export_incidents_pdf, name='export_pdf'),
]

   

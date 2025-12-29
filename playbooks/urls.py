from django.urls import path
from . import views

app_name = 'playbooks'

urlpatterns = [
    # Playbooks
    path('', views.playbook_list, name='list'),
    path('create/', views.playbook_create, name='create'),
    path('<int:pk>/', views.playbook_detail, name='detail'),
    path('<int:pk>/edit/', views.playbook_edit, name='edit'),
    path('<int:pk>/delete/', views.playbook_delete, name='delete'),
    path('<int:pk>/toggle/', views.playbook_toggle, name='toggle'),
    
    # Actions
    path('<int:playbook_pk>/action/create/', views.action_create, name='action_create'),
    path('action/<int:pk>/edit/', views.action_edit, name='action_edit'),
    path('action/<int:pk>/delete/', views.action_delete, name='action_delete'),
    path('action/<int:pk>/toggle/', views.action_toggle, name='action_toggle'),
]
path('<int:pk>/execute/', views.playbook_execute_manual, name='execute'),

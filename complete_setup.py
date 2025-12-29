#!/usr/bin/env python3
"""
Script pour créer tous les fichiers nécessaires pour SecureFlow
"""
import os

print("🚀 Configuration complète de SecureFlow...")

# Créer les dossiers
folders = [
    'templates/base',
    'templates/accounts', 
    'templates/playbooks',
    'templates/incidents',
    'templates/dashboard',
    'static',
    'media'
]

for folder in folders:
    os.makedirs(folder, exist_ok=True)
print("✓ Dossiers créés")

# 1. accounts/views.py
with open('accounts/views.py', 'w') as f:
    f.write("""from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')
    
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f'Bienvenue {user.username}!')
            return redirect('dashboard:home')
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'], 
                              password=form.cleaned_data['password'])
            if user:
                login(request, user)
                messages.success(request, f'Bienvenue {user.username}!')
                return redirect('dashboard:home')
    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})

@login_required
def logout_view(request):
    logout(request)
    messages.info(request, 'Déconnexion réussie.')
    return redirect('accounts:login')

@login_required
def profile_view(request):
    return render(request, 'accounts/profile.html')
""")

# 2. accounts/urls.py
with open('accounts/urls.py', 'w') as f:
    f.write("""from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
]
""")

# 3. dashboard/views.py
with open('dashboard/views.py', 'w') as f:
    f.write("""from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from incidents.models import Incident
from playbooks.models import Playbook

@login_required
def home(request):
    context = {
        'total_incidents': Incident.objects.count(),
        'active_incidents': Incident.objects.filter(status__in=['new', 'in_progress']).count(),
        'critical_incidents': Incident.objects.filter(severity='critical').count(),
        'active_playbooks': Playbook.objects.filter(is_active=True).count(),
        'recent_incidents': Incident.objects.all()[:20],
        'incidents_by_type': Incident.objects.values('incident_type').annotate(count=Count('id')),
    }
    return render(request, 'dashboard/home.html', context)
""")

# 4. dashboard/urls.py
with open('dashboard/urls.py', 'w') as f:
    f.write("""from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.home, name='home'),
]
""")

# 5. playbooks/urls.py
with open('playbooks/urls.py', 'w') as f:
    f.write("""from django.urls import path
from . import views

app_name = 'playbooks'

urlpatterns = [
    path('', views.playbook_list, name='list'),
    path('create/', views.playbook_create, name='create'),
    path('<int:pk>/', views.playbook_detail, name='detail'),
    path('<int:pk>/toggle/', views.playbook_toggle, name='toggle'),
]
""")

# 6. incidents/urls.py  
with open('incidents/urls.py', 'w') as f:
    f.write("""from django.urls import path
from . import views

app_name = 'incidents'

urlpatterns = [
    path('', views.incident_list, name='list'),
    path('<int:pk>/', views.incident_detail, name='detail'),
    path('import/', views.import_logs, name='import'),
]
""")

# 7. Vues temporaires pour playbooks et incidents
with open('playbooks/views.py', 'w') as f:
    f.write("""from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Playbook

@login_required
def playbook_list(request):
    playbooks = Playbook.objects.all()
    return render(request, 'playbooks/list.html', {'playbooks': playbooks})

@login_required
def playbook_create(request):
    return render(request, 'playbooks/create.html')

@login_required
def playbook_detail(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    return render(request, 'playbooks/detail.html', {'playbook': playbook})

@login_required
def playbook_toggle(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    playbook.is_active = not playbook.is_active
    playbook.save()
    return redirect('playbooks:list')
""")

with open('incidents/views.py', 'w') as f:
    f.write("""from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Incident

@login_required
def incident_list(request):
    incidents = Incident.objects.all()
    return render(request, 'incidents/list.html', {'incidents': incidents})

@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    return render(request, 'incidents/detail.html', {'incident': incident})

@login_required
def import_logs(request):
    return render(request, 'incidents/import.html')
""")

print("✓ Tous les fichiers Python créés")
print("\n🎉 Configuration terminée!")
print("\nProchaines étapes:")
print("  1. python manage.py runserver")
print("  2. Ouvrir http://localhost:8000")
print("  3. Se connecter avec le superuser créé")

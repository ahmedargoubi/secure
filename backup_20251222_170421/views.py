from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Incident, BlockedIP
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .forms import IncidentForm, LogImportForm, SimulateIncidentForm
from playbooks.models import Playbook, PlaybookExecution
import json
import csv
from datetime import datetime

@login_required
def incident_list(request):
    """Liste de tous les incidents"""
    incidents = Incident.objects.all().order_by('-detected_at')
    
    # Filtres
    status_filter = request.GET.get('status')
    severity_filter = request.GET.get('severity')
    type_filter = request.GET.get('type')
    
    if status_filter:
        incidents = incidents.filter(status=status_filter)
    if severity_filter:
        incidents = incidents.filter(severity=severity_filter)
    if type_filter:
        incidents = incidents.filter(incident_type=type_filter)
    
    # Statistiques
    total_incidents = Incident.objects.count()
    active_incidents = Incident.objects.filter(status__in=['new', 'in_progress']).count()
    critical_incidents = Incident.objects.filter(severity='critical', status__in=['new', 'in_progress']).count()
    
    context = {
        'incidents': incidents,
        'total_incidents': total_incidents,
        'active_incidents': active_incidents,
        'critical_incidents': critical_incidents,
    }
    return render(request, 'incidents/list.html', context)


@login_required
def incident_detail(request, pk):
    """Détails d'un incident"""
    incident = get_object_or_404(Incident, pk=pk)
    executions = incident.playbook_executions.all()
    
    context = {
        'incident': incident,
        'executions': executions,
    }
    return render(request, 'incidents/detail.html', context)


@login_required
def incident_create(request):
    """Créer un incident manuellement"""
    if request.method == 'POST':
        form = IncidentForm(request.POST)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.assigned_to = request.user
            incident.save()
            
            # Déclencher le playbook correspondant
            trigger_playbook(incident)
            
            messages.success(request, f'✅ Incident "{incident.title}" créé !')
            return redirect('incidents:detail', pk=incident.pk)
    else:
        form = IncidentForm()
    
    return render(request, 'incidents/create.html', {'form': form})


@login_required
def import_logs(request):
    """Importer des logs JSON ou CSV"""
    if request.method == 'POST':
        form = LogImportForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            
            # Vérifier la taille (max 5MB)
            if file.size > 5 * 1024 * 1024:
                messages.error(request, '❌ Fichier trop volumineux (max 5MB)')
                return render(request, 'incidents/import.html', {'form': form})
            
            try:
                if file.name.endswith('.json'):
                    incidents_created = process_json_logs(file, request.user)
                elif file.name.endswith('.csv'):
                    incidents_created = process_csv_logs(file, request.user)
                else:
                    messages.error(request, '❌ Format de fichier non supporté')
                    return render(request, 'incidents/import.html', {'form': form})
                
                messages.success(request, f'✅ {incidents_created} incident(s) importé(s) !')
                return redirect('incidents:list')
                
            except Exception as e:
                messages.error(request, f'❌ Erreur lors de l\'import : {str(e)}')
    else:
        form = LogImportForm()
    
    return render(request, 'incidents/import.html', {'form': form})


@login_required
def simulate_incident(request):
    """Simuler un incident de test"""
    if request.method == 'POST':
        form = SimulateIncidentForm(request.POST)
        if form.is_valid():
            scenario = form.cleaned_data['scenario']
            source_ip = form.cleaned_data['source_ip']
            severity = form.cleaned_data['severity']
            
            # Créer l'incident selon le scénario
            incident = create_simulated_incident(scenario, source_ip, severity, request.user)
            
            # Déclencher le playbook correspondant
            trigger_playbook(incident)
            
            messages.success(request, f'✅ Incident de test créé : {incident.title}')
            return redirect('incidents:detail', pk=incident.pk)
    else:
        form = SimulateIncidentForm()
    
    return render(request, 'incidents/simulate.html', {'form': form})


# ===== FONCTIONS UTILITAIRES =====

def process_json_logs(file, user):
    """Traiter un fichier JSON de logs"""
    content = file.read().decode('utf-8')
    logs = json.loads(content)
    
    # Si c'est un seul objet, le mettre dans une liste
    if isinstance(logs, dict):
        logs = [logs]
    
    incidents_created = 0
    for log in logs:
        incident = analyze_and_create_incident(log, user)
        if incident:
            trigger_playbook(incident)
            incidents_created += 1
    
    return incidents_created


def process_csv_logs(file, user):
    """Traiter un fichier CSV de logs"""
    content = file.read().decode('utf-8').splitlines()
    reader = csv.DictReader(content)
    
    incidents_created = 0
    for row in reader:
        incident = analyze_and_create_incident(row, user)
        if incident:
            trigger_playbook(incident)
            incidents_created += 1
    
    return incidents_created


def analyze_and_create_incident(log_data, user):
    """Analyser un log et créer un incident si nécessaire"""
    
    # Extraire les informations du log
    source_ip = log_data.get('source_ip') or log_data.get('src_ip') or log_data.get('ip')
    event_type = log_data.get('event_type') or log_data.get('type')
    failed_attempts = int(log_data.get('failed_attempts', 0))
    ports_scanned = log_data.get('ports_scanned', [])
    
    # Déterminer le type d'incident et la criticité
    incident_type = None
    severity = 'low'
    title = ''
    description = ''
    
    # Règle 1 : Échecs d'authentification (5+ tentatives)
    if failed_attempts >= 5 or event_type == 'auth_failure':
        incident_type = 'auth_failure'
        severity = 'high' if failed_attempts >= 10 else 'medium'
        title = f'Échecs d\'authentification multiples depuis {source_ip}'
        description = f'{failed_attempts} tentatives de connexion échouées détectées'
    
    # Règle 2 : Scan de ports
    elif (isinstance(ports_scanned, list) and len(ports_scanned) > 10) or event_type == 'port_scan':
        incident_type = 'port_scan'
        severity = 'high'
        title = f'Scan de ports détecté depuis {source_ip}'
        description = f'Tentative de reconnaissance réseau - {len(ports_scanned) if isinstance(ports_scanned, list) else "multiple"} ports scannés'
    
    # Règle 3 : IP suspecte (par défaut)
    elif source_ip:
        incident_type = 'suspicious_ip'
        severity = log_data.get('severity', 'medium')
        title = f'Activité suspecte depuis {source_ip}'
        description = f'Événement inhabituel détecté : {event_type or "inconnu"}'
    
    # Créer l'incident si un type a été déterminé
    if incident_type:
        incident = Incident.objects.create(
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            source_ip=source_ip,
            raw_log=log_data,
            assigned_to=user,
            status='new'
        )
        return incident
    
    return None


def create_simulated_incident(scenario, source_ip, severity, user):
    """Créer un incident simulé selon un scénario"""
    
    scenarios = {
        'suspicious_ip': {
            'title': f'[TEST] Connexion suspecte depuis {source_ip}',
            'description': 'Simulation d\'une connexion depuis une IP potentiellement malveillante',
            'type': 'suspicious_ip',
        },
        'auth_failure': {
            'title': f'[TEST] Tentatives de connexion multiples depuis {source_ip}',
            'description': 'Simulation de 8 tentatives de connexion échouées en 2 minutes',
            'type': 'auth_failure',
        },
        'port_scan': {
            'title': f'[TEST] Scan de ports détecté depuis {source_ip}',
            'description': 'Simulation d\'un scan de 50 ports (reconnaissance réseau)',
            'type': 'port_scan',
        }
    }
    
    scenario_data = scenarios[scenario]
    
    incident = Incident.objects.create(
        title=scenario_data['title'],
        description=scenario_data['description'],
        incident_type=scenario_data['type'],
        severity=severity,
        source_ip=source_ip,
        raw_log={
            'simulated': True,
            'scenario': scenario,
            'timestamp': datetime.now().isoformat()
        },
        assigned_to=user,
        status='new'
    )
    
    return incident


def trigger_playbook(incident):
    """Déclencher automatiquement le playbook correspondant"""
    from playbooks.tasks import execute_playbook_async
    
    # Chercher un playbook actif avec le bon déclencheur
    playbooks = Playbook.objects.filter(
        is_active=True,
        trigger=incident.incident_type
    )
    
    for playbook in playbooks:
        # Marquer l'incident comme ayant déclenché un playbook
        incident.auto_playbook_triggered = True
        incident.save()
        
        # Exécuter le playbook de manière asynchrone avec Celery
        execute_playbook_async.delay(playbook.id, incident.id)
@csrf_exempt
@require_http_methods(["POST"])
def import_events_api(request):
    """
    API pour importer des événements de sécurité
    POST /api/incidents/import/
    """
    try:
        data = json.loads(request.body)
        events = data.get('events', [])
        
        if not events:
            return JsonResponse({
                'status': 'error',
                'message': 'No events provided'
            }, status=400)
        
        incidents_created = []
        
        for event in events:
            # Créer un incident
            incident = Incident.objects.create(
                title=f"{event.get('event_type', 'Unknown')} from {event.get('source_ip', 'Unknown')}",
                description=event.get('description', ''),
                severity=event.get('severity', 'medium'),
                source_ip=event.get('source_ip', ''),
                status='open'
            )
            
            incidents_created.append(incident.id)
            
            # Déclencher les playbooks correspondants
            playbooks = Playbook.objects.filter(
                trigger_type=event.get('event_type'),
                active=True
            )
            
            for playbook in playbooks:
                # Exécuter le playbook
                from .tasks import execute_playbook
                execute_playbook.delay(playbook.id, incident.id)
        
        return JsonResponse({
            'status': 'success',
            'message': f'{len(incidents_created)} incidents created',
            'incident_ids': incidents_created
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def import_events_api(request):
    """
    API pour importer des événements de sécurité
    POST /api/incidents/import/
    """
    try:
        data = json.loads(request.body)
        events = data.get('events', [])
        
        if not events:
            return JsonResponse({
                'status': 'error',
                'message': 'No events provided'
            }, status=400)
        
        incidents_created = []
        playbooks_triggered = []
        
        for event in events:
            # Mapper le type d'événement
            event_type = event.get('event_type', 'suspicious_ip')
            
            # Mapper vers les types d'incidents Django
            type_mapping = {
                'ssh_bruteforce': 'ssh_bruteforce',
                'port_scan': 'port_scan',
                'suspicious_ip': 'suspicious_ip',
                'web_attack': 'web_attack',
                'ddos_attack': 'ddos_attack',
            }
            
            incident_type = type_mapping.get(event_type, 'suspicious_ip')
            
            # Créer l'incident
            try:
                incident = Incident.objects.create(
                    title=f"{event.get('description', 'Security Event')}",
                    description=event.get('description', ''),
                    incident_type=incident_type,
                    severity=event.get('severity', 'medium').lower(),
                    source_ip=event.get('source_ip'),
                    target_ip=event.get('destination_ip'),
                    raw_log=event,
                    status='new'
                )
                
                incidents_created.append(incident.id)
                
                # Déclencher le playbook
                trigger_playbook(incident)
                playbooks_triggered.append(incident.id)
                
            except Exception as e:
                print(f"Erreur création incident: {str(e)}")
                continue
        
        return JsonResponse({
            'status': 'success',
            'message': f'{len(incidents_created)} incidents created',
            'incident_ids': incidents_created,
            'playbooks_triggered': len(playbooks_triggered)
        })
        
    except Exception as e:
        import traceback
        print(f"Erreur API import: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

@csrf_exempt
def import_events_api(request):
    """API pour recevoir les événements de l'agent de sécurité"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        events = data.get('events', [])
        
        if not events:
            return JsonResponse({'error': 'No events provided'}, status=400)
        
        created_count = 0
        
        for event in events:
            type_mapping = {
                'ssh_bruteforce': 'ssh_bruteforce',
                'port_scan': 'port_scan',
                'web_attack': 'web_attack',
                'ddos_attack': 'ddos_attack'
            }
            
            incident_type = type_mapping.get(
                event.get('event_type', ''),
                'suspicious_ip'
            )
            
            incident = Incident.objects.create(
                title=event.get('description', 'Security Event'),
                description=event.get('description', ''),
                incident_type=incident_type,
                severity=event.get('severity', 'medium'),
                source_ip=event.get('source_ip'),
                target_ip=event.get('destination_ip'),
                status='new',
                raw_log=event.get('details', {})
            )
            
            created_count += 1
            
            from playbooks.models import Playbook
            from playbooks.tasks import execute_playbook_async
            
            playbooks = Playbook.objects.filter(
                trigger=incident_type,
                is_active=True
            )
            
            for playbook in playbooks:
                execute_playbook_async.delay(playbook.id, incident.id)
        
        return JsonResponse({
            'status': 'success',
            'incidents_created': created_count
        }, status=201)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

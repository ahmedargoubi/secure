from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import Incident, BlockedIP
from .forms import IncidentForm
import json
from django.utils import timezone
from datetime import timedelta

@login_required
def incident_list(request):
    """Liste des incidents avec statistiques"""
    incidents = Incident.objects.all().order_by('-detected_at')
    
    # Calcul des statistiques
    total_incidents = incidents.count()
    active_incidents = incidents.filter(status__in=['new', 'in_progress']).count()
    critical_incidents = incidents.filter(severity='critical').count()
    
    context = {
        'incidents': incidents,
        'total_incidents': total_incidents,
        'active_incidents': active_incidents,
        'critical_incidents': critical_incidents,
    }
    return render(request, 'incidents/list.html', context)

@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    playbook_executions = incident.playbook_executions.all().order_by('-started_at')
    blocked_ips = incident.blocked_ips.all()
    
    context = {
        'incident': incident,
        'playbook_executions': playbook_executions,
        'blocked_ips': blocked_ips,
    }
    return render(request, 'incidents/detail.html', context)

@login_required
def incident_create(request):
    if request.method == 'POST':
        form = IncidentForm(request.POST)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.assigned_to = request.user
            incident.save()
            messages.success(request, f'✅ Incident created successfully!')
            return redirect('incidents:detail', pk=incident.pk)
    else:
        form = IncidentForm()
    return render(request, 'incidents/create.html', {'form': form})

@login_required
def incident_import(request):
    """
    Page d'import de fichiers JSON (GET)
    """
    if request.method == 'GET':
        return render(request, 'incidents/import.html')
    
    # POST - traiter l'upload
    if request.method == 'POST':
        try:
            if 'file' not in request.FILES:
                messages.error(request, '❌ No file uploaded')
                return redirect('incidents:import')
            
            json_file = request.FILES['file']
            
            # Lire et parser le JSON
            try:
                data = json.load(json_file)
            except json.JSONDecodeError:
                messages.error(request, '❌ Invalid JSON file')
                return redirect('incidents:import')
            
            # Si c'est une liste directe d'événements
            if isinstance(data, list):
                events = data
            # Si c'est un dict avec une clé 'events'
            elif isinstance(data, dict) and 'events' in data:
                events = data['events']
            else:
                messages.error(request, '❌ Invalid JSON structure')
                return redirect('incidents:import')
            
            incidents_created = 0
            playbooks_triggered = 0
            
            from playbooks.models import Playbook
            from playbooks.tasks import execute_playbook_async
            
            for event in events:
                event_type = event.get('event_type', 'suspicious_ip')
                source_ip = event.get('source_ip', '')
                severity = event.get('severity', 'medium')
                description = event.get('description', 'Security event detected')
                
                # Créer l'incident
                incident = Incident.objects.create(
                    title=f"{event_type.replace('_', ' ').title()} - {source_ip}",
                    description=description,
                    incident_type=event_type,
                    severity=severity,
                    source_ip=source_ip,
                    target_ip=event.get('destination_ip', '192.168.163.135'),
                    status='new',
                    raw_log=event.get('details', {})
                )
                
                incidents_created += 1
                
                # Déclencher les playbooks correspondants
                playbooks = Playbook.objects.filter(
                    trigger=event_type,
                    is_active=True
                )
                
                for playbook in playbooks:
                    execute_playbook_async.delay(playbook.id, incident.id)
                    playbooks_triggered += 1
            
            messages.success(
                request, 
                f'✅ {incidents_created} incidents imported, {playbooks_triggered} playbooks triggered!'
            )
            return redirect('incidents:list')
            
        except Exception as e:
            messages.error(request, f'❌ Error: {str(e)}')
            return redirect('incidents:import')

@login_required
def incident_simulate(request):
    if request.method == 'POST':
        incident_type = request.POST.get('incident_type')
        severity = request.POST.get('severity', 'medium')
        source_ip = request.POST.get('source_ip', '192.168.1.100')
        description = request.POST.get('description', '')
        
        type_titles = {
            'ssh_bruteforce': 'SSH Bruteforce Attack',
            'port_scan': 'Port Scanning',
            'web_attack': 'Web Attack',
            'sql_injection': 'SQL Injection',
            'ddos_attack': 'DDoS Attack',
        }
        
        title = type_titles.get(incident_type, 'Security Incident')
        if not description:
            description = f"Simulation: {title} from {source_ip}"
        
        incident = Incident.objects.create(
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            source_ip=source_ip,
            status='new',
            assigned_to=request.user
        )
        
        # Déclencher playbooks automatiques
        from playbooks.models import Playbook
        from playbooks.tasks import execute_playbook_async
        
        playbooks = Playbook.objects.filter(
            trigger=incident_type,
            is_active=True
        )
        
        for playbook in playbooks:
            execute_playbook_async.delay(playbook.id, incident.id)
        
        messages.success(request, f'✅ Incident #{incident.id} created and playbooks triggered!')
        return redirect('incidents:detail', pk=incident.pk)
    
    context = {
        'incident_types': Incident.INCIDENT_TYPES,
        'severity_levels': Incident.SEVERITY_LEVELS,
    }
    return render(request, 'incidents/simulate.html', context)

@csrf_exempt
@require_http_methods(["POST"])
def import_events_api(request):
    """
    API pour l'agent de sécurité
    POST /api/incidents/import/
    """
    print("\n" + "="*70)
    print("🔔 API: Receiving events from security agent")
    print("="*70)
    
    try:
        data = json.loads(request.body)
        events = data.get('events', [])
        
        if not events:
            print("⚠️ No events received")
            return JsonResponse({'status': 'error', 'message': 'No events'}, status=400)
        
        print(f"📦 {len(events)} event(s) received")
        created_count = 0
        playbooks_triggered = 0
        
        from playbooks.models import Playbook
        from playbooks.tasks import execute_playbook_async
        
        for event in events:
            event_type = event.get('event_type', 'suspicious_ip')
            source_ip = event.get('source_ip')
            severity = event.get('severity', 'medium')
            description = event.get('description', 'Security event')
            
            print(f"\n  📌 Type: {event_type} | IP: {source_ip} | Severity: {severity}")
            
            # Dédupliquer (5 minutes)
            recent = timezone.now() - timedelta(minutes=5)
            if Incident.objects.filter(
                source_ip=source_ip,
                incident_type=event_type,
                detected_at__gte=recent
            ).exists():
                print(f"  ℹ️ Similar incident already exists")
                continue
            
            # Créer incident
            incident = Incident.objects.create(
                title=f"{event_type.replace('_', ' ').title()} - {source_ip}",
                description=description,
                incident_type=event_type,
                severity=severity,
                source_ip=source_ip,
                target_ip=event.get('destination_ip', '192.168.163.135'),
                status='new',
                raw_log=event.get('details', {})
            )
            
            created_count += 1
            print(f"  ✅ Incident created (ID: {incident.id})")
            
            # Déclencher playbooks automatiques
            playbooks = Playbook.objects.filter(
                trigger=event_type,
                is_active=True
            )
            
            for playbook in playbooks:
                execute_playbook_async.delay(playbook.id, incident.id)
                playbooks_triggered += 1
                print(f"  ⚡ Playbook triggered: {playbook.name}")
        
        print(f"\n✅ Total: {created_count} incident(s) created, {playbooks_triggered} playbooks triggered")
        print("="*70 + "\n")
        
        return JsonResponse({
            'status': 'success',
            'incidents_created': created_count,
            'playbooks_triggered': playbooks_triggered
        }, status=201)
    
    except json.JSONDecodeError:
        print("❌ Invalid JSON")
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

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
    incidents = Incident.objects.all().order_by('-detected_at')
    context = {
        'incidents': incidents,
        'total_count': Incident.objects.count(),
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
            messages.success(request, f'✅ Incident créé !')
            return redirect('incidents:detail', pk=incident.pk)
    else:
        form = IncidentForm()
    return render(request, 'incidents/create.html', {'form': form})

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
            description = f"Simulation: {title} depuis {source_ip}"
        
        incident = Incident.objects.create(
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            source_ip=source_ip,
            status='new',
            assigned_to=request.user
        )
        
        messages.success(request, f'✅ Incident #{incident.id} créé !')
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
    print("🔔 API: Réception événements agent")
    print("="*70)
    
    try:
        data = json.loads(request.body)
        events = data.get('events', [])
        
        if not events:
            print("⚠️ Aucun événement")
            return JsonResponse({'status': 'error', 'message': 'No events'}, status=400)
        
        print(f"📦 {len(events)} événement(s) reçu(s)")
        created_count = 0
        
        for event in events:
            event_type = event.get('event_type', 'suspicious_ip')
            source_ip = event.get('source_ip')
            severity = event.get('severity', 'medium')
            description = event.get('description', 'Security event')
            
            print(f"\n  📌 Type: {event_type} | IP: {source_ip} | Sévérité: {severity}")
            
            # Dédupliquer (5 minutes)
            recent = timezone.now() - timedelta(minutes=5)
            if Incident.objects.filter(
                source_ip=source_ip,
                incident_type=event_type,
                detected_at__gte=recent
            ).exists():
                print(f"  ℹ️ Incident similaire existe déjà")
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
            print(f"  ✅ Incident créé (ID: {incident.id})")
        
        print(f"\n✅ Total: {created_count} incident(s) créé(s)")
        print("="*70 + "\n")
        
        return JsonResponse({
            'status': 'success',
            'incidents_created': created_count
        }, status=201)
    
    except json.JSONDecodeError:
        print("❌ JSON invalide")
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

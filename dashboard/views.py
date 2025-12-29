from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Avg
from django.utils import timezone
from datetime import timedelta
from incidents.models import Incident, BlockedIP
from playbooks.models import Playbook, PlaybookExecution
import json
import os
import glob
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

@login_required
def home(request):
    """Dashboard principal avec statistiques complètes"""
    
    # ===== CHARGER TOUS LES ÉVÉNEMENTS JSON =====
    json_data = load_all_security_events_json()
    
    # ===== STATISTIQUES GÉNÉRALES =====
    total_incidents = Incident.objects.count()
    active_incidents = Incident.objects.filter(status__in=['new', 'in_progress']).count()
    critical_incidents = Incident.objects.filter(severity='critical').count()
    resolved_incidents = Incident.objects.filter(status='resolved').count()
    
    # Playbooks
    total_playbooks = Playbook.objects.count()
    active_playbooks = Playbook.objects.filter(is_active=True).count()
    
    # Success rate des playbooks
    total_executions = PlaybookExecution.objects.count()
    successful_executions = PlaybookExecution.objects.filter(status='success').count()
    success_rate = round((successful_executions / total_executions * 100) if total_executions > 0 else 0, 1)
    
    # IPs bloquées
    blocked_ips_count = BlockedIP.objects.filter(is_active=True).count()
    
    # Temps de réponse moyen (en minutes)
    resolved = Incident.objects.filter(status='resolved', resolved_at__isnull=False)
    avg_response_time = 0
    if resolved.exists():
        total_time = sum([
            (inc.resolved_at - inc.detected_at).total_seconds() / 60 
            for inc in resolved if inc.resolved_at and inc.detected_at
        ])
        avg_response_time = round(total_time / resolved.count(), 1)
    
    # ===== DONNÉES POUR LES GRAPHIQUES =====
    
    # 1. Incidents par sévérité
    severity_stats = Incident.objects.values('severity').annotate(count=Count('id'))
    severity_labels = []
    severity_data = []
    for stat in severity_stats:
        severity_labels.append(stat['severity'].capitalize())
        severity_data.append(stat['count'])
    
    # 2. Incidents par type
    type_stats = Incident.objects.values('incident_type').annotate(count=Count('id'))
    type_labels = []
    type_data = []
    for stat in type_stats:
        type_labels.append(stat['incident_type'].replace('_', ' ').title())
        type_data.append(stat['count'])
    
    # 3. Incidents par statut
    status_stats = Incident.objects.values('status').annotate(count=Count('id'))
    status_labels = []
    status_data = []
    for stat in status_stats:
        status_labels.append(stat['status'].replace('_', ' ').title())
        status_data.append(stat['count'])
    
    # 4. Tendance sur 7 jours
    today = timezone.now().date()
    trend_labels = []
    trend_data = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = Incident.objects.filter(detected_at__date=day).count()
        trend_labels.append(day.strftime('%d/%m'))
        trend_data.append(count)
    
    # 5. Performance des playbooks
    playbook_stats = Playbook.objects.all()[:5]
    playbook_names = []
    playbook_success = []
    playbook_failed = []
    playbook_partial = []
    
    for pb in playbook_stats:
        playbook_names.append(pb.name[:30])  # Limiter à 30 caractères
        
        # Compter les exécutions par statut
        success = pb.executions.filter(status='success').count()
        failed = pb.executions.filter(status='failed').count()
        partial = pb.executions.filter(status='partial').count()
        
        playbook_success.append(success)
        playbook_failed.append(failed)
        playbook_partial.append(partial)
    
    # ===== NOUVELLE SECTION : DONNÉES POUR LE GRAPHIQUE "Playbook Execution Results" =====
    response_types = [
        'Malware Response',
        'DDoS Response', 
        'SQL Injection Response',
        'Web Attack Response',
        'Auth Failure Response'
    ]
    
    response_success = []
    response_failed = []
    response_partial = []
    
    # Mapper les types d'incidents aux types de réponse
    incident_type_mapping = {
        'Malware Response': ['malware_detected', 'malware_c2'],
        'DDoS Response': ['ddos_attack'],
        'SQL Injection Response': ['sql_injection'],
        'Web Attack Response': ['web_attack', 'xss', 'lfi', 'command_injection'],
        'Auth Failure Response': ['auth_failure', 'ssh_bruteforce']
    }
    
    for response_type in response_types:
        incident_types = incident_type_mapping.get(response_type, [])
        
        # Compter les exécutions pour ces types d'incidents
        success = PlaybookExecution.objects.filter(
            incident__incident_type__in=incident_types,
            status='success'
        ).count()
        
        failed = PlaybookExecution.objects.filter(
            incident__incident_type__in=incident_types,
            status='failed'
        ).count()
        
        partial = PlaybookExecution.objects.filter(
            incident__incident_type__in=incident_types,
            status='partial'
        ).count()
        
        response_success.append(success)
        response_failed.append(failed)
        response_partial.append(partial)
    
    # 6. Actions exécutées
    total_actions_executed = sum([exec.actions_executed for exec in PlaybookExecution.objects.all()])
    total_actions_failed = sum([exec.actions_failed for exec in PlaybookExecution.objects.all()])
    
    # 7. Distribution des attaques
    attack_counts = [
        Incident.objects.filter(incident_type='suspicious_ip').count(),
        Incident.objects.filter(incident_type='auth_failure').count(),
        Incident.objects.filter(incident_type='port_scan').count(),
    ]
    
    # 8. Heatmap 24h
    hour_labels = [f"{h:02d}:00" for h in range(24)]
    hour_data = []
    for h in range(24):
        count = Incident.objects.filter(detected_at__hour=h).count()
        hour_data.append(count)
    
    # ===== THREAT INTELLIGENCE =====
    enriched_incidents = Incident.objects.filter(is_enriched=True).count()
    enrichment_rate = round((enriched_incidents / total_incidents * 100) if total_incidents > 0 else 0, 1)
    
    malicious_ips = Incident.objects.filter(
        threat_intel_data__isnull=False
    ).exclude(
        threat_intel_data={}
    ).count()
    
    # ===== MITRE ATT&CK MAPPING =====
    mitre_stats = [
        {
            'type': 'Brute Force Attack',
            'tactic': 'Credential Access',
            'technique': 'T1110 - Brute Force',
            'count': Incident.objects.filter(incident_type='auth_failure').count()
        },
        {
            'type': 'Network Reconnaissance',
            'tactic': 'Discovery',
            'technique': 'T1046 - Network Service Scanning',
            'count': Incident.objects.filter(incident_type='port_scan').count()
        },
        {
            'type': 'Malicious IP Connection',
            'tactic': 'Command and Control',
            'technique': 'T1071 - Application Layer Protocol',
            'count': Incident.objects.filter(incident_type='suspicious_ip').count()
        },
    ]
    
    # ===== INCIDENTS RÉCENTS =====
    recent_incidents = Incident.objects.all().order_by('-detected_at')[:10]
    
    # ===== TOP IPs BLOQUÉES =====
    top_blocked_ips = BlockedIP.objects.filter(is_active=True).order_by('-blocked_at')[:6]
    
    context = {
        # Stats générales
        'total_incidents': total_incidents,
        'active_incidents': active_incidents,
        'critical_incidents': critical_incidents,
        'resolved_incidents': resolved_incidents,
        'total_playbooks': total_playbooks,
        'active_playbooks': active_playbooks,
        'success_rate': success_rate,
        'blocked_ips_count': blocked_ips_count,
        'avg_response_time': avg_response_time,
        
        # Graphiques
        'severity_labels': json.dumps(severity_labels),
        'severity_data': json.dumps(severity_data),
        'type_labels': json.dumps(type_labels),
        'type_data': json.dumps(type_data),
        'status_labels': json.dumps(status_labels),
        'status_data': json.dumps(status_data),
        'trend_labels': json.dumps(trend_labels),
        'trend_data': json.dumps(trend_data),
        'playbook_names': json.dumps(playbook_names),
        'playbook_success': json.dumps(playbook_success),
        'playbook_failed': json.dumps(playbook_failed),
        'playbook_partial': json.dumps(playbook_partial),
        'total_actions_executed': total_actions_executed,
        'total_actions_failed': total_actions_failed,
        'attack_counts': json.dumps(attack_counts),
        'hour_labels': json.dumps(hour_labels),
        'hour_data': json.dumps(hour_data),
        
        # Données pour le graphique "Playbook Execution Results"
        'response_types': json.dumps(response_types),
        'response_success': json.dumps(response_success),
        'response_failed': json.dumps(response_failed),
        'response_partial': json.dumps(response_partial),
        
        # Threat Intelligence
        'enriched_incidents': enriched_incidents,
        'enrichment_rate': enrichment_rate,
        'malicious_ips': malicious_ips,
        'total_executions': total_executions,
        
        # MITRE ATT&CK
        'mitre_stats': mitre_stats,
        
        # Tables
        'recent_incidents': recent_incidents,
        'top_blocked_ips': top_blocked_ips,
        
        # JSON data (TOUS les événements)
        'json_events': json_data,
    }
    
    return render(request, 'dashboard/home.html', context)


def load_all_security_events_json():
    """
    Charge TOUS les événements de sécurité depuis TOUS les fichiers JSON
    """
    try:
        # Chercher tous les fichiers security_events_*.json
        json_pattern = os.path.join(settings.BASE_DIR, 'security_events_*.json')
        json_files = glob.glob(json_pattern)
        
        if not json_files:
            print(f"⚠️ Aucun fichier JSON trouvé dans {settings.BASE_DIR}")
            return []
        
        print(f"📂 {len(json_files)} fichier(s) JSON trouvé(s)")
        
        all_events = []
        
        # Charger chaque fichier JSON
        for json_file in sorted(json_files, reverse=True):  # Plus récents en premier
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Si c'est une liste d'événements
                    if isinstance(data, list):
                        all_events.extend(data)
                    # Si c'est un seul événement
                    elif isinstance(data, dict):
                        all_events.append(data)
                    
                    print(f"  ✓ {os.path.basename(json_file)}: {len(data) if isinstance(data, list) else 1} événement(s)")
            
            except json.JSONDecodeError as e:
                print(f"  ✗ Erreur JSON dans {os.path.basename(json_file)}: {str(e)}")
                continue
            except Exception as e:
                print(f"  ✗ Erreur lecture {os.path.basename(json_file)}: {str(e)}")
                continue
        
        # Trier par timestamp (plus récents en premier)
        all_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        print(f"✅ Total: {len(all_events)} événements chargés")
        
        return all_events
    
    except Exception as e:
        print(f"❌ Erreur globale lors du chargement des JSON: {str(e)}")
        return []


@login_required
def import_json_events(request):
    """
    Vue pour importer manuellement les événements depuis TOUS les JSON
    """
    if request.method == 'POST':
        all_events = load_all_security_events_json()
        
        if not all_events:
            return render(request, 'dashboard/import_error.html', {
                'error': 'Aucun fichier JSON trouvé ou tous vides'
            })
        
        imported_count = 0
        
        for event in all_events:
            # Mapper le type d'événement
            event_type = event.get('event_type', 'suspicious_ip')
            
            # Mapper vers les types d'incidents Django
            type_mapping = {
                'ssh_bruteforce': 'auth_failure',
                'port_scan': 'port_scan',
                'suspicious_ip': 'suspicious_ip',
            }
            
            incident_type = type_mapping.get(event_type, 'suspicious_ip')
            
            # Vérifier si l'incident existe déjà
            existing = Incident.objects.filter(
                source_ip=event.get('source_ip'),
                detected_at__gte=timezone.now() - timedelta(hours=1)  # Dédupliquer sur 1h
            ).exists()
            
            if not existing:
                try:
                    Incident.objects.create(
                        title=f"{event.get('description', 'Security Event')}",
                        description=event.get('description', ''),
                        incident_type=incident_type,
                        severity=event.get('severity', 'medium').lower(),
                        source_ip=event.get('source_ip'),
                        target_ip=event.get('destination_ip'),
                        detected_at=event.get('timestamp', timezone.now()),
                        raw_log=event,
                        status='new',
                        assigned_to=request.user if hasattr(request, 'user') else None
                    )
                    imported_count += 1
                except Exception as e:
                    print(f"Erreur import événement: {str(e)}")
                    continue
        
        return render(request, 'dashboard/import_success.html', {
            'imported_count': imported_count,
            'total_events': len(all_events)
        })
    
    return render(request, 'dashboard/import_form.html')


@login_required
@require_GET
def json_events_list(request):
    """
    API endpoint: retourne TOUS les événements de sécurité en JSON
    """
    all_events = load_all_security_events_json()

    if not all_events:
        return JsonResponse(
            {"status": "error", "message": "No JSON files found"},
            status=404
        )

    return JsonResponse({
        "status": "success",
        "total_events": len(all_events),
        "events": all_events
    }, safe=False)

from django.http import HttpResponse
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import csv
from io import StringIO

@login_required
def export_incidents_csv(request):
    """Export des incidents en CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="incidents_report.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['ID', 'Title', 'Type', 'Severity', 'Status', 'IP Source', 'Detected At', 'Resolved At'])
    
    incidents = Incident.objects.all().order_by('-detected_at')
    
    for inc in incidents:
        writer.writerow([
            inc.id,
            inc.title,
            inc.get_incident_type_display(),
            inc.get_severity_display(),
            inc.get_status_display(),
            inc.source_ip or '-',
            inc.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
            inc.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if inc.resolved_at else '-'
        ])
    
    return response

@login_required
def export_incidents_pdf(request):
    """Export des incidents en PDF"""
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="incidents_report.pdf"'
    
    doc = SimpleDocTemplate(response, pagesize=A4)
    elements = []
    
    styles = getSampleStyleSheet()
    
    # Titre
    title = Paragraph("<b>SOAR Security Incidents Report</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 0.5*inch))
    
    # Date
    date_text = Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(date_text)
    elements.append(Spacer(1, 0.3*inch))
    
    # Statistiques
    total = Incident.objects.count()
    critical = Incident.objects.filter(severity='critical').count()
    resolved = Incident.objects.filter(status='resolved').count()
    
    stats_text = f"<b>Statistics:</b> Total: {total} | Critical: {critical} | Resolved: {resolved}"
    stats = Paragraph(stats_text, styles['Normal'])
    elements.append(stats)
    elements.append(Spacer(1, 0.3*inch))
    
    # Table des incidents
    data = [['ID', 'Title', 'Type', 'Severity', 'Status', 'IP']]
    
    incidents = Incident.objects.all().order_by('-detected_at')[:50]  # 50 derniers
    
    for inc in incidents:
        data.append([
            str(inc.id),
            inc.title[:30],
            inc.get_incident_type_display()[:15],
            inc.get_severity_display(),
            inc.get_status_display(),
            inc.source_ip or '-'
        ])
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(table)
    
    doc.build(elements)
    return response

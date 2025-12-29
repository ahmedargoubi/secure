#!/bin/bash

echo "🔧 ===== REMPLACEMENT DES FICHIERS POUR DÉTECTION RÉELLE ====="
echo ""

cd ~/secureflow

# ========================================
# BACKUP DES FICHIERS ACTUELS
# ========================================
echo "💾 Sauvegarde des fichiers actuels..."

BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

cp incidents/views.py "$BACKUP_DIR/" 2>/dev/null
cp security_agent.py "$BACKUP_DIR/" 2>/dev/null

echo "✅ Backup créé: $BACKUP_DIR/"

# ========================================
# REMPLACER incidents/views.py
# ========================================
echo ""
echo "📝 Remplacement de incidents/views.py..."

cat > incidents/views.py << 'VIEWSEOF'
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
VIEWSEOF

echo "✅ incidents/views.py remplacé"

# ========================================
# REMPLACER security_agent.py
# ========================================
echo ""
echo "📝 Remplacement de security_agent.py..."

# Le contenu est déjà dans l'artifact ci-dessus
# Je vais le copier directement

cat > security_agent.py << 'AGENTEOF'
#!/usr/bin/env python3
"""Agent de Sécurité - VERSION FINALE"""

import re, time, json, requests, subprocess, os, sys, signal, threading
from datetime import datetime
from collections import defaultdict

SOAR_URL = "http://127.0.0.1:8000"
SERVER_IP = "192.168.163.135"
running = True
events_buffer = []
alert_tracker = defaultdict(float)

def signal_handler(sig, frame):
    global running
    print("\n🛑 Arrêt...")
    running = False
    send_to_soar()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def send_to_soar():
    global events_buffer
    if not events_buffer:
        return
    try:
        print(f"\n📤 Envoi {len(events_buffer)} événement(s)...")
        r = requests.post(f"{SOAR_URL}/api/incidents/import/", json={'events': events_buffer}, timeout=10)
        if r.status_code in [200, 201]:
            print(f"✅ Envoyé: {r.json()}")
            events_buffer = []
        else:
            print(f"❌ HTTP {r.status_code}: {r.text}")
            save_local()
    except Exception as e:
        print(f"❌ Erreur: {e}")
        save_local()

def save_local():
    global events_buffer
    if not events_buffer:
        return
    f = f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(f, 'w') as fp:
        json.dump(events_buffer, fp, indent=2)
    print(f"💾 Sauvegardé: {f}")
    events_buffer = []

def create_event(etype, ip, desc, sev='high'):
    global events_buffer, alert_tracker
    key = f"{etype}_{ip}"
    now = time.time()
    if key in alert_tracker and now - alert_tracker[key] < 60:
        return
    alert_tracker[key] = now
    
    evt = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event_type': etype,
        'source_ip': ip,
        'destination_ip': SERVER_IP,
        'severity': sev,
        'description': desc,
        'details': {}
    }
    events_buffer.append(evt)
    emoji = {'ssh_bruteforce':'🔐', 'port_scan':'🔍', 'web_attack':'🌐', 'sql_injection':'💉', 'ddos_attack':'💥'}.get(etype, '⚠️')
    print(f"\n{emoji} {etype} depuis {ip} ({sev})")
    
    if len(events_buffer) >= 3:
        send_to_soar()

def monitor_ssh():
    print("👁️  [SSH] Monitoring auth.log...")
    try:
        p = subprocess.Popen(['tail', '-f', '-n', '0', '/var/log/auth.log'], stdout=subprocess.PIPE, universal_newlines=True)
        for line in p.stdout:
            if not running:
                break
            if 'Failed password' in line or 'Invalid user' in line:
                m = re.search(r'from ([\d.]+)', line)
                if m:
                    create_event('ssh_bruteforce', m.group(1), f"SSH bruteforce depuis {m.group(1)}", 'high')
    except:
        pass

def monitor_ufw():
    print("👁️  [PORT] Monitoring ufw.log...")
    scan = defaultdict(set)
    try:
        p = subprocess.Popen(['tail', '-f', '-n', '0', '/var/log/ufw.log'], stdout=subprocess.PIPE, universal_newlines=True)
        for line in p.stdout:
            if not running:
                break
            m = re.search(r'SRC=([\d.]+).*DPT=(\d+)', line)
            if m:
                ip, port = m.groups()
                if ip not in ['127.0.0.1', SERVER_IP]:
                    scan[ip].add(port)
                    if len(scan[ip]) >= 3:
                        create_event('port_scan', ip, f"Port scan {len(scan[ip])} ports", 'medium')
                        scan[ip].clear()
    except:
        pass

def monitor_web():
    logs = ['/var/log/nginx/access.log', '/var/log/apache2/access.log']
    log = next((l for l in logs if os.path.exists(l)), None)
    if not log:
        print("⚠️  [WEB] Pas de log web")
        return
    print(f"👁️  [WEB] Monitoring {log}...")
    
    pats = {
        'sql_injection': [r"'.*or.*'.*=.*'", r'union.*select', r'--'],
        'xss': [r'<script', r'alert\('],
        'lfi': [r'\.\./', r'/etc/passwd']
    }
    
    try:
        p = subprocess.Popen(['tail', '-f', '-n', '0', log], stdout=subprocess.PIPE, universal_newlines=True)
        for line in p.stdout:
            if not running:
                break
            m = re.match(r'([\d.]+)', line)
            if not m or m.group(1) in ['127.0.0.1', SERVER_IP]:
                continue
            ip = m.group(1)
            
            for pt in pats['sql_injection']:
                if re.search(pt, line, re.I):
                    create_event('sql_injection', ip, f"SQL Injection depuis {ip}", 'critical')
                    break
            for pt in pats['xss']:
                if re.search(pt, line, re.I):
                    create_event('web_attack', ip, f"XSS depuis {ip}", 'critical')
                    break
            for pt in pats['lfi']:
                if re.search(pt, line, re.I):
                    create_event('web_attack', ip, f"LFI depuis {ip}", 'critical')
                    break
    except:
        pass

def monitor_ddos():
    print("👁️  [DDOS] Monitoring connexions...")
    while running:
        try:
            r = subprocess.run(['ss', '-tn', 'state', 'established'], capture_output=True, text=True, timeout=5)
            conns = defaultdict(int)
            for line in r.stdout.split('\n'):
                m = re.search(r'([\d.]+):[\d]+\s+([\d.]+):[\d]+', line)
                if m:
                    remote = m.group(2)
                    if remote not in ['127.0.0.1', SERVER_IP]:
                        conns[remote] += 1
            
            for ip, cnt in conns.items():
                if cnt >= 15:
                    create_event('ddos_attack', ip, f"DDoS {cnt} connexions depuis {ip}", 'critical')
            time.sleep(5)
        except:
            time.sleep(5)

def main():
    print("="*70)
    print("🛡️  AGENT SECUREFLOW")
    print("="*70)
    print(f"SOAR: {SOAR_URL}")
    print(f"Heure: {datetime.now().strftime('%H:%M:%S')}")
    print("="*70 + "\n")
    
    if os.geteuid() != 0:
        print("❌ Lancez en root: sudo python3 security_agent.py")
        sys.exit(1)
    
    try:
        r = requests.get(f"{SOAR_URL}/admin/", timeout=5)
        print(f"✅ SOAR accessible\n")
    except:
        print(f"⚠️ SOAR non accessible\n")
    
    threads = [
        threading.Thread(target=monitor_ssh, daemon=True),
        threading.Thread(target=monitor_ufw, daemon=True),
        threading.Thread(target=monitor_web, daemon=True),
        threading.Thread(target=monitor_ddos, daemon=True),
    ]
    
    for t in threads:
        t.start()
        time.sleep(0.3)
    
    print("✅ Moniteurs démarrés\n")
    
    try:
        while running:
            time.sleep(10)
            if events_buffer:
                send_to_soar()
    except KeyboardInterrupt:
        print("\n🛑 Arrêt...")
    finally:
        running = False
        send_to_soar()
        print("👋 Terminé")

if __name__ == '__main__':
    main()
AGENTEOF

chmod +x security_agent.py

echo "✅ security_agent.py remplacé"

# ========================================
# REDÉMARRER LES SERVICES
# ========================================
echo ""
echo "🔄 Redémarrage des services..."

# Arrêter ancien agent
sudo pkill -f security_agent
sleep 2

# Redémarrer Celery
pkill -f celery
sleep 2

source venv/bin/activate

nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &
sleep 3
echo "✅ Celery redémarré"

# Démarrer nouvel agent
sudo nohup python3 security_agent.py > logs/agent.log 2>&1 &
sleep 2

if ps aux | grep -v grep | grep -q "security_agent.py"; then
    echo "✅ Agent démarré"
else
    echo "❌ Agent non démarré"
fi

# ========================================
# TESTS
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 TESTS À FAIRE DEPUIS KALI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "1️⃣ SSH Bruteforce:"
echo "   hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.163.135 -t 4"
echo ""

echo "2️⃣ Port Scan:"
echo "   nmap -sS -p 1-100 192.168.163.135"
echo ""

echo "3️⃣ SQL Injection:"
echo "   curl \"http://192.168.163.135/?id=1' OR '1'='1\""
echo ""

echo "4️⃣ DDoS:"
echo "   for i in {1..30}; do (nc -w 1 192.168.163.135 22 &); done"
echo ""

echo "SUR UBUNTU, SURVEILLEZ:"
echo "   tail -f logs/agent.log"
echo "   tail -f logs/celery.log"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ REMPLACEMENT TERMINÉ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Dashboard: http://192.168.163.135:8000"
echo "📝 Logs agent: tail -f logs/agent.log"
echo ""

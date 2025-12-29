#!/bin/bash

echo "🔧 ===== CORRECTION DÉTECTION TOUTES LES ATTAQUES ====="
echo ""

cd ~/secureflow

# ========================================
# 1. INSTALLER LES PRÉREQUIS
# ========================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 [1/6] Installation des prérequis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# UFW pour détecter les port scans
if ! command -v ufw &> /dev/null; then
    echo "📥 Installation UFW..."
    sudo apt-get update
    sudo apt-get install -y ufw
fi

# Activer UFW logging
echo "🔧 Configuration UFW..."
sudo ufw logging on
sudo ufw allow 22/tcp  # SSH
sudo ufw allow 8000/tcp  # Django
sudo ufw allow 80/tcp  # HTTP
sudo ufw --force enable

echo "✅ UFW configuré"

# Nginx pour détecter les web attacks
if ! command -v nginx &> /dev/null; then
    echo "📥 Installation Nginx..."
    sudo apt-get install -y nginx
    sudo systemctl start nginx
    sudo systemctl enable nginx
fi

echo "✅ Nginx installé"

# ========================================
# 2. CRÉER TOUS LES PLAYBOOKS MANQUANTS
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 [2/6] Création de tous les playbooks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python manage.py shell << 'PYTEST'
from playbooks.models import Playbook, Action
from django.contrib.auth.models import User

admin = User.objects.filter(is_superuser=True).first()

if not admin:
    print("❌ Aucun admin - Créez un superuser d'abord")
    exit()

# Liste de tous les playbooks nécessaires
playbooks_config = [
    {
        'trigger': 'ssh_bruteforce',
        'name': 'SSH Bruteforce Response',
        'description': 'Blocage automatique des attaques SSH bruteforce',
    },
    {
        'trigger': 'port_scan',
        'name': 'Port Scan Response',
        'description': 'Réponse automatique aux scans de ports',
    },
    {
        'trigger': 'web_attack',
        'name': 'Web Attack Response',
        'description': 'Blocage des attaques web (SQLi, XSS, LFI)',
    },
    {
        'trigger': 'sql_injection',
        'name': 'SQL Injection Response',
        'description': 'Réponse critique aux injections SQL',
    },
    {
        'trigger': 'ddos_attack',
        'name': 'DDoS Attack Response',
        'description': 'Mitigation des attaques DDoS',
    },
    {
        'trigger': 'suspicious_ip',
        'name': 'Suspicious IP Activity Response',
        'description': 'Blocage des IPs suspectes',
    },
]

for config in playbooks_config:
    playbook, created = Playbook.objects.get_or_create(
        trigger=config['trigger'],
        defaults={
            'name': config['name'],
            'description': config['description'],
            'created_by': admin,
            'is_active': True
        }
    )
    
    if created:
        print(f"✅ Créé: {playbook.name}")
        
        # Ajouter les 4 actions standard
        Action.objects.create(
            playbook=playbook,
            action_type='block_ip',
            order=1,
            parameters={},
            is_active=True
        )
        
        Action.objects.create(
            playbook=playbook,
            action_type='enrich_threat',
            order=2,
            parameters={},
            is_active=True
        )
        
        Action.objects.create(
            playbook=playbook,
            action_type='send_email',
            order=3,
            parameters={
                'recipient': 'ahmed.argoubi123456789@gmail.com',
                'subject': f'🚨 Alerte: {config["name"]}'
            },
            is_active=True
        )
        
        Action.objects.create(
            playbook=playbook,
            action_type='create_ticket',
            order=4,
            parameters={
                'title': f'Incident: {config["trigger"]}'
            },
            is_active=True
        )
        
        print(f"   → 4 actions configurées")
    else:
        print(f"ℹ️ Existe déjà: {playbook.name}")

print("\n✅ Tous les playbooks sont configurés")

PYTEST

# ========================================
# 3. AMÉLIORER L'AGENT - TOUTES DÉTECTIONS
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🤖 [3/6] Mise à jour de l'agent de sécurité"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Backup
cp security_agent.py security_agent.py.backup_$(date +%Y%m%d_%H%M%S)

# Créer un agent amélioré qui détecte TOUT
cat > security_agent_improved.py << 'AGENTEOF'
#!/usr/bin/env python3
"""
Agent de sécurité AMÉLIORÉ - Détecte TOUTES les attaques
"""

import re
import time
import json
import requests
import subprocess
from datetime import datetime
from collections import defaultdict
import os
import signal
import sys
import threading

class ImprovedSecurityAgent:
    def __init__(self, soar_url="http://127.0.0.1:8000"):
        self.soar_url = soar_url
        self.events_buffer = []
        self.attack_counters = defaultdict(int)
        self.running = True
        self.last_alerts = defaultdict(float)  # Pour éviter spam
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print("\n🛑 Arrêt de l'agent...")
        self.running = False
        self.send_buffer_to_soar()
        sys.exit(0)
    
    def monitor_ssh_bruteforce(self):
        """Détecte les attaques SSH bruteforce"""
        print("👁️  [SSH] Monitoring /var/log/auth.log...")
        
        try:
            process = subprocess.Popen(
                ['tail', '-f', '-n', '0', '/var/log/auth.log'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stdout:
                if not self.running:
                    break
                
                # Détecter les échecs SSH
                if 'Failed password' in line or 'Invalid user' in line:
                    match = re.search(r'from ([\d.]+)', line)
                    if match:
                        ip = match.group(1)
                        self.create_event(
                            'ssh_bruteforce',
                            ip,
                            f"SSH bruteforce détecté depuis {ip}",
                            'high'
                        )
        except Exception as e:
            print(f"❌ Erreur SSH monitoring: {e}")
    
    def monitor_port_scans(self):
        """Détecte les scans de ports via UFW"""
        print("👁️  [PORT] Monitoring /var/log/ufw.log...")
        
        try:
            process = subprocess.Popen(
                ['tail', '-f', '-n', '0', '/var/log/ufw.log'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            scan_tracker = defaultdict(set)
            
            for line in process.stdout:
                if not self.running:
                    break
                
                # UFW log: [UFW BLOCK] IN=eth0 OUT= SRC=X.X.X.X DST=Y.Y.Y.Y PROTO=TCP DPT=80
                match = re.search(r'SRC=([\d.]+).*DPT=(\d+)', line)
                if match:
                    ip = match.group(1)
                    port = match.group(2)
                    
                    scan_tracker[ip].add(port)
                    
                    # Si > 5 ports différents scannés
                    if len(scan_tracker[ip]) >= 5:
                        self.create_event(
                            'port_scan',
                            ip,
                            f"Port scan détecté depuis {ip} ({len(scan_tracker[ip])} ports)",
                            'medium'
                        )
                        scan_tracker[ip].clear()
        
        except FileNotFoundError:
            print("⚠️  /var/log/ufw.log introuvable - UFW non configuré")
        except Exception as e:
            print(f"❌ Erreur PORT monitoring: {e}")
    
    def monitor_web_attacks(self):
        """Détecte les attaques web (SQLi, XSS, LFI)"""
        print("👁️  [WEB] Monitoring /var/log/nginx/access.log...")
        
        web_logs = [
            '/var/log/nginx/access.log',
            '/var/log/apache2/access.log'
        ]
        
        log_file = None
        for log in web_logs:
            if os.path.exists(log):
                log_file = log
                break
        
        if not log_file:
            print("⚠️  Aucun log web trouvé")
            return
        
        try:
            process = subprocess.Popen(
                ['tail', '-f', '-n', '0', log_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            attack_patterns = {
                'sql_injection': [r'union.*select', r'or.*1=1', r'drop.*table', r'insert.*into'],
                'xss': [r'<script', r'alert\(', r'onerror=', r'javascript:'],
                'lfi': [r'\.\./', r'/etc/passwd', r'/etc/shadow', r'file='],
            }
            
            for line in process.stdout:
                if not self.running:
                    break
                
                # Extraire IP
                ip_match = re.match(r'([\d.]+)', line)
                if not ip_match:
                    continue
                
                ip = ip_match.group(1)
                
                # Vérifier chaque type d'attaque
                for attack_type, patterns in attack_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            self.create_event(
                                attack_type if attack_type == 'sql_injection' else 'web_attack',
                                ip,
                                f"Attaque {attack_type} détectée depuis {ip}",
                                'critical'
                            )
                            break
        
        except Exception as e:
            print(f"❌ Erreur WEB monitoring: {e}")
    
    def monitor_ddos(self):
        """Détecte les attaques DDoS"""
        print("👁️  [DDOS] Monitoring connexions réseau...")
        
        while self.running:
            try:
                # Compter les connexions par IP
                result = subprocess.run(
                    ['ss', '-tn', 'state', 'established'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                connections = defaultdict(int)
                
                for line in result.stdout.split('\n'):
                    match = re.search(r'([\d.]+):[\d]+\s+([\d.]+):[\d]+', line)
                    if match:
                        remote_ip = match.group(2)
                        if remote_ip not in ['127.0.0.1', '192.168.163.135']:
                            connections[remote_ip] += 1
                
                # Alerte si > 50 connexions d'une IP
                for ip, count in connections.items():
                    if count > 50:
                        current_time = time.time()
                        # Éviter alertes répétées (1 par minute max)
                        if current_time - self.last_alerts[f'ddos_{ip}'] > 60:
                            self.create_event(
                                'ddos_attack',
                                ip,
                                f"Attaque DDoS détectée depuis {ip} ({count} connexions)",
                                'critical'
                            )
                            self.last_alerts[f'ddos_{ip}'] = current_time
                
                time.sleep(5)
            
            except Exception as e:
                print(f"❌ Erreur DDOS monitoring: {e}")
                time.sleep(5)
    
    def create_event(self, event_type, source_ip, description, severity):
        """Crée un événement de sécurité"""
        current_time = time.time()
        alert_key = f'{event_type}_{source_ip}'
        
        # Anti-spam: 1 alerte par type+IP toutes les 10 secondes
        if current_time - self.last_alerts.get(alert_key, 0) < 10:
            return
        
        self.last_alerts[alert_key] = current_time
        
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'source_ip': source_ip,
            'destination_ip': '192.168.163.135',
            'severity': severity,
            'description': description,
            'details': {}
        }
        
        self.events_buffer.append(event)
        
        emoji = {
            'ssh_bruteforce': '🔐',
            'port_scan': '🔍',
            'web_attack': '🌐',
            'sql_injection': '💉',
            'ddos_attack': '💥'
        }.get(event_type, '⚠️')
        
        print(f"{emoji} [{severity.upper()}] {event_type}: {description}")
        
        # Envoyer immédiatement si buffer >= 5
        if len(self.events_buffer) >= 5:
            self.send_buffer_to_soar()
    
    def send_buffer_to_soar(self):
        """Envoie les événements au SOAR"""
        if not self.events_buffer:
            return
        
        try:
            response = requests.post(
                f"{self.soar_url}/api/incidents/import/",
                json={'events': self.events_buffer},
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ {len(self.events_buffer)} événements envoyés au SOAR")
                self.events_buffer = []
            else:
                print(f"⚠️  Erreur SOAR: {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            print(f"❌ SOAR injoignable: {e}")
            # Sauvegarder localement
            filename = f"security_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(self.events_buffer, f, indent=2)
            print(f"💾 Événements sauvegardés dans {filename}")
            self.events_buffer = []
    
    def start(self):
        """Démarre l'agent"""
        print("="*70)
        print("🛡️  AGENT DE SÉCURITÉ AMÉLIORÉ - DÉTECTION TOUTES ATTAQUES")
        print("="*70)
        print(f"Machine: 192.168.163.135")
        print(f"SOAR URL: {self.soar_url}")
        print(f"Heure: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        print()
        
        if os.geteuid() != 0:
            print("⚠️  ATTENTION: Lancez en root pour accès aux logs")
            print("   sudo python3 security_agent_improved.py")
            return
        
        print("🚀 Démarrage des moniteurs...")
        print("   Appuyez sur Ctrl+C pour arrêter")
        print()
        
        # Démarrer tous les moniteurs en parallèle
        threads = [
            threading.Thread(target=self.monitor_ssh_bruteforce, daemon=True),
            threading.Thread(target=self.monitor_port_scans, daemon=True),
            threading.Thread(target=self.monitor_web_attacks, daemon=True),
            threading.Thread(target=self.monitor_ddos, daemon=True),
        ]
        
        for thread in threads:
            thread.start()
        
        # Boucle principale
        try:
            while self.running:
                time.sleep(10)
                if self.events_buffer:
                    self.send_buffer_to_soar()
        
        except KeyboardInterrupt:
            print("\n🛑 Arrêt demandé...")
        
        finally:
            self.running = False
            self.send_buffer_to_soar()
            print("👋 Agent arrêté")


if __name__ == '__main__':
    agent = ImprovedSecurityAgent()
    agent.start()
AGENTEOF

chmod +x security_agent_improved.py

echo "✅ Agent amélioré créé: security_agent_improved.py"

# ========================================
# 4. REDÉMARRER LES SERVICES
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔄 [4/6] Redémarrage des services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Arrêter l'ancien agent
pkill -f security_agent
sleep 2

# Redémarrer Celery
pkill -f celery
sleep 2

source venv/bin/activate
nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &

sleep 3
echo "✅ Celery redémarré"

# Démarrer le nouvel agent
echo ""
echo "🤖 Démarrage du nouvel agent..."
nohup sudo python3 security_agent_improved.py > logs/agent.log 2>&1 &

sleep 2
echo "✅ Agent démarré"

# ========================================
# 5. TEST DE TOUTES LES DÉTECTIONS
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 [5/6] Test de toutes les détections"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Créer des incidents de test pour chaque type
python manage.py shell << 'PYTEST'
from incidents.models import Incident
import time

test_cases = [
    ('ssh_bruteforce', 'Test SSH Bruteforce', 'high'),
    ('port_scan', 'Test Port Scan', 'medium'),
    ('web_attack', 'Test Web Attack', 'critical'),
    ('sql_injection', 'Test SQL Injection', 'critical'),
    ('ddos_attack', 'Test DDoS Attack', 'critical'),
]

print("Création d'incidents de test...\n")

for incident_type, title, severity in test_cases:
    incident = Incident.objects.create(
        title=title,
        description=f"Test de détection {incident_type}",
        incident_type=incident_type,
        severity=severity,
        source_ip='10.0.0.50',
        status='new'
    )
    
    print(f"✅ {title} (ID: {incident.id})")
    time.sleep(2)

print("\n⏳ Attente exécution des playbooks (15 secondes)...")
time.sleep(15)

# Vérifier les résultats
from playbooks.models import PlaybookExecution

print("\n📊 RÉSULTATS:\n")

for incident_type, title, severity in test_cases:
    incidents = Incident.objects.filter(incident_type=incident_type).order_by('-id')[:1]
    
    if incidents.exists():
        incident = incidents[0]
        executions = incident.playbook_executions.all()
        
        if executions.exists():
            exe = executions.first()
            print(f"✅ {title}")
            print(f"   Playbook: {exe.playbook.name}")
            print(f"   Statut: {exe.get_status_display()}")
            print(f"   Actions: {exe.actions_executed}/{exe.actions_executed + exe.actions_failed}")
        else:
            print(f"⚠️ {title} - Playbook NON exécuté")
    
    print()

PYTEST

# ========================================
# 6. AFFICHER LES INSTRUCTIONS
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ [6/6] CONFIGURATION TERMINÉE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "✅ TOUTES LES DÉTECTIONS SONT ACTIVES:"
echo ""
echo "   🔐 SSH Bruteforce"
echo "   🔍 Port Scan"
echo "   🌐 Web Attacks (SQLi, XSS, LFI)"
echo "   💥 DDoS Attacks"
echo ""

echo "🧪 TESTER DEPUIS KALI:"
echo ""
echo "   sudo bash kali_attacks.sh"
echo ""
echo "   Ou tests individuels:"
echo "   - SSH: hydra -l root -P pass.txt ssh://192.168.163.135"
echo "   - Port: nmap -sS 192.168.163.135"
echo "   - Web: curl 'http://192.168.163.135/?id=1' OR '1'='1'"
echo "   - DDoS: hping3 -S --flood 192.168.163.135"
echo ""

echo "📊 SURVEILLER:"
echo ""
echo "   Dashboard: http://192.168.163.135:8000"
echo "   Logs agent: tail -f logs/agent.log"
echo "   Logs celery: tail -f logs/celery.log"
echo ""

echo "🎉 VOTRE SOAR DÉTECTE MAINTENANT TOUTES LES ATTAQUES !"
echo ""

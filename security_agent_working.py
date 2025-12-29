#!/usr/bin/env python3
"""
Agent de sécurité FONCTIONNEL - Détection réelle des attaques
"""

import re
import time
import json
import requests
import subprocess
import os
import sys
import signal
from datetime import datetime
from collections import defaultdict

SOAR_URL = "http://127.0.0.1:8000"
SERVER_IP = "192.168.163.135"

# État global
running = True
events_buffer = []
alert_tracker = {}  # Pour éviter spam

def signal_handler(sig, frame):
    global running
    print("\n🛑 Arrêt de l'agent...")
    running = False
    send_events_to_soar()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def send_events_to_soar():
    """Envoie les événements au SOAR"""
    global events_buffer
    
    if not events_buffer:
        return
    
    try:
        response = requests.post(
            f"{SOAR_URL}/api/incidents/import/",
            json={'events': events_buffer},
            timeout=5
        )
        
        if response.status_code in [200, 201]:
            print(f"✅ {len(events_buffer)} événements envoyés au SOAR")
            events_buffer = []
        else:
            print(f"⚠️ Erreur SOAR HTTP {response.status_code}")
    
    except Exception as e:
        print(f"❌ Erreur envoi SOAR: {e}")
        # Sauvegarder localement
        filename = f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(events_buffer, f, indent=2)
        print(f"💾 Sauvegardé dans {filename}")
        events_buffer = []

def create_event(event_type, source_ip, description, severity='high'):
    """Crée un événement avec anti-spam"""
    global events_buffer, alert_tracker
    
    # Anti-spam: 1 alerte par IP+Type toutes les 30 secondes
    key = f"{event_type}_{source_ip}"
    now = time.time()
    
    if key in alert_tracker:
        if now - alert_tracker[key] < 30:
            return  # Trop récent, ignorer
    
    alert_tracker[key] = now
    
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event_type': event_type,
        'source_ip': source_ip,
        'destination_ip': SERVER_IP,
        'severity': severity,
        'description': description,
        'details': {}
    }
    
    events_buffer.append(event)
    
    emoji = {
        'ssh_bruteforce': '🔐',
        'port_scan': '🔍',
        'web_attack': '🌐',
        'sql_injection': '💉',
        'ddos_attack': '💥'
    }.get(event_type, '⚠️')
    
    print(f"{emoji} [{severity.upper()}] {event_type} depuis {source_ip}")
    
    # Envoyer si buffer >= 3
    if len(events_buffer) >= 3:
        send_events_to_soar()

def monitor_ssh():
    """Surveille les attaques SSH"""
    print("👁️  [SSH] Monitoring auth.log...")
    
    try:
        cmd = ['tail', '-f', '-n', '0', '/var/log/auth.log']
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        for line in process.stdout:
            if not running:
                break
            
            if 'Failed password' in line or 'Invalid user' in line:
                match = re.search(r'from ([\d.]+)', line)
                if match:
                    ip = match.group(1)
                    create_event('ssh_bruteforce', ip, f"SSH bruteforce depuis {ip}", 'high')
    
    except Exception as e:
        print(f"❌ Erreur SSH: {e}")

def monitor_ufw():
    """Surveille les scans de ports"""
    print("👁️  [PORT] Monitoring ufw.log...")
    
    scan_counter = defaultdict(set)
    
    try:
        cmd = ['tail', '-f', '-n', '0', '/var/log/ufw.log']
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        for line in process.stdout:
            if not running:
                break
            
            match = re.search(r'SRC=([\d.]+).*DPT=(\d+)', line)
            if match:
                ip, port = match.groups()
                scan_counter[ip].add(port)
                
                if len(scan_counter[ip]) >= 3:
                    create_event('port_scan', ip, f"Port scan depuis {ip} ({len(scan_counter[ip])} ports)", 'medium')
                    scan_counter[ip].clear()
    
    except FileNotFoundError:
        print("⚠️ /var/log/ufw.log introuvable")
    except Exception as e:
        print(f"❌ Erreur UFW: {e}")

def monitor_web():
    """Surveille les attaques web"""
    
    # Trouver le bon fichier de log
    log_file = None
    for path in ['/var/log/nginx/access.log', '/var/log/apache2/access.log']:
        if os.path.exists(path):
            log_file = path
            break
    
    if not log_file:
        print("⚠️ [WEB] Aucun log web trouvé")
        return
    
    print(f"👁️  [WEB] Monitoring {log_file}...")
    
    patterns = {
        'sql_injection': [r'union.*select', r"'.*or.*'1'.*=.*'1", r'drop.*table', r'--'],
        'xss': [r'<script', r'alert\(', r'onerror=', r'javascript:'],
        'lfi': [r'\.\./', r'/etc/passwd', r'file=']
    }
    
    try:
        cmd = ['tail', '-f', '-n', '0', log_file]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        for line in process.stdout:
            if not running:
                break
            
            # Extraire IP (format: 192.168.x.x - - [date] "GET ...")
            ip_match = re.match(r'([\d.]+)', line)
            if not ip_match:
                continue
            
            ip = ip_match.group(1)
            
            # Vérifier SQLi
            for pattern in patterns['sql_injection']:
                if re.search(pattern, line, re.IGNORECASE):
                    create_event('sql_injection', ip, f"SQL Injection depuis {ip}", 'critical')
                    break
            
            # Vérifier XSS
            for pattern in patterns['xss']:
                if re.search(pattern, line, re.IGNORECASE):
                    create_event('web_attack', ip, f"XSS attack depuis {ip}", 'critical')
                    break
            
            # Vérifier LFI
            for pattern in patterns['lfi']:
                if re.search(pattern, line, re.IGNORECASE):
                    create_event('web_attack', ip, f"LFI attack depuis {ip}", 'critical')
                    break
    
    except Exception as e:
        print(f"❌ Erreur WEB: {e}")

def monitor_ddos():
    """Surveille les attaques DDoS"""
    print("👁️  [DDOS] Monitoring connexions...")
    
    while running:
        try:
            result = subprocess.run(
                ['ss', '-tn'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            connections = defaultdict(int)
            
            for line in result.stdout.split('\n'):
                match = re.search(r'([\d.]+):[\d]+\s+([\d.]+):[\d]+', line)
                if match:
                    remote_ip = match.group(2)
                    if remote_ip not in ['127.0.0.1', SERVER_IP]:
                        connections[remote_ip] += 1
            
            for ip, count in connections.items():
                if count > 20:  # Seuil abaissé pour test
                    create_event('ddos_attack', ip, f"DDoS depuis {ip} ({count} connexions)", 'critical')
            
            time.sleep(5)
        
        except Exception as e:
            print(f"❌ Erreur DDOS: {e}")
            time.sleep(5)

def main():
    print("="*70)
    print("🛡️  AGENT DE SÉCURITÉ - DÉTECTION RÉELLE")
    print("="*70)
    print(f"Serveur: {SERVER_IP}")
    print(f"SOAR: {SOAR_URL}")
    print(f"Heure: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    print()
    
    if os.geteuid() != 0:
        print("❌ Erreur: Ce script doit être exécuté en root")
        print("   Relancez avec: sudo python3 security_agent_working.py")
        sys.exit(1)
    
    print("🚀 Démarrage des moniteurs (Ctrl+C pour arrêter)...")
    print()
    
    # Démarrer les moniteurs en threads
    import threading
    
    threads = [
        threading.Thread(target=monitor_ssh, daemon=True),
        threading.Thread(target=monitor_ufw, daemon=True),
        threading.Thread(target=monitor_web, daemon=True),
        threading.Thread(target=monitor_ddos, daemon=True),
    ]
    
    for t in threads:
        t.start()
    
    # Boucle principale
    try:
        while running:
            time.sleep(10)
            if events_buffer:
                send_events_to_soar()
    
    except KeyboardInterrupt:
        print("\n🛑 Arrêt demandé...")
    
    finally:
        send_events_to_soar()
        print("👋 Agent arrêté")

if __name__ == '__main__':
    main()

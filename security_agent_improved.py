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

#!/usr/bin/env python3
"""
Agent de sécurité pour capturer les attaques réelles
À installer sur la machine Ubuntu (192.168.163.135)
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

class SecurityAgent:
    def __init__(self, soar_url="http://127.0.0.1:8000"):
        self.soar_url = soar_url
        self.events_buffer = []
        self.attack_counters = defaultdict(int)
        self.running = True
        
        # Patterns de détection
        self.patterns = {
            'ssh_bruteforce': [
                r'Failed password for .* from ([\d.]+)',
                r'Invalid user .* from ([\d.]+)',
                r'Connection closed by ([\d.]+) port \d+ \[preauth\]'
            ],
            'port_scan': [
                r'SYN.*SRC=([\d.]+).*DPT=(\d+)',
            ],
            'web_attack': [
                r'([\d.]+).*"(GET|POST).*(\.\./|union|select|script|<script|alert\()',
            ]
        }
        
        # Configurer le signal handler pour arrêt propre
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        """Gère l'arrêt propre de l'agent"""
        print("\n🛑 Arrêt de l'agent...")
        self.running = False
        self.send_buffer_to_soar()
        sys.exit(0)
    
    def check_root(self):
        """Vérifie si l'agent tourne en root"""
        if os.geteuid() != 0:
            print("⚠️  ATTENTION: L'agent doit être exécuté en root pour accéder aux logs")
            print("   Relancez avec: sudo python3 security_agent.py")
            return False
        return True
    
    def setup_logging(self):
        """Configure les logs système nécessaires"""
        print("📋 Configuration des logs système...")
        
        # Activer le logging SSH détaillé
        try:
            subprocess.run(['sed', '-i', 's/#LogLevel INFO/LogLevel VERBOSE/', 
                          '/etc/ssh/sshd_config'], check=False)
            subprocess.run(['systemctl', 'restart', 'sshd'], check=False)
            print("✅ Logs SSH configurés")
        except Exception as e:
            print(f"⚠️  Erreur config SSH: {e}")
        
        # Activer UFW logging pour les scans de ports
        try:
            subprocess.run(['ufw', 'logging', 'on'], check=False)
            print("✅ UFW logging activé")
        except Exception as e:
            print(f"⚠️  Erreur UFW: {e}")
    
    def monitor_ssh_logs(self):
        """Surveille les logs SSH pour détecter les bruteforce"""
        try:
            process = subprocess.Popen(
                ['tail', '-f', '-n', '0', '/var/log/auth.log'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            print("👁️  Monitoring SSH logs...")
            
            for line in process.stdout:
                if not self.running:
                    process.kill()
                    break
                
                for event_type, patterns in self.patterns.items():
                    if event_type == 'ssh_bruteforce':
                        for pattern in patterns:
                            match = re.search(pattern, line)
                            if match:
                                source_ip = match.group(1)
                                self.create_event(
                                    event_type='ssh_bruteforce',
                                    source_ip=source_ip,
                                    description=f"SSH attack detected from {source_ip}",
                                    severity='high',
                                    details={'log_line': line.strip()}
                                )
                                break
        
        except Exception as e:
            print(f"❌ Erreur monitoring SSH: {e}")
    
    def monitor_ufw_logs(self):
        """Surveille les logs UFW pour détecter les scans de ports"""
        try:
            process = subprocess.Popen(
                ['tail', '-f', '-n', '0', '/var/log/ufw.log'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            print("👁️  Monitoring UFW logs...")
            
            for line in process.stdout:
                if not self.running:
                    process.kill()
                    break
                
                # Détecter les scans de ports
                match = re.search(r'SRC=([\d.]+).*DPT=(\d+)', line)
                if match:
                    source_ip = match.group(1)
                    dest_port = match.group(2)
                    
                    # Compter les connexions par IP
                    self.attack_counters[f'scan_{source_ip}'] += 1
                    
                    # Alerte si plus de 5 ports différents en peu de temps
                    if self.attack_counters[f'scan_{source_ip}'] > 5:
                        self.create_event(
                            event_type='port_scan',
                            source_ip=source_ip,
                            description=f"Port scan detected from {source_ip}",
                            severity='medium',
                            details={
                                'port': dest_port,
                                'count': self.attack_counters[f'scan_{source_ip}']
                            }
                        )
                        self.attack_counters[f'scan_{source_ip}'] = 0
        
        except FileNotFoundError:
            print("⚠️  /var/log/ufw.log non trouvé. UFW est-il activé?")
        except Exception as e:
            print(f"❌ Erreur monitoring UFW: {e}")
    
    def monitor_apache_logs(self):
        """Surveille les logs Apache pour détecter les attaques web"""
        apache_logs = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log'
        ]
        
        for log_file in apache_logs:
            if not os.path.exists(log_file):
                continue
            
            try:
                process = subprocess.Popen(
                    ['tail', '-f', '-n', '0', log_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                print(f"👁️  Monitoring {log_file}...")
                
                for line in process.stdout:
                    if not self.running:
                        process.kill()
                        break
                    
                    # Détecter les attaques web
                    suspicious_patterns = [
                        r'\.\.',  # Path traversal
                        r'union.*select',  # SQL injection
                        r'<script',  # XSS
                        r'alert\(',  # XSS
                        r'/etc/passwd',  # LFI
                        r'cmd=',  # Command injection
                    ]
                    
                    for pattern in suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Extraire l'IP source
                            ip_match = re.search(r'([\d.]+)', line)
                            if ip_match:
                                source_ip = ip_match.group(1)
                                
                                self.create_event(
                                    event_type='web_attack',
                                    source_ip=source_ip,
                                    description=f"Web attack detected from {source_ip}",
                                    severity='critical',
                                    details={
                                        'pattern': pattern,
                                        'log_line': line.strip()[:200]
                                    }
                                )
                            break
            
            except Exception as e:
                print(f"⚠️  Erreur monitoring {log_file}: {e}")
    
    def monitor_network_connections(self):
        """Surveille les connexions réseau suspectes"""
        print("👁️  Monitoring connexions réseau...")
        
        while self.running:
            try:
                # Utiliser ss pour voir les connexions
                result = subprocess.run(
                    ['ss', '-tn'],
                    capture_output=True,
                    text=True
                )
                
                # Analyser les connexions suspectes (trop nombreuses d'une même IP)
                connections = defaultdict(int)
                for line in result.stdout.split('\n'):
                    match = re.search(r'([\d.]+):[\d]+\s+([\d.]+):[\d]+', line)
                    if match:
                        remote_ip = match.group(2)
                        if remote_ip not in ['127.0.0.1', '192.168.163.135']:
                            connections[remote_ip] += 1
                
                # Alerte si plus de 50 connexions d'une même IP
                for ip, count in connections.items():
                    if count > 50:
                        self.create_event(
                            event_type='ddos_attack',
                            source_ip=ip,
                            description=f"Possible DDoS from {ip}",
                            severity='critical',
                            details={'connection_count': count}
                        )
                
                time.sleep(5)  # Vérifier toutes les 5 secondes
                
            except Exception as e:
                print(f"⚠️  Erreur monitoring réseau: {e}")
                time.sleep(5)
    
    def create_event(self, event_type, source_ip, description, severity, details=None):
        """Crée un événement de sécurité"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'source_ip': source_ip,
            'destination_ip': '192.168.163.135',
            'severity': severity,
            'description': description,
            'details': details or {}
        }
        
        self.events_buffer.append(event)
        
        # Afficher l'alerte
        emoji = {
            'ssh_bruteforce': '🔐',
            'port_scan': '🔍',
            'web_attack': '🌐',
            'ddos_attack': '💥'
        }.get(event_type, '⚠️')
        
        print(f"{emoji} [{severity.upper()}] {event_type}: {description}")
        
        # Envoyer au SOAR si buffer atteint 10 événements
        if len(self.events_buffer) >= 10:
            self.send_buffer_to_soar()
    
    def send_buffer_to_soar(self):
        """Envoie les événements en buffer au SOAR"""
        if not self.events_buffer:
            return
        
        try:
            response = requests.post(
                f"{self.soar_url}/api/incidents/import/",
                json={'events': self.events_buffer},
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"✅ {len(self.events_buffer)} événements envoyés au SOAR")
                self.events_buffer = []
            else:
                print(f"⚠️  Erreur SOAR: {response.status_code}")
                self.save_events_to_file()
        
        except requests.exceptions.RequestException as e:
            print(f"❌ SOAR injoignable: {e}")
            self.save_events_to_file()
    
    def save_events_to_file(self):
        """Sauvegarde les événements localement en cas d'échec"""
        filename = f"security_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.events_buffer, f, indent=2)
        print(f"💾 Événements sauvegardés dans {filename}")
        self.events_buffer = []
    
    def start(self):
        """Démarre l'agent de sécurité"""
        print("="*70)
        print("🛡️  AGENT DE SÉCURITÉ SOAR - DÉMARRAGE")
        print("="*70)
        print(f"Machine: 192.168.163.135")
        print(f"SOAR URL: {self.soar_url}")
        print(f"Heure: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        print()
        
        if not self.check_root():
            return
        
        self.setup_logging()
        
        print("\n🚀 Démarrage des moniteurs...")
        print("   Appuyez sur Ctrl+C pour arrêter proprement")
        print()
        
        # Démarrer les différents moniteurs en threads
        import threading
        
        threads = [
            threading.Thread(target=self.monitor_ssh_logs, daemon=True),
            threading.Thread(target=self.monitor_ufw_logs, daemon=True),
            threading.Thread(target=self.monitor_apache_logs, daemon=True),
            threading.Thread(target=self.monitor_network_connections, daemon=True),
        ]
        
        for thread in threads:
            thread.start()
        
        # Boucle principale
        try:
            while self.running:
                time.sleep(10)
                # Envoyer périodiquement le buffer
                if self.events_buffer:
                    self.send_buffer_to_soar()
        
        except KeyboardInterrupt:
            print("\n🛑 Arrêt demandé...")
        
        finally:
            self.running = False
            self.send_buffer_to_soar()
            print("👋 Agent arrêté proprement")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Agent de sécurité SOAR')
    parser.add_argument('--soar-url', default='http://127.0.0.1:8000', 
                       help='URL du serveur SOAR')
    
    args = parser.parse_args()
    
    agent = SecurityAgent(soar_url=args.soar_url)
    agent.start()

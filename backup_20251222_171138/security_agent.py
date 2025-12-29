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

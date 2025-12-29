#!/usr/bin/env python3
"""
Script pour créer TOUS les playbooks fonctionnels
Compatible avec TOUS les types d'incidents
"""

from playbooks.models import Playbook, Action
from django.contrib.auth.models import User

# Supprimer TOUS les anciens playbooks
print("🗑️  Suppression des anciens playbooks...")
Playbook.objects.all().delete()
print("✅ Playbooks supprimés")

# Récupérer l'utilisateur admin
admin_user = User.objects.filter(is_superuser=True).first()
if not admin_user:
    admin_user = User.objects.first()

print("\n" + "="*70)
print("🚀 CRÉATION DES PLAYBOOKS COMPLETS ET FONCTIONNELS")
print("="*70)

# ==================== PLAYBOOK 1: SSH BRUTEFORCE ====================
print("\n1️⃣  Créat du playbook SSH Bruteforce...")
playbook_ssh = Playbook.objects.create(
    name="🔐 SSH Bruteforce Response",
    description="Automated response to SSH brute force attacks",
    trigger='ssh_bruteforce',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_ssh, action_type='block_ip', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_ssh, action_type='enrich_threat', order=2, parameters={}, is_active=True),
    Action(playbook=playbook_ssh, action_type='send_email', order=3, parameters={
        'recipient': 'security@company.com',
        'subject': 'ALERT: SSH Bruteforce Detected'
    }, is_active=True),
    Action(playbook=playbook_ssh, action_type='create_ticket', order=4, parameters={
        'title': 'SSH Bruteforce Investigation'
    }, is_active=True),
])
print(f"   ✅ {playbook_ssh.name} - 4 actions")

# ==================== PLAYBOOK 2: PORT SCAN ====================
print("\n2️⃣  Création du playbook Port Scan...")
playbook_portscan = Playbook.objects.create(
    name="🔍 Port Scan Response",
    description="Automated response to port scanning activity",
    trigger='port_scan',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_portscan, action_type='enrich_threat', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_portscan, action_type='block_ip', order=2, parameters={}, is_active=True),
    Action(playbook=playbook_portscan, action_type='send_email', order=3, parameters={
        'recipient': 'security@company.com',
        'subject': 'ALERT: Port Scanning Detected'
    }, is_active=True),
])
print(f"   ✅ {playbook_portscan.name} - 3 actions")

# ==================== PLAYBOOK 3: SUSPICIOUS IP ====================
print("\n3️⃣  Création du playbook Suspicious IP...")
playbook_suspicious = Playbook.objects.create(
    name="🚨 Suspicious IP Response",
    description="Automated response to suspicious IP activity",
    trigger='suspicious_ip',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_suspicious, action_type='enrich_threat', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_suspicious, action_type='block_ip', order=2, parameters={}, is_active=True),
    Action(playbook=playbook_suspicious, action_type='send_email', order=3, parameters={
        'recipient': 'security@company.com',
        'subject': 'ALERT: Suspicious IP Activity'
    }, is_active=True),
])
print(f"   ✅ {playbook_suspicious.name} - 3 actions")

# ==================== PLAYBOOK 4: AUTH FAILURE ====================
print("\n4️⃣  Création du playbook Authentication Failure...")
playbook_auth = Playbook.objects.create(
    name="🔑 Authentication Failure Response",
    description="Automated response to failed authentication attempts",
    trigger='auth_failure',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_auth, action_type='block_ip', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_auth, action_type='enrich_threat', order=2, parameters={}, is_active=True),
    Action(playbook=playbook_auth, action_type='send_email', order=3, parameters={
        'recipient': 'security@company.com',
        'subject': 'ALERT: Multiple Failed Login Attempts'
    }, is_active=True),
])
print(f"   ✅ {playbook_auth.name} - 3 actions")

# ==================== PLAYBOOK 5: SQL INJECTION ====================
print("\n5️⃣  Création du playbook SQL Injection...")
playbook_sqli = Playbook.objects.create(
    name="💉 SQL Injection Response",
    description="Critical response to SQL injection attacks",
    trigger='sql_injection',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_sqli, action_type='block_ip', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_sqli, action_type='send_email', order=2, parameters={
        'recipient': 'security@company.com',
        'subject': 'CRITICAL: SQL Injection Attack'
    }, is_active=True),
    Action(playbook=playbook_sqli, action_type='create_ticket', order=3, parameters={
        'title': 'SQL Injection - Critical Investigation'
    }, is_active=True),
])
print(f"   ✅ {playbook_sqli.name} - 3 actions")

# ==================== PLAYBOOK 6: WEB ATTACK ====================
print("\n6️⃣  Création du playbook Web Attack...")
playbook_web = Playbook.objects.create(
    name="🌐 Web Application Attack Response",
    description="Comprehensive response to web application attacks",
    trigger='web_attack',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_web, action_type='block_ip', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_web, action_type='enrich_threat', order=2, parameters={}, is_active=True),
    Action(playbook=playbook_web, action_type='send_email', order=3, parameters={
        'recipient': 'security@company.com',
        'subject': 'CRITICAL: Web Application Attack'
    }, is_active=True),
    Action(playbook=playbook_web, action_type='create_ticket', order=4, parameters={
        'title': 'Web Attack - Immediate Action Required'
    }, is_active=True),
])
print(f"   ✅ {playbook_web.name} - 4 actions")

# ==================== PLAYBOOK 7: DDOS ATTACK ====================
print("\n7️⃣  Création du playbook DDoS Attack...")
playbook_ddos = Playbook.objects.create(
    name="💥 DDoS Attack Response",
    description="Emergency response to DDoS attacks",
    trigger='ddos_attack',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_ddos, action_type='block_ip', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_ddos, action_type='send_email', order=2, parameters={
        'recipient': 'security@company.com',
        'subject': 'CRITICAL: DDoS Attack in Progress'
    }, is_active=True),
    Action(playbook=playbook_ddos, action_type='create_ticket', order=3, parameters={
        'title': 'DDoS Attack - Infrastructure Alert'
    }, is_active=True),
])
print(f"   ✅ {playbook_ddos.name} - 3 actions")

# ==================== PLAYBOOK 8: MALWARE DETECTED ====================
print("\n8️⃣  Création du playbook Malware Detected...")
playbook_malware = Playbook.objects.create(
    name="☠️ Malware Detection Response",
    description="Critical response to malware detection",
    trigger='malware_detected',
    is_active=True,
    created_by=admin_user
)

Action.objects.bulk_create([
    Action(playbook=playbook_malware, action_type='block_ip', order=1, parameters={}, is_active=True),
    Action(playbook=playbook_malware, action_type='enrich_threat', order=2, parameters={}, is_active=True),
    Action(playbook=playbook_malware, action_type='send_email', order=3, parameters={
        'recipient': 'security@company.com',
        'subject': 'CRITICAL: Malware Detected'
    }, is_active=True),
    Action(playbook=playbook_malware, action_type='create_ticket', order=4, parameters={
        'title': 'Malware Detection - Host Isolation Required'
    }, is_active=True),
])
print(f"   ✅ {playbook_malware.name} - 4 actions")

# ==================== RÉSUMÉ ====================
print("\n" + "="*70)
print("✅ CONFIGURATION TERMINÉE!")
print("="*70)
print(f"📊 Total Playbooks créés: {Playbook.objects.count()}")
print(f"📊 Total Actions configurées: {Action.objects.count()}")
print(f"📊 Playbooks actifs: {Playbook.objects.filter(is_active=True).count()}")

print("\n📋 LISTE DES PLAYBOOKS:")
for pb in Playbook.objects.all():
    actions_count = pb.actions.count()
    print(f"  • {pb.name}")
    print(f"    → Trigger: {pb.trigger}")
    print(f"    → Actions: {actions_count}")
    print(f"    → Status: {'✅ Actif' if pb.is_active else '❌ Inactif'}")

print("\n💡 Les playbooks sont prêts à répondre automatiquement aux attaques!")
print("="*70)

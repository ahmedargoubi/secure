
# ========================================
# ÉTAPE 2: DDOS DETECTION
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💥 ÉTAPE 2/3: Configuration Détection DDoS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Créer le playbook DDoS
python manage.py shell << 'PYTEST'
from playbooks.models import Playbook, Action
from django.contrib.auth.models import User

admin = User.objects.filter(is_superuser=True).first()

playbook, created = Playbook.objects.get_or_create(
    trigger='ddos_attack',
    defaults={
        'name': 'DDoS Attack Response',
        'description': 'Blocage automatique des attaques DDoS',
        'created_by': admin,
        'is_active': True
    }
)

if created:
    print("✅ Playbook DDoS créé")
    
    Action.objects.create(playbook=playbook, action_type='block_ip', order=1, parameters={}, is_active=True)
    Action.objects.create(playbook=playbook, action_type='enrich_threat', order=2, parameters={}, is_active=True)
    Action.objects.create(playbook=playbook, action_type='send_email', order=3, parameters={'recipient': 'ahmedargoubi28@gmail.com', 'subject': '🚨 Attaque DDoS Critique'}, is_active=True)
    Action.objects.create(playbook=playbook, action_type='create_ticket', order=4, parameters={'title': 'Incident DDoS'}, is_active=True)
    
    print(f"✅ {playbook.actions.count()} actions configurées")
else:
    print("ℹ️ Playbook DDoS existe déjà")

PYTEST

# ========================================
# ÉTAPE 3: REDÉMARRER
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔄 ÉTAPE 3/3: Redémarrage des Services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

pkill -f celery
pkill -f runserver

sleep 2

source venv/bin/activate

nohup python manage.py runserver 0.0.0.0:8000 > logs/django.log 2>&1 &
nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &

sleep 3

echo "✅ Services redémarrés"

# ========================================
# TESTS
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 TESTS DISPONIBLES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat > ~/test_all_attacks.sh << 'EOF'
#!/bin/bash

TARGET="192.168.163.135"

echo "🎯 TEST COMPLET DES ATTAQUES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 1. SSH Bruteforce
echo "1️⃣ SSH Bruteforce..."
for i in {1..5}; do
    sshpass -p 'test' ssh -o ConnectTimeout=1 root@$TARGET 2>/dev/null
done
echo "✅ Terminé"
sleep 5

# 2. Port Scan
echo ""
echo "2️⃣ Port Scan..."
nmap -sS -p 1-100 $TARGET >/dev/null 2>&1
echo "✅ Terminé"
sleep 5

# 3. DDoS Simulation
echo ""
echo "3️⃣ DDoS Attack..."
for i in {1..50}; do
    (nc -w 1 $TARGET 22 &) 2>/dev/null
done
echo "✅ Terminé"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ TOUS LES TESTS LANCÉS"
echo ""
echo "Vérifiez:"
echo "  - Dashboard: http://$TARGET:8000"
echo "  - Email: ahmedargoubi28@gmail.com"
echo "  - IPs bloquées: sudo iptables -L INPUT -n"
echo ""
EOF

chmod +x ~/test_all_attacks.sh

echo "✅ Script de test créé: ~/test_all_attacks.sh"

# ========================================
# RÉSUMÉ FINAL
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 PROJET SECUREFLOW FINALISÉ !"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ FONCTIONNALITÉS OPÉRATIONNELLES:"
echo ""
echo "   🚫 Blocage IP automatique (iptables)"
echo "   📧 Notifications email"
echo "   🔍 Enrichissement VirusTotal"
echo "   🎫 Création de tickets"
echo "   💥 Détection DDoS"
echo "   🔐 Détection SSH Bruteforce"
echo "   🔎 Détection Port Scan"
echo "   🌐 Détection Web Attacks"
echo ""
echo "🎯 ACCÈS:"
echo ""
echo "   Dashboard: http://192.168.163.135:8000"
echo "   Simulateur: http://192.168.163.135:8000/incidents/simulate/"
echo "   Admin: http://192.168.163.135:8000/admin/"
echo ""
echo "🧪 TESTS:"
echo ""
echo "   Depuis Kali:"
echo "     ~/test_all_attacks.sh"
echo ""
echo "   Avec l'agent:"
echo "     sudo python3 ~/secureflow/security_agent.py"
echo ""
echo "📊 SURVEILLANCE:"
echo ""
echo "   Logs Celery: tail -f ~/secureflow/logs/celery.log"
echo "   Logs Django: tail -f ~/secureflow/logs/django.log"
echo "   IPs bloquées: sudo iptables -L INPUT -n"
echo ""
echo "📧 NOTIFICATIONS: ahmedargoubi28@gmail.com"
echo ""
echo "🎉 VOTRE SYSTÈME SOAR EST PRÊT !"
echo ""

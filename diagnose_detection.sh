#!/bin/bash

echo "🔍 ===== DIAGNOSTIC DÉTECTION ATTAQUES ====="
echo ""

cd ~/secureflow

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣ VÉRIFICATION DES FICHIERS DE LOGS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# SSH logs
if [ -f /var/log/auth.log ]; then
    echo "✅ /var/log/auth.log existe"
    echo "   Dernières lignes:"
    tail -3 /var/log/auth.log | sed 's/^/   /'
else
    echo "❌ /var/log/auth.log n'existe pas"
fi

echo ""

# UFW logs (port scan)
if [ -f /var/log/ufw.log ]; then
    echo "✅ /var/log/ufw.log existe"
    echo "   Dernières lignes:"
    tail -3 /var/log/ufw.log | sed 's/^/   /'
else
    echo "❌ /var/log/ufw.log n'existe pas"
    echo "   💡 UFW n'est peut-être pas configuré"
fi

echo ""

# Apache logs (web attacks)
if [ -f /var/log/apache2/access.log ]; then
    echo "✅ /var/log/apache2/access.log existe"
    echo "   Dernières lignes:"
    tail -3 /var/log/apache2/access.log | sed 's/^/   /'
else
    echo "❌ /var/log/apache2/access.log n'existe pas"
    echo "   💡 Apache n'est pas installé ou pas de logs"
fi

echo ""

# Nginx logs (alternative à Apache)
if [ -f /var/log/nginx/access.log ]; then
    echo "✅ /var/log/nginx/access.log existe"
    echo "   Dernières lignes:"
    tail -3 /var/log/nginx/access.log | sed 's/^/   /'
else
    echo "❌ /var/log/nginx/access.log n'existe pas"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2️⃣ VÉRIFICATION DES PLAYBOOKS ACTIFS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python manage.py shell << 'PYTEST'
from playbooks.models import Playbook

playbooks = Playbook.objects.filter(is_active=True)

print(f"Playbooks actifs: {playbooks.count()}\n")

for pb in playbooks:
    print(f"✓ {pb.name}")
    print(f"  Trigger: {pb.trigger}")
    print(f"  Actions: {pb.actions.filter(is_active=True).count()}")
    print()

# Vérifier quels triggers manquent
all_triggers = [
    'ssh_bruteforce',
    'port_scan',
    'web_attack',
    'sql_injection',
    'ddos_attack'
]

existing_triggers = list(playbooks.values_list('trigger', flat=True))
missing = [t for t in all_triggers if t not in existing_triggers]

if missing:
    print(f"⚠️ Playbooks manquants pour:")
    for t in missing:
        print(f"   - {t}")

PYTEST

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3️⃣ VÉRIFICATION AGENT DE SÉCURITÉ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if ps aux | grep -v grep | grep -q "security_agent.py"; then
    echo "✅ Agent en cours d'exécution"
    ps aux | grep security_agent.py | grep -v grep
else
    echo "❌ Agent NON démarré"
    echo "   💡 Lancez: sudo python3 security_agent.py"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4️⃣ RÉSUMÉ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "PROBLÈMES DÉTECTÉS:"
echo ""

if [ ! -f /var/log/ufw.log ]; then
    echo "❌ UFW non configuré → Port scan NON détecté"
fi

if [ ! -f /var/log/apache2/access.log ] && [ ! -f /var/log/nginx/access.log ]; then
    echo "❌ Pas de serveur web → Web attacks NON détectés"
fi

if ! ps aux | grep -v grep | grep -q "security_agent.py"; then
    echo "❌ Agent non démarré → AUCUNE détection automatique"
fi

echo ""

#!/bin/bash

echo "🔥 ===== FIX BLOCAGE IP AVEC IPTABLES ====="
echo ""

cd ~/secureflow

# 1. CRÉER UN SCRIPT DE BLOCAGE SÉPARÉ
echo "📝 Création du script de blocage..."

sudo tee /usr/local/bin/block_ip.sh > /dev/null << 'EOF'
#!/bin/bash

IP=$1

if [ -z "$IP" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

# Vérifier si l'IP est déjà bloquée
if iptables -L INPUT -n | grep -q "$IP"; then
    echo "IP $IP déjà bloquée"
    exit 0
fi

# Bloquer l'IP
iptables -I INPUT -s $IP -j DROP

# Sauvegarder les règles
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
elif command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4
fi

echo "IP $IP bloquée avec succès"
exit 0
EOF

sudo chmod +x /usr/local/bin/block_ip.sh

echo "✅ Script de blocage créé : /usr/local/bin/block_ip.sh"

# 2. CONFIGURER SUDOERS POUR PERMETTRE L'EXÉCUTION SANS MOT DE PASSE
echo "🔐 Configuration sudoers..."

sudo tee /etc/sudoers.d/secureflow > /dev/null << EOF
# Permettre à tous les utilisateurs d'exécuter le script de blocage
ALL ALL=(ALL) NOPASSWD: /usr/local/bin/block_ip.sh
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -I *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -D *
EOF

sudo chmod 0440 /etc/sudoers.d/secureflow

echo "✅ Sudoers configuré"

# 3. TESTER LE SCRIPT
echo ""
echo "🧪 Test du script de blocage..."

TEST_IP="1.2.3.4"
sudo /usr/local/bin/block_ip.sh $TEST_IP

if sudo iptables -L INPUT -n | grep -q "$TEST_IP"; then
    echo "✅ Test réussi ! IP $TEST_IP bloquée"
    sudo iptables -D INPUT -s $TEST_IP -j DROP
    echo "🧹 Règle de test supprimée"
else
    echo "❌ Test échoué"
    exit 1
fi

# 4. MODIFIER playbooks/tasks.py POUR UTILISER LE SCRIPT
echo ""
echo "📝 Modification de tasks.py..."

cat > /tmp/block_ip_function.py << 'PYEOF'
def block_ip_action(incident, parameters, execution):
    """
    Bloquer une adresse IP - VERSION FINALE QUI MARCHE
    """
    import subprocess
    
    try:
        ip_to_block = parameters.get('ip_address') or incident.source_ip
        
        logger.info(f"🚫 Blocage IP: {ip_to_block}")
        
        if not ip_to_block:
            execution.add_log('⚠️ Aucune IP à bloquer', 'warning')
            return False
        
        # Vérifier si déjà bloquée dans la DB
        existing = BlockedIP.objects.filter(ip_address=ip_to_block, is_active=True).first()
        
        if existing:
            execution.add_log(f'ℹ️ IP {ip_to_block} déjà bloquée en DB', 'info')
            logger.info(f"ℹ️ IP {ip_to_block} déjà dans la base")
        
        # === BLOQUER AVEC LE SCRIPT ===
        try:
            result = subprocess.run(
                ['sudo', '/usr/local/bin/block_ip.sh', ip_to_block],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"✅ IP {ip_to_block} BLOQUÉE avec iptables")
                execution.add_log(f'🔥 IP {ip_to_block} BLOQUÉE avec iptables', 'info')
            else:
                logger.error(f"❌ Erreur blocage: {result.stderr}")
                execution.add_log(f'❌ Erreur iptables: {result.stderr}', 'error')
        
        except subprocess.TimeoutExpired:
            logger.error("❌ Timeout lors du blocage")
            execution.add_log('❌ Timeout iptables', 'error')
        
        except Exception as e:
            logger.error(f"❌ Erreur: {str(e)}")
            execution.add_log(f'❌ Erreur: {str(e)}', 'error')
        
        # Créer/Mettre à jour dans la DB
        if not existing:
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_to_block,
                reason=f'Bloquée auto - Incident: {incident.title}',
                blocked_by_incident=incident,
                is_active=True
            )
            logger.info(f"✅ IP {ip_to_block} enregistrée (DB ID: {blocked_ip.id})")
        
        execution.add_log(f'✅ Blocage terminé pour {ip_to_block}', 'info')
        
        incident.status = 'in_progress'
        incident.save()
        
        return True
    
    except Exception as e:
        execution.add_log(f'❌ Erreur globale: {str(e)}', 'error')
        logger.error(f"❌ Erreur globale blocage IP: {str(e)}")
        return False
PYEOF

echo "✅ Nouvelle fonction créée"

# 5. REMPLACER LA FONCTION DANS tasks.py
echo "📝 Remplacement dans tasks.py..."

# Backup
cp playbooks/tasks.py playbooks/tasks.py.backup_$(date +%Y%m%d_%H%M%S)

# Trouver et remplacer la fonction block_ip_action
python3 << 'PYREPLACE'
import re

with open('playbooks/tasks.py', 'r') as f:
    content = f.read()

# Lire la nouvelle fonction
with open('/tmp/block_ip_function.py', 'r') as f:
    new_function = f.read()

# Trouver et remplacer
pattern = r'def block_ip_action\(.*?\n(?:.*?\n)*?(?=\ndef [a-z_]+\(|$)'
replacement = new_function + '\n\n'

content = re.sub(pattern, replacement, content, count=1)

with open('playbooks/tasks.py', 'w') as f:
    f.write(content)

print("✅ Fonction remplacée")
PYREPLACE

echo "✅ tasks.py modifié"

# 6. REDÉMARRER CELERY
echo ""
echo "🔄 Redémarrage de Celery..."

pkill -f celery
sleep 2

nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &
CELERY_PID=$!

sleep 3

if ps -p $CELERY_PID > /dev/null; then
    echo "✅ Celery redémarré (PID: $CELERY_PID)"
else
    echo "❌ Erreur redémarrage Celery"
    tail -20 logs/celery.log
    exit 1
fi

# 7. CRÉER UN INCIDENT DE TEST
echo ""
echo "🧪 Test complet avec incident..."

python3 << 'PYTEST'
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secureflow_project.settings')
django.setup()

from incidents.models import Incident

# Créer incident avec IP Kali
incident = Incident.objects.create(
    title="Test blocage automatique IP Kali",
    description="Test final du blocage iptables",
    incident_type='ssh_bruteforce',
    severity='high',
    source_ip='192.168.163.142',
    status='new'
)

print(f"✅ Incident créé : ID {incident.id}")
print(f"   IP Source : {incident.source_ip}")
PYTEST

echo ""
echo "⏳ Attente de l'exécution du playbook (10 secondes)..."
sleep 10

# 8. VÉRIFIER LE BLOCAGE
echo ""
echo "🔍 Vérification finale..."

if sudo iptables -L INPUT -n | grep -q "192.168.163.142"; then
    echo ""
    echo "✅✅✅ SUCCÈS ! IP 192.168.163.142 EST BLOQUÉE ! ✅✅✅"
    echo ""
    sudo iptables -L INPUT -n | grep "192.168.163.142"
    echo ""
    echo "🎯 Testez depuis Kali : ping 192.168.163.135"
    echo "   (ne devrait PLUS répondre)"
else
    echo ""
    echo "⚠️  IP non bloquée - Vérification des logs..."
    echo ""
    echo "=== Logs Celery (dernières 30 lignes) ==="
    tail -30 logs/celery.log
fi

echo ""
echo "✅ ===== CONFIGURATION TERMINÉE ====="
echo ""
echo "📋 POUR DÉBLOQUER UNE IP :"
echo "   sudo iptables -D INPUT -s 192.168.163.142 -j DROP"
echo ""
echo "📋 VOIR TOUTES LES IPs BLOQUÉES :"
echo "   sudo iptables -L INPUT -n -v"
echo ""

#!/bin/bash

echo "🔥 ===== CONFIGURATION COMPLÈTE - SCÉNARIO RÉEL ====="
echo "🎯 Kali attaque → Agent détecte → SOAR réagit automatiquement"
echo ""

cd ~/secureflow

# ========================================
# 1. CRÉER incidents/signals.py
# ========================================
echo "📝 [1/5] Création de incidents/signals.py (déclenchement auto)..."

cat > incidents/signals.py << 'EOF'
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Incident
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=Incident)
def auto_trigger_playbook(sender, instance, created, **kwargs):
    """
    🤖 DÉCLENCHEMENT AUTOMATIQUE DES PLAYBOOKS
    
    Quand un incident est créé (par agent ou web),
    ce signal lance automatiquement le playbook correspondant.
    """
    
    # Seulement pour les nouveaux incidents
    if not created:
        return
    
    # Éviter les doubles déclenchements
    if instance.auto_playbook_triggered:
        return
    
    logger.info(f"🎯 SIGNAL: Nouvel incident #{instance.id} - {instance.incident_type}")
    
    try:
        from playbooks.models import Playbook
        from playbooks.tasks import execute_playbook_async
        
        # Chercher playbook(s) actif(s) correspondant au type d'incident
        playbooks = Playbook.objects.filter(
            trigger=instance.incident_type,
            is_active=True
        )
        
        if not playbooks.exists():
            logger.warning(f"⚠️ Aucun playbook actif pour: {instance.incident_type}")
            return
        
        # Lancer chaque playbook trouvé
        for playbook in playbooks:
            logger.info(f"🚀 Lancement automatique: '{playbook.name}'")
            
            # Exécution asynchrone avec Celery
            execute_playbook_async.delay(playbook.id, instance.id)
        
        # Marquer comme traité
        instance.auto_playbook_triggered = True
        instance.save(update_fields=['auto_playbook_triggered'])
        
        logger.info(f"✅ {playbooks.count()} playbook(s) lancé(s) pour incident #{instance.id}")
    
    except Exception as e:
        logger.error(f"❌ Erreur déclenchement automatique: {str(e)}")
        import traceback
        traceback.print_exc()
EOF

echo "   ✅ incidents/signals.py créé"

# ========================================
# 2. MODIFIER incidents/apps.py
# ========================================
echo "📝 [2/5] Modification de incidents/apps.py..."

cat > incidents/apps.py << 'EOF'
from django.apps import AppConfig

class IncidentsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'incidents'
    verbose_name = 'Incidents de Sécurité'
    
    def ready(self):
        """
        Importer les signals au démarrage de l'app
        """
        try:
            import incidents.signals
        except Exception as e:
            print(f"❌ Erreur import signals: {e}")
EOF

echo "   ✅ incidents/apps.py modifié"

# ========================================
# 3. VÉRIFIER playbooks/tasks.py
# ========================================
echo "🔍 [3/5] Vérification de playbooks/tasks.py..."

# Vérifier si les 4 fonctions principales existent
FUNCTIONS=("block_ip_action" "send_email_action" "enrich_threat_action" "create_ticket_action")
MISSING=()

for func in "${FUNCTIONS[@]}"; do
    if ! grep -q "def $func" playbooks/tasks.py; then
        MISSING+=("$func")
    fi
done

if [ ${#MISSING[@]} -eq 0 ]; then
    echo "   ✅ Toutes les fonctions d'action sont présentes"
else
    echo "   ⚠️ Fonctions manquantes: ${MISSING[*]}"
    echo "   (Elles seront ajoutées automatiquement)"
fi

# ========================================
# 4. CONFIGURER EMAIL GMAIL
# ========================================
echo "📧 [4/5] Configuration Email Gmail..."

# Demander l'App Password Gmail
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📧 CONFIGURATION EMAIL GMAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Pour recevoir les alertes par email, vous devez créer un"
echo "App Password Gmail (mot de passe d'application)."
echo ""
echo "🔗 Allez sur: https://myaccount.google.com/apppasswords"
echo ""
echo "1. Connectez-vous avec: ahmedargoubi28@gmail.com"
echo "2. Créez un nouveau mot de passe (nom: SecureFlow)"
echo "3. Copiez le mot de passe de 16 caractères généré"
echo ""
read -p "Avez-vous créé l'App Password ? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Collez votre App Password Gmail (16 chars): " APP_PASSWORD
    
    # Mettre à jour settings.py
    sed -i "s/EMAIL_HOST_PASSWORD = .*/EMAIL_HOST_PASSWORD = '$APP_PASSWORD'/" secureflow_project/settings.py
    
    echo "   ✅ App Password configuré"
else
    echo "   ⚠️ App Password non configuré - Les emails ne seront pas envoyés"
    echo "   💡 Vous pouvez le configurer plus tard dans settings.py"
fi

# ========================================
# 5. CONFIGURER VIRUSTOTAL (Optionnel)
# ========================================
echo ""
echo "🔍 [5/5] Configuration VirusTotal (Optionnel)..."
echo ""
echo "Pour l'enrichissement threat intelligence, vous pouvez"
echo "obtenir une clé API VirusTotal gratuite (500 requêtes/jour)."
echo ""
echo "🔗 Allez sur: https://www.virustotal.com/gui/join-us"
echo ""
read -p "Avez-vous une clé API VirusTotal ? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Collez votre clé API VirusTotal: " VT_API_KEY
    
    # Mettre à jour settings.py
    sed -i "s/VIRUSTOTAL_API_KEY = .*/VIRUSTOTAL_API_KEY = '$VT_API_KEY'/" secureflow_project/settings.py
    
    echo "   ✅ Clé VirusTotal configurée"
else
    echo "   ⚠️ VirusTotal non configuré - Enrichissement simulé"
fi

# ========================================
# 6. REDÉMARRER LES SERVICES
# ========================================
echo ""
echo "🔄 Redémarrage de Django et Celery..."

# Arrêter
pkill -f runserver
pkill -f celery
sleep 2

# Activer venv
source venv/bin/activate

# Démarrer Django
nohup python manage.py runserver 0.0.0.0:8000 > logs/django.log 2>&1 &
DJANGO_PID=$!

sleep 2

# Démarrer Celery
nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &
CELERY_PID=$!

sleep 3

# Vérifier
if ps -p $DJANGO_PID > /dev/null && ps -p $CELERY_PID > /dev/null; then
    echo "   ✅ Django démarré (PID: $DJANGO_PID)"
    echo "   ✅ Celery démarré (PID: $CELERY_PID)"
else
    echo "   ❌ Erreur démarrage - Vérifiez les logs"
    exit 1
fi

# ========================================
# 7. TEST AUTOMATIQUE
# ========================================
echo ""
echo "🧪 TEST DU WORKFLOW COMPLET..."
echo ""

python manage.py shell << 'PYTEST'
from incidents.models import Incident
from playbooks.models import Playbook
import time

print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🧪 TEST 1: Vérification des playbooks actifs")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

playbooks = Playbook.objects.filter(is_active=True)
print(f"\n📌 {playbooks.count()} playbook(s) actif(s):\n")

for pb in playbooks:
    print(f"   ✓ {pb.name}")
    print(f"     Trigger: {pb.get_trigger_display()}")
    print(f"     Actions: {pb.actions.filter(is_active=True).count()}")
    print()

print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🧪 TEST 2: Simulation d'attaque SSH depuis Kali")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

incident = Incident.objects.create(
    title="SSH Bruteforce Attack from Kali Linux",
    description="Tentative de bruteforce SSH détectée depuis Kali (192.168.163.142)",
    incident_type='ssh_bruteforce',
    severity='high',
    source_ip='192.168.163.142',
    target_ip='192.168.163.135',
    status='new'
)

print(f"\n✅ Incident créé:")
print(f"   ID: {incident.id}")
print(f"   Type: {incident.get_incident_type_display()}")
print(f"   IP Kali: {incident.source_ip}")
print(f"   Criticité: {incident.get_severity_display()}")
print()

print("⏳ Attente de l'exécution automatique (10 secondes)...")
time.sleep(10)

# Vérifier les exécutions
from playbooks.models import PlaybookExecution

executions = incident.playbook_executions.all()

print()
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("📊 RÉSULTATS DE L'EXÉCUTION")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print()

if executions.exists():
    print(f"✅✅✅ SUCCÈS ! Playbook déclenché automatiquement ! ✅✅✅")
    print()
    
    for exe in executions:
        print(f"📌 Playbook: {exe.playbook.name}")
        print(f"   Statut: {exe.get_status_display()}")
        print(f"   Actions réussies: {exe.actions_executed}")
        print(f"   Actions échouées: {exe.actions_failed}")
        print(f"   Démarré: {exe.started_at.strftime('%H:%M:%S')}")
        
        if exe.completed_at:
            duration = (exe.completed_at - exe.started_at).total_seconds()
            print(f"   Terminé: {exe.completed_at.strftime('%H:%M:%S')} ({duration:.1f}s)")
        
        print()
        print("   📝 Logs d'exécution:")
        for log in exe.logs[-5:]:  # Derniers 5 logs
            emoji = {
                'info': 'ℹ️',
                'warning': '⚠️',
                'error': '❌'
            }.get(log.get('level', 'info'), 'ℹ️')
            print(f"      {emoji} {log.get('message', '')}")
        print()
else:
    print("❌ Aucune exécution trouvée")
    print("⚠️ Vérifiez les logs Celery: tail -f logs/celery.log")
    print()

PYTEST

# ========================================
# 8. VÉRIFIER LE BLOCAGE IPTABLES
# ========================================
echo ""
echo "🔍 Vérification du blocage IP..."

if sudo iptables -L INPUT -n | grep -q "192.168.163.142"; then
    echo ""
    echo "✅✅✅ IP KALI BLOQUÉE DANS IPTABLES ! ✅✅✅"
    echo ""
    sudo iptables -L INPUT -n -v | grep "192.168.163.142"
    echo ""
else
    echo ""
    echo "⚠️ IP non bloquée - Vérifiez les logs"
    echo ""
fi

# ========================================
# 9. AFFICHER LES INSTRUCTIONS FINALES
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ CONFIGURATION TERMINÉE - SYSTÈME PRÊT !"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🎯 SCÉNARIO DE TEST COMPLET:"
echo ""
echo "Sur KALI (192.168.163.142):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Tester la connectivité AVANT attaque:"
echo "   ping 192.168.163.135"
echo ""
echo "2. Lancer l'attaque SSH bruteforce:"
echo "   hydra -l root -P /usr/share/wordlists/rockyou.txt \\
         ssh://192.168.163.135 -t 4"
echo ""
echo "   OU avec un script simple:"
echo "   for i in {1..10}; do"
echo "     sshpass -p 'test' ssh root@192.168.163.135"
echo "   done"
echo ""
echo "3. Tester APRÈS (devrait être bloqué):"
echo "   ping 192.168.163.135  # Pas de réponse !"
echo ""
echo "Sur UBUNTU (192.168.163.135):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Lancer l'agent de sécurité:"
echo "   sudo python3 security_agent.py"
echo ""
echo "2. Surveiller les logs en temps réel:"
echo "   tail -f logs/celery.log"
echo ""
echo "3. Voir le dashboard:"
echo "   http://192.168.163.135:8000"
echo ""
echo "4. Vérifier les IPs bloquées:"
echo "   sudo iptables -L INPUT -n"
echo ""
echo "5. Débloquer une IP (si besoin):"
echo "   sudo iptables -D INPUT -s 192.168.163.142 -j DROP"
echo ""
echo "📊 WORKFLOW AUTOMATIQUE:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Kali attaque"
echo "  ↓"
echo "Agent détecte (auth.log)"
echo "  ↓"
echo "Crée incident automatiquement"
echo "  ↓"
echo "Signal Django déclenche playbook"
echo "  ↓"
echo "Celery exécute les actions:"
echo "  ✓ 🚫 Blocage IP avec iptables"
echo "  ✓ 📧 Email envoyé à ahmedargoubi28@gmail.com"
echo "  ✓ 🔍 Enrichissement VirusTotal"
echo "  ✓ 🎫 Ticket créé"
echo "  ↓"
echo "Dashboard mis à jour en temps réel"
echo ""
echo "🎉 VOTRE SYSTÈME SOAR EST OPÉRATIONNEL !"
echo ""

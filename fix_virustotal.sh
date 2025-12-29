#!/bin/bash

echo "🔍 ===== CONFIGURATION VIRUSTOTAL RÉELLE ====="
echo ""

cd ~/secureflow

# ========================================
# 1. VÉRIFIER LA CLÉ API ACTUELLE
# ========================================
echo "📝 [1/3] Vérification de la clé API actuelle..."

CURRENT_KEY=$(grep "VIRUSTOTAL_API_KEY" secureflow_project/settings.py | cut -d"'" -f2)

if [ -z "$CURRENT_KEY" ] || [ "$CURRENT_KEY" == "" ]; then
    echo "   ❌ Aucune clé API configurée"
    HAS_KEY=false
else
    echo "   ✅ Clé trouvée: ${CURRENT_KEY:0:20}..."
    HAS_KEY=true
fi

# ========================================
# 2. DEMANDER LA CLÉ API SI NÉCESSAIRE
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔑 CONFIGURATION CLÉ API VIRUSTOTAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$HAS_KEY" = false ]; then
    echo "Pour obtenir une clé API VirusTotal GRATUITE :"
    echo ""
    echo "1️⃣ Allez sur : https://www.virustotal.com/gui/join-us"
    echo "2️⃣ Créez un compte (email: ahmedargoubi28@gmail.com)"
    echo "3️⃣ Vérifiez votre email et activez le compte"
    echo "4️⃣ Connectez-vous : https://www.virustotal.com/gui/sign-in"
    echo "5️⃣ Cliquez sur votre avatar → API Key"
    echo "6️⃣ Copiez la clé (64 caractères)"
    echo ""
    
    read -p "Avez-vous créé votre compte VirusTotal ? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Collez votre clé API VirusTotal (64 chars): " VT_KEY
        
        # Valider la longueur (environ 64 chars)
        if [ ${#VT_KEY} -lt 40 ]; then
            echo "❌ Clé invalide (trop courte)"
            exit 1
        fi
        
        # Mettre à jour settings.py
        sed -i "s/VIRUSTOTAL_API_KEY = .*/VIRUSTOTAL_API_KEY = '$VT_KEY'/" secureflow_project/settings.py
        
        echo "✅ Clé API configurée"
    else
        echo "⚠️ Configuration annulée"
        exit 0
    fi
else
    echo "ℹ️ Clé API déjà configurée"
    echo ""
    read -p "Voulez-vous la changer ? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Nouvelle clé API: " VT_KEY
        sed -i "s/VIRUSTOTAL_API_KEY = .*/VIRUSTOTAL_API_KEY = '$VT_KEY'/" secureflow_project/settings.py
        echo "✅ Clé API mise à jour"
    fi
fi

# ========================================
# 3. REDÉMARRER CELERY
# ========================================
echo ""
echo "🔄 [2/3] Redémarrage de Celery..."

pkill -f celery
sleep 2

source venv/bin/activate
nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &

sleep 3
echo "✅ Celery redémarré"

# ========================================
# 4. TEST AVEC IP PUBLIQUE MALVEILLANTE
# ========================================
echo ""
echo "🧪 [3/3] Test avec une IP publique malveillante connue..."
echo ""

python manage.py shell << 'PYTEST'
from incidents.models import Incident
import time

print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🧪 TEST VIRUSTOTAL AVEC IP PUBLIQUE")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print()

# Utiliser une IP Tor connue comme malveillante
public_ips = [
    ('185.220.101.1', 'IP Tor Exit Node'),
    ('8.8.8.8', 'Google DNS'),
    ('1.1.1.1', 'Cloudflare DNS')
]

for ip, description in public_ips:
    print(f"📌 Test avec {ip} ({description})")
    
    incident = Incident.objects.create(
        title=f"Test VirusTotal - {description}",
        description=f"Test enrichissement avec {ip}",
        incident_type='ssh_bruteforce',
        severity='high',
        source_ip=ip,
        status='new'
    )
    
    print(f"   ✅ Incident #{incident.id} créé")
    print(f"   ⏳ Attente enrichissement VirusTotal (15 secondes)...")
    
    time.sleep(15)
    
    # Vérifier enrichissement
    incident.refresh_from_db()
    
    print()
    if incident.is_enriched:
        intel = incident.threat_intel_data
        
        is_real = not intel.get('simulated', False)
        
        if is_real:
            print(f"   ✅✅✅ VIRUSTOTAL RÉEL FONCTIONNE ! ✅✅✅")
        else:
            print(f"   ⚠️ Données simulées (vérifier clé API)")
        
        print()
        print(f"   📊 RÉSULTATS:")
        print(f"      Source: {intel.get('source', 'N/A')}")
        print(f"      Malicious: {intel.get('malicious', 0)}")
        print(f"      Suspicious: {intel.get('suspicious', 0)}")
        print(f"      Harmless: {intel.get('harmless', 0)}")
        print(f"      Country: {intel.get('country', 'Unknown')}")
        print(f"      AS Owner: {intel.get('as_owner', 'Unknown')}")
        print(f"      Reputation: {intel.get('reputation', 0)}")
        
        if is_real:
            print()
            print(f"   🎉 SUCCÈS ! VirusTotal configuré correctement !")
            break
    else:
        print(f"   ❌ Enrichissement échoué")
        print(f"   💡 Vérifiez: tail -f logs/celery.log | grep VirusTotal")
    
    print()
    print()

print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("📊 RÉSUMÉ")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print()

from django.conf import settings

api_key = settings.VIRUSTOTAL_API_KEY

if api_key and len(api_key) > 20:
    print(f"✅ Clé API configurée: {api_key[:20]}...")
    print()
    print("💡 IMPORTANT:")
    print("   - VirusTotal ne fonctionne QU'AVEC des IPs PUBLIQUES")
    print("   - IPs privées (192.168.x.x) = SIMULATION")
    print("   - IPs publiques (Internet) = DONNÉES RÉELLES")
    print()
    print("🎯 Pour tester avec une vraie attaque:")
    print("   1. Utilisez une IP publique dans la simulation")
    print("   2. Ou attendez une attaque depuis Internet")
else:
    print("⚠️ Clé API non configurée ou invalide")
    print()
    print("📝 Pour configurer:")
    print("   nano secureflow_project/settings.py")
    print("   VIRUSTOTAL_API_KEY = 'votre_clé_ici'")

print()

PYTEST

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ CONFIGURATION TERMINÉE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 COMPRENDRE LES RÉSULTATS:"
echo ""
echo "🔴 IP PRIVÉE (192.168.163.142):"
echo "   ├─ Source: VirusTotal (Simulated)"
echo "   ├─ Malicious: 0"
echo "   ├─ Country: Unknown"
echo "   └─ 💡 NORMAL ! VirusTotal ne peut pas analyser les IPs privées"
echo ""
echo "🟢 IP PUBLIQUE (185.220.101.1):"
echo "   ├─ Source: VirusTotal"
echo "   ├─ Malicious: 15+"
echo "   ├─ Country: NL, DE, etc."
echo "   └─ ✅ DONNÉES RÉELLES de VirusTotal"
echo ""
echo "🎯 POUR VOIR DES DONNÉES RÉELLES:"
echo "   1. Configurez votre clé API (si pas fait)"
echo "   2. Créez un incident avec une IP publique:"
echo "      http://192.168.163.135:8000/incidents/simulate/"
echo "      IP: 185.220.101.1 (IP Tor malveillante)"
echo ""
echo "📊 Vérifiez ensuite le dashboard pour voir les vraies données !"
echo ""

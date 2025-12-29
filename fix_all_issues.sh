#!/bin/bash

echo "🔧 ===== CORRECTION SECUREFLOW SOAR ====="
echo ""

# 1. Installer iptables-persistent
echo "📦 Installation de iptables-persistent..."
sudo apt-get update
sudo apt-get install -y iptables-persistent netfilter-persistent

# 2. Configurer sudoers pour Celery (permettre iptables sans mot de passe)
echo "🔐 Configuration sudoers pour Celery..."
sudo bash -c 'cat > /etc/sudoers.d/celery-iptables << EOF
# Permettre à l'\''utilisateur actuel d'\''exécuter iptables sans mot de passe
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables
$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables-save
$USER ALL=(ALL) NOPASSWD: /usr/sbin/netfilter-persistent
EOF'
sudo chmod 0440 /etc/sudoers.d/celery-iptables

# 3. Tester iptables
echo "🧪 Test iptables..."
sudo iptables -L INPUT -n | head -5

# 4. Arrêter Celery
echo "⏹️ Arrêt de Celery..."
pkill -f "celery.*worker" || true

# 5. Démarrer Celery avec les bonnes permissions
echo "🚀 Démarrage de Celery..."
cd ~/secureflow
source venv/bin/activate

# Lancer Celery en arrière-plan
nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &
CELERY_PID=$!

echo "✅ Celery démarré (PID: $CELERY_PID)"

# 6. Afficher les instructions pour Gmail
echo ""
echo "📧 ===== CONFIGURATION EMAIL GMAIL ====="
echo ""
echo "Pour activer l'envoi d'emails réels :"
echo ""
echo "1. Allez sur : https://myaccount.google.com/apppasswords"
echo "2. Connectez-vous avec ahmedargoubi28@gmail.com"
echo "3. Créez un nouveau 'App Password' (nommez-le 'SecureFlow')"
echo "4. Copiez le mot de passe de 16 caractères généré"
echo "5. Modifiez secureflow_project/settings.py :"
echo "   EMAIL_HOST_PASSWORD = 'xxxx xxxx xxxx xxxx'  # Le mot de passe d'app"
echo ""

# 7. Créer un fichier .env
echo "📝 Création du fichier .env..."
cat > .env << EOF
DEBUG=True
SECRET_KEY=django-insecure-g@1y_ah@07ny_nbwh\$l-hxbgesbi8%3-_pz*4y_x7*6unx%cu1
ALLOWED_HOSTS=192.168.163.135,localhost,127.0.0.1

# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=ahmedargoubi28@gmail.com
EMAIL_HOST_PASSWORD=REMPLACER_PAR_VOTRE_APP_PASSWORD

# Celery
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Threat Intelligence
VIRUSTOTAL_API_KEY=
EOF

echo "✅ Fichier .env créé"

# 8. Test de blocage IP
echo ""
echo "🧪 ===== TEST DE BLOCAGE IP ====="
TEST_IP="1.2.3.4"
echo "Test de blocage de $TEST_IP..."

# Ajouter la règle
sudo iptables -I INPUT -s $TEST_IP -j DROP
if [ $? -eq 0 ]; then
    echo "✅ Règle iptables ajoutée avec succès"
    
    # Vérifier
    if sudo iptables -L INPUT -n | grep -q $TEST_IP; then
        echo "✅ Règle iptables vérifiée"
        
        # Nettoyer
        sudo iptables -D INPUT -s $TEST_IP -j DROP
        echo "🧹 Règle de test supprimée"
    fi
else
    echo "❌ Erreur lors de l'ajout de la règle"
fi

echo ""
echo "✅ ===== CONFIGURATION TERMINÉE ====="
echo ""
echo "📋 ÉTAPES SUIVANTES :"
echo ""
echo "1. Configurez votre App Password Gmail dans .env"
echo "2. Rechargez Django : python manage.py runserver"
echo "3. Testez un incident : http://127.0.0.1:8000/incidents/simulate/"
echo "4. Vérifiez les logs Celery : tail -f logs/celery.log"
echo "5. Vérifiez les règles iptables : sudo iptables -L INPUT -n"
echo ""
echo "🎯 Pour tester depuis Kali :"
echo "   - Avant : ping 192.168.163.135 (devrait répondre)"
echo "   - Créer incident avec IP de Kali"
echo "   - Après : ping 192.168.163.135 (devrait être bloqué)"
echo ""

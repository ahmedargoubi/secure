# 📘 GUIDE COMPLET - SECUREFLOW SOAR PLATFORM

<div align="center">



**Security Orchestration, Automation and Response**

 Année Universitaire 2025-2026

</div>

---

## 📑 TABLE DES MATIÈRES

1. [Introduction](#1-introduction)
2. [Prérequis](#2-prérequis)
3. [Architecture du Système](#3-architecture-du-système)
4. [Installation Complète](#4-installation-complète)
5. [Configuration](#5-configuration)
6. [Démarrage du Système](#6-démarrage-du-système)
7. [Utilisation](#7-utilisation)
8. [Tests avec Kali Linux](#8-tests-avec-kali-linux)
9. [Playbooks et Actions](#9-playbooks-et-actions)
10. [Troubleshooting](#10-troubleshooting)
11. [Annexes](#11-annexes)

---

## 1. INTRODUCTION

### 1.1 Qu'est-ce que SecureFlow ?

SecureFlow est une plateforme SOAR (Security Orchestration, Automation and Response) développée en Python/Django qui permet d'**automatiser** la détection et la réponse aux incidents de sécurité en temps réel.

### 1.2 Objectifs du Projet

- ✅ **Détection automatique** des attaques (SSH bruteforce, port scanning, web attacks)
- ✅ **Réponse automatisée** via playbooks intelligents
- ✅ **Blocage temps réel** des IPs malveillantes avec iptables
- ✅ **Enrichissement** via VirusTotal API
- ✅ **Dashboard** avec statistiques et graphiques en temps réel

### 1.3 Technologies Utilisées

| Composant | Version | Rôle |
|-----------|---------|------|
| Python | 3.10+ | Langage principal |
| Django | 5.2 | Framework web MVT |
| Celery | 5.3+ | Orchestration asynchrone |
| Redis | 7.0+ | Message broker |
| SQLite | 3.x | Base de données |
| Chart.js | 4.4.0 | Visualisation |
| VirusTotal API | v3 | Threat intelligence |

---

## 2. PRÉREQUIS

### 2.1 Machine Ubuntu (Cible/Serveur)

**Configuration recommandée :**

```
Système d'exploitation : Ubuntu 22.04 LTS
RAM : 4 GB minimum
Disque : 20 GB
Processeur : 2 cœurs minimum
IP Statique : 192.168.163.135
Services : SSH, Apache2 (optionnel)
```

**Logiciels requis :**

```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Python 3.10+
python3 --version

# Redis
sudo apt install redis-server -y

# Outils système
sudo apt install build-essential python3-dev python3-pip git -y
```

### 2.2 Machine Kali Linux (Attaquant)

**Configuration :**

```
Système d'exploitation : Kali Linux 2024.x
IP : Variable (DHCP ou statique)
Connectivité : Même réseau que Ubuntu
```

**Outils nécessaires :**

```bash
# Hydra (bruteforce SSH)
sudo apt install hydra -y

# Nmap (port scanning)
sudo apt install nmap -y

# hping3 (DDoS simulation)
sudo apt install hping3 -y

# curl (web attacks)
sudo apt install curl -y
```

---

## 3. ARCHITECTURE DU SYSTÈME

### 3.1 Diagramme d'Architecture Global

```
┌──────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE SECUREFLOW                       │
└──────────────────────────────────────────────────────────────────┘

┌─────────────────┐                    ┌──────────────────────────┐
│   KALI LINUX    │                    │    UBUNTU SERVER         │
│   (Attaquant)   │                    │    (192.168.163.135)     │
│                 │                    │                          │
│  ┌───────────┐  │    Attaques       │  ┌────────────────────┐  │
│  │  Hydra    │──┼────SSH Brute──────▶  │  Security Agent    │  │
│  └───────────┘  │    force           │  │  (Python)          │  │
│                 │                    │  └─────────┬──────────┘  │
│  ┌───────────┐  │                    │            │             │
│  │   Nmap    │──┼────Port Scan──────▶            │ Parse logs  │
│  └───────────┘  │                    │            │             │
│                 │                    │            ▼             │
│  ┌───────────┐  │                    │  ┌─────────────────────┐ │
│  │  hping3   │──┼────DDoS Sim───────▶  │  Django (Port 8000) │ │
│  └───────────┘  │                    │  │  ┌────────────────┐ │ │
│                 │                    │  │  │  Incidents DB  │ │ │
│  ┌───────────┐  │                    │  │  └────────────────┘ │ │
│  │   curl    │──┼────Web Attacks────▶  │  ┌────────────────┐ │ │
│  └───────────┘  │                    │  │  │  Playbooks     │ │ │
└─────────────────┘                    │  │  └────────────────┘ │ │
                                       │  └─────────┬───────────┘ │
                                       │            │             │
                                       │            ▼             │
                                       │  ┌─────────────────────┐ │
                                       │  │  Celery Workers     │ │
                                       │  │  (Async Tasks)      │ │
                                       │  └─────────┬───────────┘ │
                                       │            │             │
                                       │     Exécute Actions:    │
                                       │            │             │
                                       │  ┌─────────▼───────────┐ │
                                       │  │  1. block_ip()      │ │
                                       │  │     (iptables)      │ │
                                       │  │                     │ │
                                       │  │  2. enrich_threat() │ │
                                       │  │     (VirusTotal)    │ │
                                       │  │                     │ │
                                       │  │  3. send_email()    │ │
                                       │  │     (Gmail SMTP)    │ │
                                       │  │                     │ │
                                       │  │  4. create_ticket() │ │
                                       │  └─────────────────────┘ │
                                       └──────────────────────────┘
```

### 3.2 Flux de Traitement d'un Incident

```
┌──────────────────────────────────────────────────────────────────┐
│                 FLUX DE TRAITEMENT D'INCIDENT                    │
└──────────────────────────────────────────────────────────────────┘

[1] Attaque SSH Bruteforce depuis Kali
           │
           ▼
[2] Agent détecte dans /var/log/auth.log
    - Parse: "Failed password from 192.168.1.50"
    - Compteur: 5 tentatives échouées
           │
           ▼
[3] Création fichier JSON
    security_events_20251222_153045.json
           │
           ▼
[4] Django charge le JSON
    → Incident créé (type: auth_failure, severity: high)
           │
           ▼
[5] Matching Playbook
    → Trouve "SSH Bruteforce Response"
           │
           ▼
[6] Celery exécute le Playbook (asynchrone)
    ┌─────────────────────────────────────┐
    │  Action #1: block_ip()              │
    │  → iptables -I INPUT -s IP -j DROP  │
    │  → DB: BlockedIP créée              │
    │  ✅ Succès                           │
    └─────────────────────────────────────┘
           │
           ▼
    ┌─────────────────────────────────────┐
    │  Action #2: enrich_threat()         │
    │  → API VirusTotal GET /ip/{IP}      │
    │  → Mise à jour threat_intel_data    │
    │  ✅ Succès                           │
    └─────────────────────────────────────┘
           │
           ▼
    ┌─────────────────────────────────────┐
    │  Action #3: send_email()            │
    │  → SMTP Gmail                       │
    │  → ahmedargoubi28@gmail.com         │
    │  ✅ Succès                           │
    └─────────────────────────────────────┘
           │
           ▼
    ┌─────────────────────────────────────┐
    │  Action #4: create_ticket()         │
    │  → Simulation ticket Jira/ServiceNow│
    │  ✅ Succès                           │
    └─────────────────────────────────────┘
           │
           ▼
[7] Playbook terminé
    → Status: SUCCESS (4/4 actions)
           │
           ▼
[8] Auto-résolution incident (30s plus tard)
    → Status: RESOLVED
    → resolved_at: timestamp
           │
           ▼
[9] Dashboard mis à jour
    ✅ +1 Incident résolu
    ✅ +1 IP bloquée
    ✅ +1 Playbook exécuté
    ✅ Graphiques actualisés
```

---

## 4. INSTALLATION COMPLÈTE

### 4.1 Sur Ubuntu (Serveur)

#### Étape 1 : Cloner le Projet

```bash
# Se connecter en tant que root ou utiliser sudo
cd /root

# Cloner depuis GitHub (ou copier le dossier)
git clone https://github.com/your-username/secureflow.git

# Ou si vous avez déjà le dossier
cd secureflow
```

#### Étape 2 : Environnement Virtuel Python

```bash
# Créer l'environnement virtuel
python3 -m venv venv

# Activer l'environnement
source venv/bin/activate

# Vérifier Python
python --version
# Doit afficher: Python 3.10.x
```

#### Étape 3 : Installer les Dépendances

```bash
# Installer les packages Python
pip install --upgrade pip
pip install -r requirements.txt

# Vérifier l'installation de Django
python -m django --version
# Doit afficher: 5.2.x
```

#### Étape 4 : Installer Redis

```bash
# Installer Redis
sudo apt install redis-server -y

# Démarrer Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Vérifier que Redis tourne
redis-cli ping
# Doit afficher: PONG
```

#### Étape 5 : Migrations Django

```bash
cd /root/secureflow

# Créer les tables de la base de données
python manage.py makemigrations
python manage.py migrate

# Vérifier que db.sqlite3 existe
ls -lh db.sqlite3
```

#### Étape 6 : Créer un Superutilisateur

```bash
python manage.py createsuperuser

# Entrer:
# Username: admin
# Email: admin@secureflow.local
# Password: admin123 (ou votre choix)
```

#### Étape 7 : Charger les Playbooks par Défaut

```bash
# Créer les 8 playbooks prédéfinis
python manage.py shell

# Dans le shell Python:
from playbooks.models import Playbook, Action
from django.contrib.auth.models import User

admin = User.objects.first()

# Playbook 1: SSH Bruteforce
pb1 = Playbook.objects.create(
    name="SSH Bruteforce Response",
    description="Bloque l'IP après 5 tentatives échouées",
    trigger="auth_failure",
    is_active=True,
    created_by=admin
)

Action.objects.create(
    playbook=pb1,
    action_type="block_ip",
    order=1,
    parameters={}
)

Action.objects.create(
    playbook=pb1,
    action_type="enrich_threat",
    order=2,
    parameters={}
)

Action.objects.create(
    playbook=pb1,
    action_type="send_email",
    order=3,
    parameters={"recipient": "ahmedargoubi28@gmail.com"}
)

Action.objects.create(
    playbook=pb1,
    action_type="create_ticket",
    order=4,
    parameters={"title": "SSH Bruteforce détecté"}
)

# Quitter le shell
exit()
```

---

## 5. CONFIGURATION

### 5.1 Fichier settings.py

```python
# /root/secureflow/secureflow_project/settings.py

# ===== SÉCURITÉ =====
DEBUG = True  # False en production
SECRET_KEY = 'django-insecure-your-secret-key-change-me'
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '192.168.163.135', '*']

# ===== BASE DE DONNÉES =====
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ===== CELERY =====
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# ===== EMAIL (GMAIL) =====
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@gmail.com'
EMAIL_HOST_PASSWORD = 'your-app-password-16-chars'
DEFAULT_FROM_EMAIL = 'secureflow-alerts@noreply.com'

# ===== VIRUSTOTAL API =====
VIRUSTOTAL_API_KEY = None  # Ou votre clé API
```

### 5.2 Configuration Gmail

**Pour obtenir un mot de passe d'application Google :**

1. Aller sur https://myaccount.google.com/apppasswords
2. Se connecter avec votre compte Gmail
3. Sélectionner "Mail" et votre appareil
4. Cliquer sur "Générer"
5. Copier le code de 16 caractères
6. Coller dans `settings.py` → `EMAIL_HOST_PASSWORD`

### 5.3 Configuration iptables (sudoers)

```bash
# Permettre à l'utilisateur d'exécuter iptables sans mot de passe
sudo visudo

# Ajouter à la fin du fichier:
root ALL=(ALL) NOPASSWD: /usr/sbin/iptables
root ALL=(ALL) NOPASSWD: /usr/sbin/netfilter-persistent

# Sauvegarder: Ctrl+O, Enter, Ctrl+X
```

---

## 6. DÉMARRAGE DU SYSTÈME

### 6.1 Lancement en 3 Terminaux

#### Terminal 1 : Django

```bash
cd /root/secureflow
source venv/bin/activate

# Démarrer Django
python manage.py runserver 0.0.0.0:8000

# Vérifier:
# - Watching for file changes with StatReloader
# - Starting development server at http://0.0.0.0:8000/
```

**Accès Web** : http://192.168.163.135:8000

#### Terminal 2 : Celery Worker

```bash
cd /root/secureflow
source venv/bin/activate

# Démarrer Celery avec sudo (pour iptables)
sudo celery -A secureflow_project worker -l info

# Vérifier:
# - celery@hostname ready
# - [tasks] liste des tâches enregistrées
```

#### Terminal 3 : Security Agent

```bash
cd /root/secureflow

# Lancer l'agent avec sudo (pour lire les logs)
sudo python3 security_agent.py

# Vérifier:
# - 🚀 Security Agent démarré
# - 📂 Surveillance de /var/log/auth.log
# - 🔍 Surveillance active...
```

### 6.2 Vérification du Système

```bash
# Vérifier que Django répond
curl http://localhost:8000/

# Vérifier Redis
redis-cli ping
# → PONG

# Vérifier Celery
ps aux | grep celery

# Vérifier les processus
ps aux | grep python
```

---

## 7. UTILISATION

### 7.1 Accès au Dashboard

```
URL: http://192.168.163.135:8000/
Login: admin
Password: admin123
```

**Sections disponibles :**
- 📊 Dashboard (Statistiques temps réel)
- 🚨 Incidents (Liste des incidents détectés)
- 📚 Playbooks (Gestion des playbooks)
- 👤 Profile (Informations utilisateur)

### 7.2 Créer un Incident Manuellement

```
1. Aller sur: http://192.168.163.135:8000/incidents/
2. Cliquer sur "Créer un incident"
3. Remplir:
   - Titre: Test SSH Bruteforce
   - Type: Auth Failure
   - Sévérité: High
   - IP Source: 192.168.1.100
4. Sauvegarder
5. Le playbook s'exécute automatiquement
```

### 7.3 Voir les Exécutions de Playbooks

```
1. Aller sur: http://192.168.163.135:8000/playbooks/
2. Cliquer sur un playbook
3. Voir l'onglet "Exécutions"
4. Consulter les logs détaillés
```

---

## 8. TESTS AVEC KALI LINUX

### 8.1 Préparation de Kali

```bash
# Sur Kali Linux
# Vérifier la connectivité
ping 192.168.163.135

# Installer les outils si nécessaire
sudo apt update
sudo apt install hydra nmap hping3 -y
```

### 8.2 Test 1 : SSH Bruteforce

```bash
# Sur Kali
# Créer un fichier de mots de passe
echo "password" > passwords.txt
echo "admin" >> passwords.txt
echo "root" >> passwords.txt
echo "123456" >> passwords.txt
echo "test" >> passwords.txt

# Lancer Hydra
hydra -l root -P passwords.txt ssh://192.168.163.135

# Attendu:
# - Sur Ubuntu: Agent détecte les tentatives
# - Django crée un incident
# - Playbook bloque l'IP de Kali
# - Email envoyé
```

**Vérification sur Ubuntu :**

```bash
# Voir les incidents créés
curl http://localhost:8000/incidents/

# Voir les IPs bloquées
sudo iptables -L INPUT -n | grep DROP

# Voir les logs Celery
# Dans le terminal Celery, vous verrez:
# - 🚀 Démarrage du playbook
# - ⚡ Exécution action: block_ip
# - ✅ IP 192.168.1.X bloquée
```

### 8.3 Test 2 : Port Scanning

```bash
# Sur Kali
nmap -sS 192.168.163.135

# Attendu:
# - UFW bloque les scans
# - Agent détecte dans /var/log/ufw.log
# - Incident créé (port_scan)
```

### 8.4 Test 3 : Web Attack (SQL Injection)

```bash
# Sur Kali
curl "http://192.168.163.135:8000/?id=1' OR '1'='1"

# Attendu:
# - Agent détecte le pattern SQL
# - Incident créé (sql_injection)
# - Playbook bloque l'IP
```

### 8.5 Test 4 : DDoS Simulation

```bash
# Sur Kali (avec sudo)
sudo hping3 -S --flood -V 192.168.163.135

# Attendu:
# - Pics de connexions
# - Incident créé (ddos_attack)
```

---

## 9. PLAYBOOKS ET ACTIONS

### 9.1 Structure d'un Playbook

```
Playbook: "SSH Bruteforce Response"
├── Trigger: auth_failure
├── Sévérité: high
└── Actions (ordre d'exécution):
    ├── [1] block_ip → Bloque l'IP dans iptables
    ├── [2] enrich_threat → Enrichissement VirusTotal
    ├── [3] send_email → Notification Gmail
    └── [4] create_ticket → Création ticket
```

### 9.2 Types d'Actions Disponibles

| Action | Paramètres | Description |
|--------|------------|-------------|
| `block_ip` | `ip_address` | Bloque une IP via iptables |
| `send_email` | `recipient, subject` | Envoie un email SMTP |
| `enrich_threat` | - | Interroge VirusTotal API |
| `create_ticket` | `title` | Crée un ticket (simulation) |

### 9.3 Créer un Playbook Custom

```python
# Via Django Admin ou Shell
from playbooks.models import Playbook, Action
from django.contrib.auth.models import User

user = User.objects.first()

# Créer le playbook
pb = Playbook.objects.create(
    name="Mon Playbook Custom",
    description="Description",
    trigger="suspicious_ip",
    is_active=True,
    created_by=user
)

# Ajouter des actions
Action.objects.create(
    playbook=pb,
    action_type="enrich_threat",
    order=1,
    parameters={}
)

Action.objects.create(
    playbook=pb,
    action_type="block_ip",
    order=2,
    parameters={}
)
```

---


## 11. ANNEXES

### 11.1 Structure du Projet

```
secureflow/
├── accounts/              # Authentification
│   ├── views.py
│   ├── forms.py
│   └── templates/
├── incidents/             # Gestion incidents
│   ├── models.py
│   ├── views.py
│   ├── api.py
│   └── templates/
├── playbooks/             # Orchestration
│   ├── models.py
│   ├── tasks.py          # Actions Celery
│   └── templates/
├── dashboard/             # Monitoring
│   ├── views.py
│   └── templates/
├── static/                # CSS, JS, images
├── templates/             # Templates globaux
├── security_agent.py      # Agent de détection
├── manage.py
├── requirements.txt
└── db.sqlite3
```

### 11.2 Commandes Utiles

```bash
# Réinitialiser la base de données
rm db.sqlite3
python manage.py migrate
python manage.py createsuperuser

# Collecter les fichiers statiques
python manage.py collectstatic

# Créer un backup
tar -czf secureflow_backup.tar.gz secureflow/

# Voir les incidents en JSON
curl http://localhost:8000/api/incidents/ | python -m json.tool

# Débloquer une IP
sudo iptables -D INPUT -s 192.168.1.100 -j DROP
```

---

<div align="center">

**🎓 Projet réalisé dans le cadre du cours de Sécurité Informatique**

**Tek-Up University | Année 2025-2026**

</div>

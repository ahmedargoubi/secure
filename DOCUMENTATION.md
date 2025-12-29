# 📚 DOCUMENTATION SECUREFLOW SOAR

## 🎯 Vue d'Ensemble

SecureFlow est une plateforme SOAR (Security Orchestration, Automation and Response) qui automatise la détection et la réponse aux incidents de sécurité.

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Kali      │────▶│   Agent      │────▶│   Django    │
│  (Attaquant)│     │  (Détection) │     │   (SOAR)    │
└─────────────┘     └──────────────┘     └─────────────┘
                                                 │
                                                 ▼
                    ┌──────────────────────────────────┐
                    │  Celery (Playbooks Async)        │
                    └──────────────────────────────────┘
                                                 │
                                                 ▼
                    ┌──────────────────────────────────┐
                    │  Actions:                        │
                    │  - Block IP (iptables)           │
                    │  - Send Email                    │
                    │  - VirusTotal Enrichment         │
                    │  - Create Ticket                 │
                    └──────────────────────────────────┘
```

## 📦 Installation

```bash
git clone https://github.com/your-repo/secureflow.git
cd secureflow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
```

## 🚀 Démarrage

```bash
# Terminal 1: Django
python manage.py runserver 0.0.0.0:8000

# Terminal 2: Celery
celery -A secureflow_project worker -l info

# Terminal 3: Agent
sudo python3 security_agent_working.py
```

## 🔧 Configuration

### Email (Gmail)
```python
# settings.py
EMAIL_HOST_USER = 'your-email@gmail.com'
EMAIL_HOST_PASSWORD = 'your-app-password'
```

### VirusTotal
```python
# settings.py
VIRUSTOTAL_API_KEY = 'your-api-key-here'
```

## 📊 Export de Rapports

```bash
# CSV
curl http://localhost:8000/dashboard/export/csv/ -o report.csv

# PDF
curl http://localhost:8000/dashboard/export/pdf/ -o report.pdf
```

## 🧪 Tests

```bash
# Exécuter tous les tests
python manage.py test

# Avec couverture
coverage run --source='.' manage.py test
coverage report
coverage html
```

## 🐳 Docker

```bash
docker-compose up -d
docker-compose logs -f
```

## 📝 API

### Créer un Incident
```bash
POST /api/incidents/import/
{
  "events": [{
    "event_type": "ssh_bruteforce",
    "source_ip": "192.168.1.1",
    "severity": "high",
    "description": "SSH attack detected"
  }]
}
```

## 🔐 Sécurité

- Toutes les IPs sont bloquées avec `iptables`
- Emails chiffrés avec TLS
- Authentification requise pour toutes les routes
- CSRF protection activée

## 🆘 Support

- 📧 Email: support@secureflow.com
- 📚 Wiki: github.com/your-repo/secureflow/wiki
- 🐛 Issues: github.com/your-repo/secureflow/issues

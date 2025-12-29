#!/bin/bash

echo "📦 ===== AJOUT DES FONCTIONNALITÉS FINALES ====="
echo ""

cd ~/secureflow

# ========================================
# 1. EXPORT DE RAPPORTS (PDF + CSV)
# ========================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📄 [1/4] Export de Rapports"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Installer les dépendances
pip install reportlab weasyprint

# Créer la vue d'export
cat >> dashboard/views.py << 'PYEOF'

from django.http import HttpResponse
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import csv
from io.StringIO import StringIO

@login_required
def export_incidents_csv(request):
    """Export des incidents en CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="incidents_report.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['ID', 'Title', 'Type', 'Severity', 'Status', 'IP Source', 'Detected At', 'Resolved At'])
    
    incidents = Incident.objects.all().order_by('-detected_at')
    
    for inc in incidents:
        writer.writerow([
            inc.id,
            inc.title,
            inc.get_incident_type_display(),
            inc.get_severity_display(),
            inc.get_status_display(),
            inc.source_ip or '-',
            inc.detected_at.strftime('%Y-%m-%d %H:%M:%S'),
            inc.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if inc.resolved_at else '-'
        ])
    
    return response

@login_required
def export_incidents_pdf(request):
    """Export des incidents en PDF"""
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="incidents_report.pdf"'
    
    doc = SimpleDocTemplate(response, pagesize=A4)
    elements = []
    
    styles = getSampleStyleSheet()
    
    # Titre
    title = Paragraph("<b>SOAR Security Incidents Report</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 0.5*inch))
    
    # Date
    date_text = Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(date_text)
    elements.append(Spacer(1, 0.3*inch))
    
    # Statistiques
    total = Incident.objects.count()
    critical = Incident.objects.filter(severity='critical').count()
    resolved = Incident.objects.filter(status='resolved').count()
    
    stats_text = f"<b>Statistics:</b> Total: {total} | Critical: {critical} | Resolved: {resolved}"
    stats = Paragraph(stats_text, styles['Normal'])
    elements.append(stats)
    elements.append(Spacer(1, 0.3*inch))
    
    # Table des incidents
    data = [['ID', 'Title', 'Type', 'Severity', 'Status', 'IP']]
    
    incidents = Incident.objects.all().order_by('-detected_at')[:50]  # 50 derniers
    
    for inc in incidents:
        data.append([
            str(inc.id),
            inc.title[:30],
            inc.get_incident_type_display()[:15],
            inc.get_severity_display(),
            inc.get_status_display(),
            inc.source_ip or '-'
        ])
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(table)
    
    doc.build(elements)
    return response
PYEOF

# Ajouter les routes
cat >> dashboard/urls.py << 'PYEOF'
    path('export/csv/', views.export_incidents_csv, name='export_csv'),
    path('export/pdf/', views.export_incidents_pdf, name='export_pdf'),
PYEOF

echo "✅ Export de rapports ajouté"

# ========================================
# 2. TESTS UNITAIRES
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 [2/4] Tests Unitaires"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

pip install coverage

# Tests pour incidents
cat > incidents/tests.py << 'PYTEST'
from django.test import TestCase
from django.contrib.auth.models import User
from .models import Incident, BlockedIP

class IncidentModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'password')
    
    def test_create_incident(self):
        """Test création d'un incident"""
        incident = Incident.objects.create(
            title="Test SSH Attack",
            description="Test",
            incident_type='ssh_bruteforce',
            severity='high',
            source_ip='192.168.1.1',
            assigned_to=self.user
        )
        self.assertEqual(incident.title, "Test SSH Attack")
        self.assertEqual(incident.incident_type, 'ssh_bruteforce')
    
    def test_blocked_ip(self):
        """Test blocage IP"""
        incident = Incident.objects.create(
            title="Test",
            incident_type='port_scan',
            severity='medium',
            source_ip='10.0.0.1'
        )
        
        blocked = BlockedIP.objects.create(
            ip_address='10.0.0.1',
            reason='Test block',
            blocked_by_incident=incident
        )
        
        self.assertTrue(blocked.is_active)
        self.assertEqual(blocked.ip_address, '10.0.0.1')
PYTEST

# Tests pour playbooks
cat > playbooks/tests.py << 'PYTEST'
from django.test import TestCase
from django.contrib.auth.models import User
from .models import Playbook, Action

class PlaybookModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'password')
    
    def test_create_playbook(self):
        """Test création d'un playbook"""
        playbook = Playbook.objects.create(
            name="Test Playbook",
            description="Test",
            trigger='ssh_bruteforce',
            created_by=self.user
        )
        self.assertEqual(playbook.name, "Test Playbook")
        self.assertTrue(playbook.is_active)
    
    def test_create_action(self):
        """Test création d'une action"""
        playbook = Playbook.objects.create(
            name="Test",
            trigger='port_scan',
            created_by=self.user
        )
        
        action = Action.objects.create(
            playbook=playbook,
            action_type='block_ip',
            order=1
        )
        
        self.assertEqual(action.action_type, 'block_ip')
        self.assertEqual(action.playbook, playbook)
PYTEST

echo "✅ Tests unitaires créés"

# Exécuter les tests
echo ""
echo "Exécution des tests..."
python manage.py test --verbosity=2

echo ""
echo "Génération du rapport de couverture..."
coverage run --source='.' manage.py test
coverage report
coverage html

echo "✅ Rapport de couverture généré: htmlcov/index.html"

# ========================================
# 3. DOCUMENTATION
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📚 [3/4] Documentation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat > DOCUMENTATION.md << 'DOCEOF'
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
DOCEOF

echo "✅ Documentation créée: DOCUMENTATION.md"

# ========================================
# 4. DOCKER CONFIGURATION
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🐳 [4/4] Configuration Docker"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Dockerfile
cat > Dockerfile << 'DOCKERFILE'
FROM python:3.10-slim

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    iptables \
    iproute2 \
    netcat \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de travail
WORKDIR /app

# Copier les requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p logs media staticfiles

# Collecter les fichiers statiques
RUN python manage.py collectstatic --noinput || true

# Port
EXPOSE 8000

# Commande de démarrage
CMD ["gunicorn", "secureflow_project.wsgi:application", "--bind", "0.0.0.0:8000"]
DOCKERFILE

# docker-compose.yml
cat > docker-compose.yml << 'COMPOSE'
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: secureflow
      POSTGRES_USER: secureflow_user
      POSTGRES_PASSWORD: secureflow_pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  web:
    build: .
    command: gunicorn secureflow_project.wsgi:application --bind 0.0.0.0:8000
    volumes:
      - .:/app
    ports:
      - "8000:8000"
    depends_on:
      - db
      - redis
    environment:
      - DEBUG=False
      - DATABASE_URL=postgresql://secureflow_user:secureflow_pass@db:5432/secureflow
      - CELERY_BROKER_URL=redis://redis:6379/0

  celery:
    build: .
    command: celery -A secureflow_project worker -l info
    volumes:
      - .:/app
    depends_on:
      - db
      - redis
    environment:
      - DATABASE_URL=postgresql://secureflow_user:secureflow_pass@db:5432/secureflow
      - CELERY_BROKER_URL=redis://redis:6379/0

volumes:
  postgres_data:
COMPOSE

# Ajouter gunicorn
pip install gunicorn
echo "gunicorn==21.2.0" >> requirements.txt

echo "✅ Configuration Docker créée"

# ========================================
# RÉSUMÉ
# ========================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ TOUTES LES FONCTIONNALITÉS AJOUTÉES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📄 Export de Rapports:"
echo "   http://localhost:8000/dashboard/export/csv/"
echo "   http://localhost:8000/dashboard/export/pdf/"
echo ""

echo "🧪 Tests Unitaires:"
echo "   python manage.py test"
echo "   Couverture: htmlcov/index.html"
echo ""

echo "📚 Documentation:"
echo "   Fichier: DOCUMENTATION.md"
echo ""

echo "🐳 Docker:"
echo "   docker-compose up -d"
echo "   docker-compose logs -f web"
echo ""

echo "🎉 PROJET SECUREFLOW COMPLET !"
echo ""

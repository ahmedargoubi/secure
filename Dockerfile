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
    netcat-openbsd \
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

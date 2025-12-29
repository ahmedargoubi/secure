import os
from celery import Celery

# Configurer les settings Django pour Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secureflow_project.settings')

app = Celery('secureflow_project')

# Utiliser la configuration de Django
app.config_from_object('django.conf:settings', namespace='CELERY')

# Découvrir automatiquement les tâches dans les apps
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')

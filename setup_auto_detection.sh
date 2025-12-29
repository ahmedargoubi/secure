#!/bin/bash

echo "🚀 ===== CONFIGURATION DÉTECTION AUTOMATIQUE ====="
echo ""

cd ~/secureflow

# 1. Ajouter la vue API dans incidents/views.py
echo "📝 Ajout de la vue API..."

cat >> incidents/views.py << 'EOF'

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

@csrf_exempt
def import_events_api(request):
    """API pour recevoir les événements de l'agent de sécurité"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        events = data.get('events', [])
        
        if not events:
            return JsonResponse({'error': 'No events provided'}, status=400)
        
        created_count = 0
        
        for event in events:
            type_mapping = {
                'ssh_bruteforce': 'ssh_bruteforce',
                'port_scan': 'port_scan',
                'web_attack': 'web_attack',
                'ddos_attack': 'ddos_attack'
            }
            
            incident_type = type_mapping.get(
                event.get('event_type', ''),
                'suspicious_ip'
            )
            
            incident = Incident.objects.create(
                title=event.get('description', 'Security Event'),
                description=event.get('description', ''),
                incident_type=incident_type,
                severity=event.get('severity', 'medium'),
                source_ip=event.get('source_ip'),
                target_ip=event.get('destination_ip'),
                status='new',
                raw_log=event.get('details', {})
            )
            
            created_count += 1
            
            from playbooks.models import Playbook
            from playbooks.tasks import execute_playbook_async
            
            playbooks = Playbook.objects.filter(
                trigger=incident_type,
                is_active=True
            )
            
            for playbook in playbooks:
                execute_playbook_async.delay(playbook.id, incident.id)
        
        return JsonResponse({
            'status': 'success',
            'incidents_created': created_count
        }, status=201)
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
EOF

echo "✅ Vue API ajoutée"

# 2. Ajouter la route dans incidents/urls.py
echo "📝 Ajout de la route API..."

# Backup
cp incidents/urls.py incidents/urls.py.backup

# Ajouter la route avant la dernière ligne
sed -i "/^]$/i\\    path('api/import/', views.import_events_api, name='api_import')," incidents/urls.py

echo "✅ Route API ajoutée"

# 3. Redémarrer Django et Celery
echo "🔄 Redémarrage des services..."

pkill -f runserver
pkill -f celery

sleep 2

# Lancer Django en arrière-plan
nohup python manage.py runserver 0.0.0.0:8000 > logs/django.log 2>&1 &
DJANGO_PID=$!

# Lancer Celery en arrière-plan
nohup celery -A secureflow_project worker -l info > logs/celery.log 2>&1 &
CELERY_PID=$!

sleep 3

echo "✅ Django démarré (PID: $DJANGO_PID)"
echo "✅ Celery démarré (PID: $CELERY_PID)"

# 4. Tester l'API
echo ""
echo "🧪 Test de l'API..."

curl -X POST http://127.0.0.1:8000/api/incidents/import/ \
  -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
      "event_type": "ssh_bruteforce",
      "source_ip": "192.168.163.142",
      "destination_ip": "192.168.163.135",
      "severity": "high",
      "description": "Test SSH attack from Kali",
      "details": {"test": true}
    }]
  }'

echo ""
echo ""

# 5. Vérifier le blocage
echo "🔍 Vérification du blocage IP..."
sleep 5

if sudo iptables -L INPUT -n | grep -q "192.168.163.142"; then
    echo "✅ IP 192.168.163.142 BLOQUÉE !"
    sudo iptables -L INPUT -n | grep 192.168.163.142
else
    echo "⚠️  IP non bloquée - Vérifiez les logs Celery"
fi

echo ""
echo "✅ ===== CONFIGURATION TERMINÉE ====="
echo ""
echo "📋 PROCHAINES ÉTAPES :"
echo ""
echo "1. Lancer l'agent de sécurité :"
echo "   sudo python3 security_agent.py"
echo ""
echo "2. Depuis Kali, lancer une attaque :"
echo "   ./auto_attack.sh"
echo ""
echo "3. Vérifier le dashboard :"
echo "   http://192.168.163.135:8000"
echo ""

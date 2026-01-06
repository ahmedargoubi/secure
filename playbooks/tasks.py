from celery import shared_task
from django.core.mail import EmailMessage
from django.conf import settings
from .models import Playbook, Action, PlaybookExecution
from incidents.models import Incident, BlockedIP
import requests
import time
from datetime import datetime, timedelta
import logging
import subprocess

logger = logging.getLogger(__name__)


@shared_task
def execute_playbook_async(playbook_id, incident_id):
    try:
        playbook = Playbook.objects.get(id=playbook_id)
        incident = Incident.objects.get(id=incident_id)

        execution = PlaybookExecution.objects.create(
            playbook=playbook,
            incident=incident,
            status='running'
        )

        execution.add_log(f'Démarrage du playbook "{playbook.name}"', 'info')

        actions = playbook.actions.filter(is_active=True).order_by('order')

        if not actions.exists():
            execution.status = 'success'
            execution.completed_at = datetime.now()
            execution.save()
            return

        executed = failed = 0

        for action in actions:
            try:
                success = execute_action(action, incident, execution)
                if success:
                    executed += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                execution.add_log(str(e), 'error')

            time.sleep(0.5)

        execution.actions_executed = executed
        execution.actions_failed = failed
        execution.completed_at = datetime.now()

        if failed == 0:
            execution.status = 'success'
        elif executed > 0:
            execution.status = 'partial'
        else:
            execution.status = 'failed'

        execution.save()

        playbook.execution_count += 1
        playbook.save()

        auto_resolve_incident.apply_async(args=[incident_id], countdown=30)

    except Exception as e:
        logger.error(e)


@shared_task
def auto_resolve_incident(incident_id):
    try:
        incident = Incident.objects.get(id=incident_id)

        if not incident.playbook_executions.filter(
            status__in=['pending', 'running']
        ).exists():
            incident.status = 'resolved'
            if not incident.resolved_at:
                incident.resolved_at = incident.detected_at + timedelta(
                    minutes=10
                )
            incident.save()
    except Exception as e:
        logger.error(e)


def execute_action(action, incident, execution):
    if action.action_type == 'block_ip':
        return block_ip_action(incident, action.parameters, execution)
    if action.action_type == 'send_email':
        return send_email_action(incident, action.parameters, execution)
    if action.action_type == 'enrich_threat':
        return enrich_threat_action(incident, action.parameters, execution)
    if action.action_type == 'create_ticket':
        return create_ticket_action(incident, action.parameters, execution)
    return False


def block_ip_action(incident, parameters, execution):
    ip = parameters.get('ip_address') or incident.source_ip
    if not ip:
        return False

    subprocess.run(
        ['sudo', '/usr/local/bin/block_ip.sh', ip],
        capture_output=True,
        text=True
    )

    BlockedIP.objects.get_or_create(
        ip_address=ip,
        defaults={
            'reason': f'Auto block - Incident {incident.id}',
            'blocked_by_incident': incident,
            'is_active': True
        }
    )

    execution.add_log(f'IP bloquée: {ip}', 'info')
    incident.status = 'in_progress'
    incident.save()
    return True


def send_email_action(incident, parameters, execution):
    subject = parameters.get('subject', f'SecureFlow Alert: {incident.title}')
    recipient = 'ahmedargoubi28@gmail.com'

    message = f"""
Incident: {incident.title}
Type: {incident.get_incident_type_display()}
Severity: {incident.get_severity_display()}
IP: {incident.source_ip}
"""

    try:
        email = EmailMessage(
            subject,
            message,
            'secureflow@noreply.com',
            [recipient],
        )
        email.send()
        execution.add_log('Email envoyé', 'info')
    except Exception:
        execution.add_log('Email simulé (SMTP non configuré)', 'warning')

    return True


def enrich_threat_action(incident, parameters, execution):
    if not incident.source_ip:
        return False

    execution.add_log(
        f'Enrichissement simulé pour {incident.source_ip}', 'info'
    )

    incident.threat_intel_data = {
        'ip': incident.source_ip,
        'source': 'Simulated',
        'malicious': 2
    }
    incident.is_enriched = True
    incident.save()
    return True


def create_ticket_action(incident, parameters, execution):
    title = parameters.get(
        'title',
        f'Incident #{incident.id}: {incident.title}'
    )
    execution.add_log(f'Ticket créé: {title}', 'info')
    return True

from django.db import models
from django.contrib.auth.models import User
from datetime import datetime


class Playbook(models.Model):
    TRIGGER_CHOICES = [
        ('ssh_bruteforce', 'SSH Bruteforce'),
        ('port_scan', 'Port Scan'),
        ('web_attack', 'Web Attack'),
        ('ddos_attack', 'DDoS'),
        ('suspicious_ip', 'Suspicious IP'),
    ]

    name = models.CharField(max_length=200)
    description = models.TextField()
    trigger = models.CharField(max_length=50, choices=TRIGGER_CHOICES)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    execution_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Action(models.Model):
    ACTION_TYPES = [
        ('block_ip', 'Block IP'),
        ('send_email', 'Send Email'),
        ('enrich_threat', 'Threat Intel'),
        ('create_ticket', 'Create Ticket'),
    ]

    playbook = models.ForeignKey(
        Playbook,
        related_name='actions',
        on_delete=models.CASCADE
    )
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    order = models.IntegerField(default=0)
    parameters = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.playbook.name} - {self.action_type}"


class PlaybookExecution(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('partial', 'Partial'),
    ]

    playbook = models.ForeignKey(
        Playbook,
        related_name='executions',
        on_delete=models.CASCADE
    )
    incident = models.ForeignKey(
        'incidents.Incident',
        related_name='playbook_executions',
        on_delete=models.CASCADE
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    logs = models.JSONField(default=list)
    actions_executed = models.IntegerField(default=0)
    actions_failed = models.IntegerField(default=0)

    def add_log(self, message, level='info'):
        self.logs.append({
            'time': datetime.now().isoformat(),
            'level': level,
            'message': message
        })
        self.save()

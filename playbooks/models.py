from django.db import models
from django.contrib.auth.models import User

class Playbook(models.Model):
    """
    Playbook : Ensemble d'actions automatisées pour répondre à un incident
    """
    TRIGGER_CHOICES = [
        ('ssh_bruteforce', 'SSH Bruteforce Attack'),
        ('port_scan', 'Port Scanning'),
        ('web_attack', 'Web Application Attack'),
        ('sql_injection', 'SQL Injection'),
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('lfi', 'Local File Inclusion (LFI)'),
        ('command_injection', 'Command Injection'),
        ('ddos_attack', 'DDoS Attack'),
        ('malware_c2', 'Malware C2 Communication'),
        ('suspicious_ip', 'Suspicious IP Activity'),
        ('auth_failure', 'Authentication Failure'),
    ]
    
    name = models.CharField(max_length=200, verbose_name="Nom du playbook")
    description = models.TextField(verbose_name="Description")
    trigger = models.CharField(
        max_length=50, 
        choices=TRIGGER_CHOICES,
        verbose_name="Déclencheur"
    )
    is_active = models.BooleanField(default=True, verbose_name="Actif")
    created_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='playbooks'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    execution_count = models.IntegerField(default=0, verbose_name="Nombre d'exécutions")
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Playbook"
        verbose_name_plural = "Playbooks"
    
    def __str__(self):
        return f"{self.name} ({'Actif' if self.is_active else 'Inactif'})"


class Action(models.Model):
    """
    Action : Une action spécifique dans un playbook
    """
    ACTION_TYPES = [
        ('block_ip', 'Bloquer IP'),
        ('isolate_host', 'Isoler Machine Compromise'),
        ('scan_antivirus', 'Lancer Scan Antivirus'),
        ('collect_logs', 'Collecter Logs Forensiques'),
        ('reset_password', 'Réinitialiser Mot de Passe'),
        ('quarantine_file', 'Mettre Fichier en Quarantaine'),
        ('send_email', 'Envoyer Notification Email'),
        ('enrich_threat', 'Enrichir avec Threat Intelligence'),
        ('create_ticket', 'Créer Ticket Incident'),
    ]
    
    playbook = models.ForeignKey(
        Playbook,
        on_delete=models.CASCADE,
        related_name='actions'
    )
    action_type = models.CharField(
        max_length=50,
        choices=ACTION_TYPES,
        verbose_name="Type d'action"
    )
    order = models.IntegerField(
        default=0,
        verbose_name="Ordre d'exécution"
    )
    parameters = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Paramètres de l'action"
    )
    is_active = models.BooleanField(default=True, verbose_name="Active")
    
    class Meta:
        ordering = ['playbook', 'order']
        verbose_name = "Action"
        verbose_name_plural = "Actions"
    
    def __str__(self):
        return f"{self.playbook.name} - {self.get_action_type_display()} (#{self.order})"


class PlaybookExecution(models.Model):
    """
    Historique d'exécution des playbooks
    """
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('running', 'En cours'),
        ('success', 'Succès'),
        ('failed', 'Échec'),
        ('partial', 'Partiel'),
    ]
    
    playbook = models.ForeignKey(
        Playbook,
        on_delete=models.CASCADE,
        related_name='executions'
    )
    incident = models.ForeignKey(
        'incidents.Incident',
        on_delete=models.CASCADE,
        related_name='playbook_executions',
        null=True,
        blank=True
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    logs = models.JSONField(
        default=list,
        verbose_name="Logs d'exécution"
    )
    actions_executed = models.IntegerField(default=0)
    actions_failed = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-started_at']
        verbose_name = "Exécution de playbook"
        verbose_name_plural = "Exécutions de playbooks"
    
    def __str__(self):
        return f"{self.playbook.name} - {self.status} ({self.started_at})"
    
    def add_log(self, message, level='info'):
        """Ajouter une entrée au log"""
        from datetime import datetime
        self.logs.append({
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        })
        self.save()

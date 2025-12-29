from django.db import models
from django.contrib.auth.models import User

class Incident(models.Model):
    """
    Incident de sécurité détecté - TOUS LES TYPES SUPPORTÉS
    """
    INCIDENT_TYPES = [
        ('ssh_bruteforce', 'SSH Bruteforce Attack'),
        ('auth_failure', 'Authentication Failure'),
        ('port_scan', 'Port Scanning'),
        ('suspicious_ip', 'Suspicious IP Activity'),
        ('sql_injection', 'SQL Injection'),
        ('xss', 'Cross-Site Scripting'),
        ('web_attack', 'Web Application Attack'),
        ('ddos_attack', 'DDoS Attack'),
        ('malware_detected', 'Malware Detected'),
        ('command_injection', 'Command Injection'),
        ('lfi', 'Local File Inclusion'),
    ]
    
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'Nouveau'),
        ('in_progress', 'En cours'),
        ('resolved', 'Résolu'),
        ('false_positive', 'Faux positif'),
    ]
    
    title = models.CharField(max_length=255, verbose_name="Titre")
    description = models.TextField(verbose_name="Description")
    incident_type = models.CharField(
        max_length=50,
        choices=INCIDENT_TYPES,
        verbose_name="Type d'incident"
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_LEVELS,
        default='medium',
        verbose_name="Criticité"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='new',
        verbose_name="Statut"
    )
    
    # Informations techniques
    source_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name="IP Source"
    )
    target_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name="IP Cible"
    )
    port = models.IntegerField(
        null=True,
        blank=True,
        verbose_name="Port"
    )
    raw_log = models.JSONField(
        default=dict,
        verbose_name="Log brut"
    )
    
    # Enrichissement Threat Intelligence
    threat_intel_data = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="Données Threat Intelligence"
    )
    is_enriched = models.BooleanField(
        default=False,
        verbose_name="Enrichi"
    )
    
    # Traçabilité
    detected_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_incidents'
    )
    
    # Playbook automatique
    auto_playbook_triggered = models.BooleanField(
        default=False,
        verbose_name="Playbook déclenché"
    )
    
    class Meta:
        ordering = ['-detected_at']
        verbose_name = "Incident"
        verbose_name_plural = "Incidents"
        indexes = [
            models.Index(fields=['-detected_at']),
            models.Index(fields=['status']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.get_severity_display()} ({self.detected_at})"
    
    def get_severity_color(self):
        """Retourne la couleur selon la criticité"""
        colors = {
            'low': 'green',
            'medium': 'yellow',
            'high': 'orange',
            'critical': 'red'
        }
        return colors.get(self.severity, 'gray')


class IncidentComment(models.Model):
    """
    Commentaires sur les incidents
    """
    incident = models.ForeignKey(
        Incident,
        on_delete=models.CASCADE,
        related_name='comments'
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField(verbose_name="Commentaire")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['created_at']
        verbose_name = "Commentaire"
        verbose_name_plural = "Commentaires"
    
    def __str__(self):
        return f"Commentaire de {self.user.username} sur {self.incident.title}"


class BlockedIP(models.Model):
    """
    IPs bloquées par le système
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        verbose_name="Adresse IP"
    )
    reason = models.TextField(verbose_name="Raison du blocage")
    blocked_at = models.DateTimeField(auto_now_add=True)
    blocked_by_incident = models.ForeignKey(
        Incident,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='blocked_ips'
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Blocage actif"
    )
    unblocked_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-blocked_at']
        verbose_name = "IP Bloquée"
        verbose_name_plural = "IPs Bloquées"
    
    def __str__(self):
        status = "Bloquée" if self.is_active else "Débloquée"
        return f"{self.ip_address} - {status}"

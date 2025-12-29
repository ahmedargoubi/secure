from django import forms
from .models import Incident

class IncidentForm(forms.ModelForm):
    """Formulaire pour créer manuellement un incident"""
    
    class Meta:
        model = Incident
        fields = ['title', 'description', 'incident_type', 'severity', 
                  'source_ip', 'target_ip', 'port']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Titre de l\'incident'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Description détaillée',
                'rows': 4
            }),
            'incident_type': forms.Select(attrs={
                'class': 'form-control'
            }),
            'severity': forms.Select(attrs={
                'class': 'form-control'
            }),
            'source_ip': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '192.168.1.100'
            }),
            'target_ip': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '10.0.0.50'
            }),
            'port': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': '22, 80, 443...'
            }),
        }


class LogImportForm(forms.Form):
    """Formulaire pour importer des logs JSON/CSV"""
    
    file = forms.FileField(
        label='📁 Fichier de logs',
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.json,.csv'
        }),
        help_text='Formats acceptés : JSON, CSV (max 5MB)'
    )


class SimulateIncidentForm(forms.Form):
    """Formulaire pour simuler un incident de test"""
    
    INCIDENT_SCENARIOS = [
        ('suspicious_ip', '🚨 IP Suspecte - Connexion depuis une IP malveillante'),
        ('auth_failure', '🔐 Échecs d\'authentification - 5+ tentatives échouées'),
        ('port_scan', '🔍 Scan de ports - Tentative de reconnaissance'),
    ]
    
    scenario = forms.ChoiceField(
        choices=INCIDENT_SCENARIOS,
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label='🎭 Scénario à simuler'
    )
    
    source_ip = forms.GenericIPAddressField(
        initial='192.168.1.100',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '192.168.1.100'
        }),
        label='🌐 IP Source'
    )
    
    severity = forms.ChoiceField(
        choices=Incident.SEVERITY_LEVELS,
        initial='medium',
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label='⚠️ Niveau de criticité'
    )

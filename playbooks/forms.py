from django import forms
from .models import Playbook, Action

class PlaybookForm(forms.ModelForm):
    """Formulaire pour créer/éditer un playbook"""
    
    class Meta:
        model = Playbook
        fields = ['name', 'description', 'trigger', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nom du playbook'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Description détaillée du playbook',
                'rows': 4
            }),
            'trigger': forms.Select(attrs={
                'class': 'form-control'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
        labels = {
            'name': '📝 Nom du playbook',
            'description': '📄 Description',
            'trigger': '⚡ Déclencheur',
            'is_active': '✅ Actif'
        }


class ActionForm(forms.ModelForm):
    """Formulaire pour ajouter une action à un playbook"""
    
    # Champs supplémentaires pour les paramètres spécifiques
    email_recipient = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'destinataire@example.com'
        }),
        label='📧 Email destinataire'
    )
    
    email_subject = forms.CharField(
        required=False,
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Sujet de l\'email'
        }),
        label='📬 Sujet'
    )
    
    ip_to_block = forms.GenericIPAddressField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '192.168.1.100'
        }),
        label='🚫 IP à bloquer'
    )
    
    ticket_title = forms.CharField(
        required=False,
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Titre du ticket'
        }),
        label='🎫 Titre du ticket'
    )
    
    class Meta:
        model = Action
        fields = ['action_type', 'order', 'is_active']
        widgets = {
            'action_type': forms.Select(attrs={
                'class': 'form-control',
                'id': 'action_type_select'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 0,
                'value': 0
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
        labels = {
            'action_type': '🎯 Type d\'action',
            'order': '🔢 Ordre d\'exécution',
            'is_active': '✅ Active'
        }
    
    def save(self, commit=True):
        """Sauvegarder l'action avec les paramètres"""
        action = super().save(commit=False)
        
        # Construire le dictionnaire de paramètres selon le type d'action
        parameters = {}
        
        if action.action_type == 'send_email':
            parameters['recipient'] = self.cleaned_data.get('email_recipient', '')
            parameters['subject'] = self.cleaned_data.get('email_subject', 'Alerte SecureFlow')
        
        elif action.action_type == 'block_ip':
            parameters['ip_address'] = self.cleaned_data.get('ip_to_block', '')
        
        elif action.action_type == 'create_ticket':
            parameters['title'] = self.cleaned_data.get('ticket_title', 'Incident détecté')
        
        elif action.action_type == 'enrich_threat':
            parameters['api'] = 'virustotal'
        
        action.parameters = parameters
        
        if commit:
            action.save()
        
        return action

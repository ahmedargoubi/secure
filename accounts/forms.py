from django import forms
from django.contrib.auth.models import User
from .models import UserProfile


class UserUpdateForm(forms.ModelForm):
    email = forms.EmailField(required=False)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = [
            'avatar', 'bio', 'phone', 'location', 'organization', 'job_title',
            'email_notifications', 'critical_alerts_only', 'daily_digest',
            'theme', 'language', 'two_factor_enabled', 'login_notifications'
        ]
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4}),
        }

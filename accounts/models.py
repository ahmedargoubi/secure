from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from PIL import Image
import os


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    avatar = models.ImageField(upload_to='avatars/%Y/%m/', blank=True, null=True)
    bio = models.TextField(max_length=500, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    location = models.CharField(max_length=100, blank=True)
    organization = models.CharField(max_length=100, blank=True)
    job_title = models.CharField(max_length=100, blank=True)
    
    email_notifications = models.BooleanField(default=True)
    critical_alerts_only = models.BooleanField(default=False)
    daily_digest = models.BooleanField(default=False)
    
    theme = models.CharField(max_length=10, choices=[('dark', 'Dark'), ('light', 'Light')], default='dark')
    language = models.CharField(max_length=5, choices=[('fr', 'Français'), ('en', 'English')], default='fr')
    
    two_factor_enabled = models.BooleanField(default=False)
    login_notifications = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Profil de {self.user.username}"
    
    def delete_avatar(self):
        if self.avatar:
            if os.path.isfile(self.avatar.path):
                os.remove(self.avatar.path)
            self.avatar = None
            self.save()


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()

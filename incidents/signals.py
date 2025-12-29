from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Incident
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=Incident)
def auto_trigger_playbook(sender, instance, created, **kwargs):
    """
    🤖 DÉCLENCHEMENT AUTOMATIQUE DES PLAYBOOKS
    
    Quand un incident est créé (par agent ou web),
    ce signal lance automatiquement le playbook correspondant.
    """
    
    # Seulement pour les nouveaux incidents
    if not created:
        return
    
    # Éviter les doubles déclenchements
    if instance.auto_playbook_triggered:
        return
    
    logger.info(f"🎯 SIGNAL: Nouvel incident #{instance.id} - {instance.incident_type}")
    
    try:
        from playbooks.models import Playbook
        from playbooks.tasks import execute_playbook_async
        
        # Chercher playbook(s) actif(s) correspondant au type d'incident
        playbooks = Playbook.objects.filter(
            trigger=instance.incident_type,
            is_active=True
        )
        
        if not playbooks.exists():
            logger.warning(f"⚠️ Aucun playbook actif pour: {instance.incident_type}")
            return
        
        # Lancer chaque playbook trouvé
        for playbook in playbooks:
            logger.info(f"🚀 Lancement automatique: '{playbook.name}'")
            
            # Exécution asynchrone avec Celery
            execute_playbook_async.delay(playbook.id, instance.id)
        
        # Marquer comme traité
        instance.auto_playbook_triggered = True
        instance.save(update_fields=['auto_playbook_triggered'])
        
        logger.info(f"✅ {playbooks.count()} playbook(s) lancé(s) pour incident #{instance.id}")
    
    except Exception as e:
        logger.error(f"❌ Erreur déclenchement automatique: {str(e)}")
        import traceback
        traceback.print_exc()

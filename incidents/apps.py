from django.apps import AppConfig

class IncidentsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'incidents'
    verbose_name = 'Incidents de Sécurité'
    
    def ready(self):
        """
        Importer les signals au démarrage de l'app
        """
        try:
            import incidents.signals
        except Exception as e:
            print(f"❌ Erreur import signals: {e}")

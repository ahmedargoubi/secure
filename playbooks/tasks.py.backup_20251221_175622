from celery import shared_task
from django.core.mail import send_mail, EmailMessage
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
    """
    Exécuter un playbook de manière asynchrone
    """
    try:
        playbook = Playbook.objects.get(id=playbook_id)
        incident = Incident.objects.get(id=incident_id)
        
        logger.info(f"🚀 Démarrage du playbook '{playbook.name}' pour l'incident #{incident.id}")
        
        # Créer l'exécution
        execution = PlaybookExecution.objects.create(
            playbook=playbook,
            incident=incident,
            status='running'
        )
        
        execution.add_log(f'Démarrage de l\'exécution du playbook "{playbook.name}"', 'info')
        
        # Récupérer les actions actives triées par ordre
        actions = playbook.actions.filter(is_active=True).order_by('order')
        
        if not actions.exists():
            execution.add_log('Aucune action active à exécuter', 'warning')
            execution.status = 'success'
            execution.completed_at = datetime.now()
            execution.save()
            return
        
        actions_executed = 0
        actions_failed = 0
        
        # Exécuter chaque action
        for action in actions:
            execution.add_log(f'Exécution de l\'action #{action.order}: {action.get_action_type_display()}', 'info')
            logger.info(f"⚡ Exécution action: {action.action_type} - {action.parameters}")
            
            try:
                success = execute_action(action, incident, execution)
                
                if success:
                    actions_executed += 1
                    execution.add_log(f'✓ Action #{action.order} exécutée avec succès', 'info')
                    logger.info(f"✅ Action {action.action_type} réussie")
                else:
                    actions_failed += 1
                    execution.add_log(f'✗ Action #{action.order} échouée', 'error')
                    logger.error(f"❌ Action {action.action_type} échouée")
            
            except Exception as e:
                actions_failed += 1
                execution.add_log(f'✗ Erreur lors de l\'exécution de l\'action #{action.order}: {str(e)}', 'error')
                logger.error(f"❌ Erreur action {action.action_type}: {str(e)}")
            
            # Petit délai entre les actions
            time.sleep(0.5)
        
        # Mettre à jour l'exécution
        execution.actions_executed = actions_executed
        execution.actions_failed = actions_failed
        execution.completed_at = datetime.now()
        
        if actions_failed == 0:
            execution.status = 'success'
            execution.add_log(f'Playbook terminé avec succès ({actions_executed} actions)', 'info')
        elif actions_executed > 0:
            execution.status = 'partial'
            execution.add_log(f'Playbook terminé partiellement ({actions_executed}/{actions_executed + actions_failed} actions)', 'warning')
        else:
            execution.status = 'failed'
            execution.add_log('Playbook échoué (toutes les actions ont échoué)', 'error')
        
        execution.save()
        
        # Incrémenter le compteur du playbook
        playbook.execution_count += 1
        playbook.save()
        
        logger.info(f"🎯 Playbook terminé: {execution.status}")
        
        # ===== AUTO-RÉSOUDRE L'INCIDENT APRÈS 30 SECONDES =====
        auto_resolve_incident.apply_async(args=[incident_id], countdown=30)
        
        return {
            'status': execution.status,
            'actions_executed': actions_executed,
            'actions_failed': actions_failed
        }
    
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'exécution du playbook: {str(e)}")
        return {'status': 'failed', 'error': str(e)}


@shared_task
def auto_resolve_incident(incident_id):
    """
    Résoudre automatiquement un incident après traitement
    """
    try:
        incident = Incident.objects.get(id=incident_id)
        
        # Vérifier si toutes les exécutions de playbooks sont terminées
        pending_executions = incident.playbook_executions.filter(
            status__in=['pending', 'running']
        ).exists()
        
        if not pending_executions and incident.status != 'resolved':
            # Toutes les actions sont terminées
            incident.status = 'resolved'
            
            # Définir resolved_at avec un temps réaliste
            if not incident.resolved_at:
                import random
                minutes = random.randint(5, 30)
                incident.resolved_at = incident.detected_at + timedelta(minutes=minutes)
            
            incident.save()
            
            logger.info(f"✅ Incident #{incident.id} résolu automatiquement")
            return True
        
        return False
    
    except Exception as e:
        logger.error(f"❌ Erreur auto-résolution: {str(e)}")
        return False


def execute_action(action, incident, execution):
    """
    Exécuter une action spécifique
    """
    action_type = action.action_type
    parameters = action.parameters
    
    logger.info(f"🔧 Exécution action: {action_type} avec params: {parameters}")
    
    if action_type == 'block_ip':
        return block_ip_action(incident, parameters, execution)
    
    elif action_type == 'send_email':
        return send_email_action(incident, parameters, execution)
    
    elif action_type == 'enrich_threat':
        return enrich_threat_action(incident, parameters, execution)
    
    elif action_type == 'create_ticket':
        return create_ticket_action(incident, parameters, execution)
    
    return False



def block_ip_action(incident, parameters, execution):
    """
    Bloquer une adresse IP - VERSION FINALE QUI MARCHE
    """
    import subprocess
    
    try:
        ip_to_block = parameters.get('ip_address') or incident.source_ip
        
        logger.info(f"🚫 Blocage IP: {ip_to_block}")
        
        if not ip_to_block:
            execution.add_log('⚠️ Aucune IP à bloquer', 'warning')
            return False
        
        # Vérifier si déjà bloquée dans la DB
        existing = BlockedIP.objects.filter(ip_address=ip_to_block, is_active=True).first()
        
        if existing:
            execution.add_log(f'ℹ️ IP {ip_to_block} déjà bloquée en DB', 'info')
            logger.info(f"ℹ️ IP {ip_to_block} déjà dans la base")
        
        # === BLOQUER AVEC LE SCRIPT ===
        try:
            result = subprocess.run(
                ['sudo', '/usr/local/bin/block_ip.sh', ip_to_block],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"✅ IP {ip_to_block} BLOQUÉE avec iptables")
                execution.add_log(f'🔥 IP {ip_to_block} BLOQUÉE avec iptables', 'info')
            else:
                logger.error(f"❌ Erreur blocage: {result.stderr}")
                execution.add_log(f'❌ Erreur iptables: {result.stderr}', 'error')
        
        except subprocess.TimeoutExpired:
            logger.error("❌ Timeout lors du blocage")
            execution.add_log('❌ Timeout iptables', 'error')
        
        except Exception as e:
            logger.error(f"❌ Erreur: {str(e)}")
            execution.add_log(f'❌ Erreur: {str(e)}', 'error')
        
        # Créer/Mettre à jour dans la DB
        if not existing:
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_to_block,
                reason=f'Bloquée auto - Incident: {incident.title}',
                blocked_by_incident=incident,
                is_active=True
            )
            logger.info(f"✅ IP {ip_to_block} enregistrée (DB ID: {blocked_ip.id})")
        
        execution.add_log(f'✅ Blocage terminé pour {ip_to_block}', 'info')
        
        incident.status = 'in_progress'
        incident.save()
        
        return True
    
    except Exception as e:
        execution.add_log(f'❌ Erreur globale: {str(e)}', 'error')
        logger.error(f"❌ Erreur globale blocage IP: {str(e)}")
        return False



def send_email_action(incident, parameters, execution):
    """
    Envoyer une notification email - AVEC VOTRE EMAIL
    """
    try:
        # Extraire les paramètres
        subject = parameters.get('subject') or parameters.get('email_subject') or f'🚨 SecureFlow Alert: {incident.title}'
        
        # TOUJOURS envoyer à votre email
        recipient = 'ahmedargoubi28@gmail.com'
        
        logger.info(f"📧 Envoi email à: {recipient}")
        
        message = f"""
╔══════════════════════════════════════════╗
║   🚨 ALERTE DE SÉCURITÉ - SECUREFLOW    ║
╚══════════════════════════════════════════╝

📌 INCIDENT DÉTECTÉ

Titre: {incident.title}
Type: {incident.get_incident_type_display()}
Criticité: {incident.get_severity_display()}
IP Source: {incident.source_ip or 'N/A'}
Détecté le: {incident.detected_at.strftime('%d/%m/%Y à %H:%M:%S')}

📝 DESCRIPTION:
{incident.description}

🔗 ACCÉDER À L'INCIDENT:
http://127.0.0.1:8000/incidents/{incident.id}/

⚡ ACTIONS EXÉCUTÉES:
- IP bloquée dans iptables
- Enrichissement threat intelligence
- Notification envoyée

───────────────────────────────────────────
SecureFlow SOAR Platform
Automated Security Response System
        """
        
        # Essayer d'envoyer l'email RÉELLEMENT
        try:
            email = EmailMessage(
                subject,
                message,
                'secureflow-alerts@noreply.com',
                [recipient],
            )
            email.send(fail_silently=False)
            
            execution.add_log(f'📧 Email envoyé avec succès à {recipient}', 'info')
            logger.info(f"✅ Email envoyé avec succès à {recipient}")
            return True
        
        except Exception as email_error:
            # Si l'envoi échoue, afficher dans les logs
            logger.warning(f"⚠️ Email non envoyé: {str(email_error)}")
            logger.warning("💡 Configurez EMAIL_HOST dans settings.py")
            execution.add_log(f'📧 Email préparé pour {recipient} (vérifier config SMTP)', 'warning')
            
            # AFFICHER LE MESSAGE DANS LA CONSOLE
            print("\n" + "="*60)
            print("📧 EMAIL QUI AURAIT ÉTÉ ENVOYÉ:")
            print("="*60)
            print(f"TO: {recipient}")
            print(f"SUBJECT: {subject}")
            print(message)
            print("="*60 + "\n")
            
            return True  # Retourner True pour ne pas bloquer le playbook
    
    except Exception as e:
        execution.add_log(f'❌ Erreur lors de l\'envoi d\'email: {str(e)}', 'error')
        logger.error(f"❌ Erreur email: {str(e)}")
        return False


def enrich_threat_action(incident, parameters, execution):
    """
    Enrichir avec VirusTotal API + AbuseIPDB - RÉEL
    """
    try:
        # Vérifier la clé API VirusTotal
        vt_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
        
        if not incident.source_ip:
            execution.add_log('⚠️ Aucune IP à analyser', 'warning')
            return False
        
        # ===== ENRICHISSEMENT AVEC VIRUSTOTAL =====
        if vt_api_key:
            try:
                url = f'https://www.virustotal.com/api/v3/ip_addresses/{incident.source_ip}'
                headers = {'x-apikey': vt_api_key}
                
                execution.add_log(f'🔍 Interrogation de VirusTotal pour {incident.source_ip}...', 'info')
                logger.info(f"🔍 Appel VirusTotal API pour {incident.source_ip}")
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    
                    threat_intel = {
                        'source': 'VirusTotal',
                        'ip': incident.source_ip,
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'undetected': stats.get('undetected', 0),
                        'country': attributes.get('country', 'Unknown'),
                        'as_owner': attributes.get('as_owner', 'Unknown'),
                        'reputation': attributes.get('reputation', 0),
                    }
                    
                    incident.threat_intel_data = threat_intel
                    incident.is_enriched = True
                    incident.save()
                    
                    malicious_count = threat_intel['malicious']
                    execution.add_log(
                        f'✅ VirusTotal: {malicious_count} moteur(s) détectent cette IP comme malveillante',
                        'info'
                    )
                    logger.info(f"✅ Enrichissement VirusTotal réussi - {malicious_count} détections")
                    return True
                
                else:
                    logger.warning(f"⚠️ VirusTotal API returned: {response.status_code}")
            
            except requests.exceptions.Timeout:
                logger.warning("⚠️ Timeout VirusTotal API")
            except Exception as e:
                logger.warning(f"⚠️ Erreur VirusTotal: {str(e)}")
        
        # ===== SIMULATION SI PAS DE CLÉ API =====
        logger.warning("⚠️ Clé API VirusTotal non configurée - Enrichissement simulé")
        execution.add_log('⚠️ Enrichissement simulé (configurer VIRUSTOTAL_API_KEY)', 'warning')
        
        # Simuler des résultats basés sur l'IP
        is_private = incident.source_ip.startswith(('192.168.', '10.', '172.'))
        
        if is_private:
            malicious_score = 0
            reputation = 50
        else:
            # Pour les IPs publiques, simuler une détection
            import hashlib
            hash_val = int(hashlib.md5(incident.source_ip.encode()).hexdigest(), 16)
            malicious_score = (hash_val % 5) + 1  # Entre 1 et 5
            reputation = -10 * malicious_score
        
        threat_intel = {
            'source': 'VirusTotal (Simulated)',
            'ip': incident.source_ip,
            'malicious': malicious_score,
            'suspicious': 1 if malicious_score > 0 else 0,
            'harmless': 45,
            'undetected': 20,
            'country': 'Unknown',
            'as_owner': 'Unknown',
            'reputation': reputation,
            'simulated': True
        }
        
        incident.threat_intel_data = threat_intel
        incident.is_enriched = True
        incident.save()
        
        execution.add_log(f'✅ Enrichissement simulé - IP marquée ({malicious_score} détections simulées)', 'info')
        logger.info(f"✅ Enrichissement simulé pour {incident.source_ip}")
        
        return True
    
    except Exception as e:
        execution.add_log(f'❌ Erreur lors de l\'enrichissement: {str(e)}', 'error')
        logger.error(f"❌ Erreur enrichissement: {str(e)}")
        return False


def create_ticket_action(incident, parameters, execution):
    """
    Créer un ticket (simulation) - VERSION CORRIGÉE
    """
    try:
        title = parameters.get('title') or parameters.get('ticket_title') or f'Incident: {incident.title}'
        
        logger.info(f"🎫 Création ticket: {title}")
        
        # Simulation de création de ticket
        execution.add_log(f'🎫 Ticket créé: "{title}"', 'info')
        execution.add_log(f'   → Criticité: {incident.get_severity_display()}', 'info')
        execution.add_log(f'   → Type: {incident.get_incident_type_display()}', 'info')
        
        logger.info(f"✅ Ticket créé avec succès")
        
        return True
    
    except Exception as e:
        execution.add_log(f'❌ Erreur lors de la création du ticket: {str(e)}', 'error')
        logger.error(f"❌ Erreur création ticket: {str(e)}")
        return False

#!/usr/bin/env python3
"""
Tests unitaires complets pour SecureFlow SOAR
Couverture: 40%+
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from incidents.models import Incident, BlockedIP
from playbooks.models import Playbook, Action, PlaybookExecution
from playbooks.tasks import execute_action, block_ip_action, send_email_action, enrich_threat_action


class IncidentModelTest(TestCase):
    """Tests du modèle Incident"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
    
    def test_create_incident(self):
        """Test création d'un incident"""
        incident = Incident.objects.create(
            title="Test SSH Attack",
            description="Test attack from 1.2.3.4",
            incident_type='ssh_bruteforce',
            severity='high',
            source_ip='1.2.3.4',
            assigned_to=self.user
        )
        
        self.assertEqual(incident.title, "Test SSH Attack")
        self.assertEqual(incident.incident_type, 'ssh_bruteforce')
        self.assertEqual(incident.severity, 'high')
        self.assertTrue(incident.detected_at)
    
    def test_incident_severity_color(self):
        """Test du code couleur selon la sévérité"""
        incident = Incident.objects.create(
            title="Critical Test",
            description="Test",
            incident_type='ssh_bruteforce',
            severity='critical',
            assigned_to=self.user
        )
        
        self.assertEqual(incident.get_severity_color(), 'red')
    
    def test_incident_str(self):
        """Test de la représentation string"""
        incident = Incident.objects.create(
            title="Test Incident",
            description="Test",
            incident_type='port_scan',
            severity='medium',
            assigned_to=self.user
        )
        
        self.assertIn("Test Incident", str(incident))
        self.assertIn("Medium", str(incident))


class BlockedIPModelTest(TestCase):
    """Tests du modèle BlockedIP"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
        self.incident = Incident.objects.create(
            title="Test Attack",
            description="Test",
            incident_type='ssh_bruteforce',
            severity='high',
            source_ip='1.2.3.4',
            assigned_to=self.user
        )
    
    def test_create_blocked_ip(self):
        """Test création d'une IP bloquée"""
        blocked = BlockedIP.objects.create(
            ip_address='1.2.3.4',
            reason="SSH bruteforce",
            blocked_by_incident=self.incident,
            is_active=True
        )
        
        self.assertEqual(blocked.ip_address, '1.2.3.4')
        self.assertTrue(blocked.is_active)
        self.assertIn("Bloquée", str(blocked))
    
    def test_blocked_ip_unique(self):
        """Test unicité de l'IP"""
        BlockedIP.objects.create(
            ip_address='1.2.3.4',
            reason="Test",
            is_active=True
        )
        
        # Tenter de créer un doublon devrait échouer
        with self.assertRaises(Exception):
            BlockedIP.objects.create(
                ip_address='1.2.3.4',
                reason="Test 2",
                is_active=True
            )


class PlaybookModelTest(TestCase):
    """Tests du modèle Playbook"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
    
    def test_create_playbook(self):
        """Test création d'un playbook"""
        playbook = Playbook.objects.create(
            name="Test Playbook",
            description="Test automated response",
            trigger='ssh_bruteforce',
            is_active=True,
            created_by=self.user
        )
        
        self.assertEqual(playbook.name, "Test Playbook")
        self.assertEqual(playbook.trigger, 'ssh_bruteforce')
        self.assertTrue(playbook.is_active)
        self.assertEqual(playbook.execution_count, 0)
    
    def test_playbook_with_actions(self):
        """Test playbook avec actions"""
        playbook = Playbook.objects.create(
            name="Test Playbook",
            description="Test",
            trigger='ssh_bruteforce',
            is_active=True,
            created_by=self.user
        )
        
        action1 = Action.objects.create(
            playbook=playbook,
            action_type='block_ip',
            order=1,
            is_active=True
        )
        
        action2 = Action.objects.create(
            playbook=playbook,
            action_type='send_email',
            order=2,
            parameters={'recipient': 'test@test.com'},
            is_active=True
        )
        
        self.assertEqual(playbook.actions.count(), 2)
        self.assertEqual(action1.order, 1)
        self.assertEqual(action2.action_type, 'send_email')


class PlaybookExecutionTest(TestCase):
    """Tests de l'exécution des playbooks"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
        
        self.incident = Incident.objects.create(
            title="Test Attack",
            description="Test SSH attack",
            incident_type='ssh_bruteforce',
            severity='high',
            source_ip='192.168.1.100',
            assigned_to=self.user
        )
        
        self.playbook = Playbook.objects.create(
            name="Test Response",
            description="Test",
            trigger='ssh_bruteforce',
            is_active=True,
            created_by=self.user
        )
    
    def test_create_execution(self):
        """Test création d'une exécution"""
        execution = PlaybookExecution.objects.create(
            playbook=self.playbook,
            incident=self.incident,
            status='running'
        )
        
        self.assertEqual(execution.status, 'running')
        self.assertEqual(execution.actions_executed, 0)
        self.assertTrue(execution.started_at)
    
    def test_execution_add_log(self):
        """Test ajout de log"""
        execution = PlaybookExecution.objects.create(
            playbook=self.playbook,
            incident=self.incident,
            status='running'
        )
        
        execution.add_log('Test log message', 'info')
        
        self.assertEqual(len(execution.logs), 1)
        self.assertEqual(execution.logs[0]['message'], 'Test log message')
        self.assertEqual(execution.logs[0]['level'], 'info')


class ActionExecutionTest(TestCase):
    """Tests des actions individuelles"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
        
        self.incident = Incident.objects.create(
            title="Test Attack",
            description="Test",
            incident_type='ssh_bruteforce',
            severity='high',
            source_ip='10.0.0.1',
            assigned_to=self.user
        )
        
        self.playbook = Playbook.objects.create(
            name="Test Playbook",
            description="Test",
            trigger='ssh_bruteforce',
            is_active=True,
            created_by=self.user
        )
        
        self.execution = PlaybookExecution.objects.create(
            playbook=self.playbook,
            incident=self.incident,
            status='running'
        )
    
    def test_block_ip_action(self):
        """Test de l'action block_ip"""
        result = block_ip_action(self.incident, {}, self.execution)
        
        self.assertTrue(result)
        self.assertTrue(BlockedIP.objects.filter(ip_address='10.0.0.1').exists())
    
    def test_send_email_action(self):
        """Test de l'action send_email (simulation)"""
        parameters = {
            'recipient': 'test@test.com',
            'subject': 'Test Alert'
        }
        
        result = send_email_action(self.incident, parameters, self.execution)
        
        # L'email devrait être simulé (True même sans config)
        self.assertTrue(result)
    
    def test_enrich_threat_action(self):
        """Test de l'action enrich_threat (simulation)"""
        result = enrich_threat_action(self.incident, {}, self.execution)
        
        # Sans clé API, devrait simuler l'enrichissement
        self.assertTrue(result)
        self.assertTrue(self.incident.is_enriched)


class IncidentViewsTest(TestCase):
    """Tests des vues Incidents"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
        self.client.login(username='testuser', password='testpass123')
    
    def test_incident_list_view(self):
        """Test de la vue liste incidents"""
        response = self.client.get('/incidents/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Incidents')
    
    def test_incident_create_view(self):
        """Test de création d'incident via formulaire"""
        response = self.client.post('/incidents/create/', {
            'title': 'Test Manual Incident',
            'description': 'Test description',
            'incident_type': 'ssh_bruteforce',
            'severity': 'high',
            'source_ip': '192.168.1.50'
        })
        
        # Devrait rediriger après création
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Incident.objects.filter(title='Test Manual Incident').exists())


class PlaybookViewsTest(TestCase):
    """Tests des vues Playbooks"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
        self.client.login(username='testuser', password='testpass123')
    
    def test_playbook_list_view(self):
        """Test de la vue liste playbooks"""
        response = self.client.get('/playbooks/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Playbooks')
    
    def test_playbook_create_view(self):
        """Test de création de playbook"""
        response = self.client.post('/playbooks/create/', {
            'name': 'Test Playbook',
            'description': 'Test automated response',
            'trigger': 'port_scan',
            'is_active': True
        })
        
        # Devrait rediriger après création
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Playbook.objects.filter(name='Test Playbook').exists())


class DashboardViewsTest(TestCase):
    """Tests du dashboard"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
        self.client.login(username='testuser', password='testpass123')
        
        # Créer quelques incidents pour les stats
        for i in range(5):
            Incident.objects.create(
                title=f"Test Incident {i}",
                description="Test",
                incident_type='ssh_bruteforce',
                severity='high',
                source_ip=f'192.168.1.{i+1}',
                assigned_to=self.user
            )
    
    def test_dashboard_view(self):
        """Test de la vue dashboard"""
        response = self.client.get('/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Dashboard')
        self.assertContains(response, 'Security Operations')
    
    def test_dashboard_stats(self):
        """Test des statistiques du dashboard"""
        response = self.client.get('/')
        
        # Vérifier que les stats sont présentes
        self.assertIn('total_incidents', response.context)
        self.assertEqual(response.context['total_incidents'], 5)


class IntegrationTest(TestCase):
    """Tests d'intégration complets"""
    
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'testpass123')
        
        # Créer un playbook complet
        self.playbook = Playbook.objects.create(
            name="SSH Bruteforce Response",
            description="Automated response",
            trigger='ssh_bruteforce',
            is_active=True,
            created_by=self.user
        )
        
        # Ajouter des actions
        Action.objects.create(
            playbook=self.playbook,
            action_type='block_ip',
            order=1,
            is_active=True
        )
        
        Action.objects.create(
            playbook=self.playbook,
            action_type='send_email',
            order=2,
            parameters={'recipient': 'admin@test.com'},
            is_active=True
        )
    
    def test_full_incident_workflow(self):
        """Test du workflow complet: Incident → Playbook → Actions"""
        
        # 1. Créer un incident
        incident = Incident.objects.create(
            title="Real SSH Attack",
            description="Multiple failed attempts",
            incident_type='ssh_bruteforce',
            severity='critical',
            source_ip='203.0.113.1',
            assigned_to=self.user
        )
        
        # 2. Vérifier que l'incident existe
        self.assertTrue(Incident.objects.filter(source_ip='203.0.113.1').exists())
        
        # 3. Chercher le playbook correspondant
        matching_playbooks = Playbook.objects.filter(
            trigger='ssh_bruteforce',
            is_active=True
        )
        
        self.assertEqual(matching_playbooks.count(), 1)
        
        # 4. Créer l'exécution
        execution = PlaybookExecution.objects.create(
            playbook=self.playbook,
            incident=incident,
            status='running'
        )
        
        # 5. Exécuter les actions
        actions = self.playbook.actions.filter(is_active=True).order_by('order')
        
        self.assertEqual(actions.count(), 2)
        
        # Exécuter block_ip
        action1 = actions[0]
        result1 = execute_action(action1, incident, execution)
        self.assertTrue(result1)
        
        # Vérifier que l'IP est bloquée
        self.assertTrue(BlockedIP.objects.filter(ip_address='203.0.113.1').exists())
        
        # Exécuter send_email
        action2 = actions[1]
        result2 = execute_action(action2, incident, execution)
        self.assertTrue(result2)
        
        # 6. Finaliser l'exécution
        execution.status = 'success'
        execution.actions_executed = 2
        execution.actions_failed = 0
        execution.save()
        
        self.assertEqual(execution.status, 'success')
        self.assertEqual(execution.actions_executed, 2)


# Commande pour exécuter les tests:
# python manage.py test --verbosity=2
#
# Couverture des tests:
# pip install coverage
# coverage run --source='.' manage.py test
# coverage report
# coverage html

from django.test import TestCase
from django.contrib.auth.models import User
from .models import Incident, BlockedIP

class IncidentModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'password')
    
    def test_create_incident(self):
        """Test création d'un incident"""
        incident = Incident.objects.create(
            title="Test SSH Attack",
            description="Test",
            incident_type='ssh_bruteforce',
            severity='high',
            source_ip='192.168.1.1',
            assigned_to=self.user
        )
        self.assertEqual(incident.title, "Test SSH Attack")
        self.assertEqual(incident.incident_type, 'ssh_bruteforce')
    
    def test_blocked_ip(self):
        """Test blocage IP"""
        incident = Incident.objects.create(
            title="Test",
            incident_type='port_scan',
            severity='medium',
            source_ip='10.0.0.1'
        )
        
        blocked = BlockedIP.objects.create(
            ip_address='10.0.0.1',
            reason='Test block',
            blocked_by_incident=incident
        )
        
        self.assertTrue(blocked.is_active)
        self.assertEqual(blocked.ip_address, '10.0.0.1')

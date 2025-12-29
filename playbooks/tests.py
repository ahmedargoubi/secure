from django.test import TestCase
from django.contrib.auth.models import User
from .models import Playbook, Action

class PlaybookModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser', 'test@test.com', 'password')
    
    def test_create_playbook(self):
        """Test création d'un playbook"""
        playbook = Playbook.objects.create(
            name="Test Playbook",
            description="Test",
            trigger='ssh_bruteforce',
            created_by=self.user
        )
        self.assertEqual(playbook.name, "Test Playbook")
        self.assertTrue(playbook.is_active)
    
    def test_create_action(self):
        """Test création d'une action"""
        playbook = Playbook.objects.create(
            name="Test",
            trigger='port_scan',
            created_by=self.user
        )
        
        action = Action.objects.create(
            playbook=playbook,
            action_type='block_ip',
            order=1
        )
        
        self.assertEqual(action.action_type, 'block_ip')
        self.assertEqual(action.playbook, playbook)

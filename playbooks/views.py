from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Playbook, Action, PlaybookExecution
from .forms import PlaybookForm, ActionForm

@login_required
def playbook_list(request):
    """Liste de tous les playbooks"""
    playbooks = Playbook.objects.all().order_by('-created_at')
    
    # Statistiques
    total_playbooks = playbooks.count()
    active_playbooks = playbooks.filter(is_active=True).count()
    
    context = {
        'playbooks': playbooks,
        'total_playbooks': total_playbooks,
        'active_playbooks': active_playbooks,
    }
    return render(request, 'playbooks/list.html', context)


@login_required
def playbook_create(request):
    """Créer un nouveau playbook"""
    if request.method == 'POST':
        form = PlaybookForm(request.POST)
        if form.is_valid():
            playbook = form.save(commit=False)
            playbook.created_by = request.user
            playbook.save()
            messages.success(request, f'✅ Playbook "{playbook.name}" créé avec succès !')
            return redirect('playbooks:detail', pk=playbook.pk)
        else:
            messages.error(request, '❌ Erreur lors de la création du playbook.')
    else:
        form = PlaybookForm()
    
    return render(request, 'playbooks/create.html', {'form': form})


@login_required
def playbook_detail(request, pk):
    """Détails d'un playbook avec ses actions"""
    playbook = get_object_or_404(Playbook, pk=pk)
    actions = playbook.actions.all().order_by('order')
    executions = playbook.executions.all()[:10]  # 10 dernières exécutions
    
    context = {
        'playbook': playbook,
        'actions': actions,
        'executions': executions,
        'action_count': actions.count(),
    }
    return render(request, 'playbooks/detail.html', context)


@login_required
def playbook_edit(request, pk):
    """Éditer un playbook existant"""
    playbook = get_object_or_404(Playbook, pk=pk)
    
    if request.method == 'POST':
        form = PlaybookForm(request.POST, instance=playbook)
        if form.is_valid():
            form.save()
            messages.success(request, f'✅ Playbook "{playbook.name}" mis à jour !')
            return redirect('playbooks:detail', pk=playbook.pk)
        else:
            messages.error(request, '❌ Erreur lors de la mise à jour.')
    else:
        form = PlaybookForm(instance=playbook)
    
    context = {
        'form': form,
        'playbook': playbook,
        'is_edit': True
    }
    return render(request, 'playbooks/create.html', context)


@login_required
def playbook_delete(request, pk):
    """Supprimer un playbook"""
    playbook = get_object_or_404(Playbook, pk=pk)
    
    if request.method == 'POST':
        playbook_name = playbook.name
        playbook.delete()
        messages.success(request, f'🗑️ Playbook "{playbook_name}" supprimé.')
        return redirect('playbooks:list')
    
    return render(request, 'playbooks/delete.html', {'playbook': playbook})


@login_required
def playbook_toggle(request, pk):
    """Activer/désactiver un playbook"""
    playbook = get_object_or_404(Playbook, pk=pk)
    playbook.is_active = not playbook.is_active
    playbook.save()
    
    status = "activé" if playbook.is_active else "désactivé"
    messages.success(request, f'✅ Playbook "{playbook.name}" {status}.')
    
    return redirect('playbooks:list')


@login_required
def action_create(request, playbook_pk):
    """Ajouter une action à un playbook"""
    playbook = get_object_or_404(Playbook, pk=playbook_pk)
    
    if request.method == 'POST':
        form = ActionForm(request.POST)
        if form.is_valid():
            action = form.save(commit=False)
            action.playbook = playbook
            action.save()
            messages.success(request, f'✅ Action ajoutée au playbook "{playbook.name}" !')
            return redirect('playbooks:detail', pk=playbook.pk)
        else:
            messages.error(request, '❌ Erreur lors de l\'ajout de l\'action.')
    else:
        # Définir l'ordre par défaut comme le nombre d'actions + 1
        initial_order = playbook.actions.count()
        form = ActionForm(initial={'order': initial_order})
    
    context = {
        'form': form,
        'playbook': playbook,
    }
    return render(request, 'playbooks/action_create.html', context)


@login_required
def action_edit(request, pk):
    """Éditer une action existante"""
    action = get_object_or_404(Action, pk=pk)
    playbook = action.playbook
    
    if request.method == 'POST':
        form = ActionForm(request.POST, instance=action)
        if form.is_valid():
            form.save()
            messages.success(request, '✅ Action mise à jour !')
            return redirect('playbooks:detail', pk=playbook.pk)
    else:
        # Pré-remplir les champs avec les paramètres existants
        initial_data = {
            'email_recipient': action.parameters.get('recipient', ''),
            'email_subject': action.parameters.get('subject', ''),
            'ip_to_block': action.parameters.get('ip_address', ''),
            'ticket_title': action.parameters.get('title', ''),
        }
        form = ActionForm(instance=action, initial=initial_data)
    
    context = {
        'form': form,
        'action': action,
        'playbook': playbook,
        'is_edit': True
    }
    return render(request, 'playbooks/action_create.html', context)


@login_required
def action_delete(request, pk):
    """Supprimer une action"""
    action = get_object_or_404(Action, pk=pk)
    playbook = action.playbook
    
    if request.method == 'POST':
        action.delete()
        messages.success(request, '🗑️ Action supprimée.')
        return redirect('playbooks:detail', pk=playbook.pk)
    
    return render(request, 'playbooks/action_delete.html', {
        'action': action,
        'playbook': playbook
    })


@login_required
def action_toggle(request, pk):
    """Activer/désactiver une action"""
    action = get_object_or_404(Action, pk=pk)
    action.is_active = not action.is_active
    action.save()
    
    status = "activée" if action.is_active else "désactivée"
    messages.success(request, f'✅ Action {status}.')
    
    return redirect('playbooks:detail', pk=action.playbook.pk)
@login_required
def playbook_execute_manual(request, pk):
    """Exécuter manuellement un playbook sur un incident"""
    from .tasks import execute_playbook_async
    
    playbook = get_object_or_404(Playbook, pk=pk)
    
    if request.method == 'POST':
        incident_id = request.POST.get('incident_id')
        
        if incident_id:
            from incidents.models import Incident
            incident = get_object_or_404(Incident, pk=incident_id)
            
            # Lancer l'exécution asynchrone
            execute_playbook_async.delay(playbook.id, incident.id)
            
            messages.success(request, f'⚡ Playbook "{playbook.name}" lancé sur l\'incident "{incident.title}"')
            return redirect('playbooks:detail', pk=playbook.pk)
    
    # Récupérer les incidents actifs
    from incidents.models import Incident
    incidents = Incident.objects.filter(status__in=['new', 'in_progress']).order_by('-detected_at')
    
    context = {
        'playbook': playbook,
        'incidents': incidents,
    }
    return render(request, 'playbooks/execute.html', context)

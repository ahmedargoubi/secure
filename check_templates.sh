#!/bin/bash

echo "🔍 Vérification des templates..."

FILES=(
    "templates/playbooks/list.html"
    "templates/playbooks/create.html"
    "templates/playbooks/detail.html"
    "templates/playbooks/action_create.html"
    "templates/playbooks/delete.html"
    "templates/playbooks/action_delete.html"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        size=$(wc -c < "$file")
        if [ $size -gt 100 ]; then
            echo "✅ $file (${size} bytes)"
        else
            echo "⚠️  $file existe mais est vide ou trop petit!"
        fi
    else
        echo "❌ $file manquant!"
    fi
done

---
name: agentic-sec-guard
description: >
  Load this skill when the user asks to create, audit, or secure an agentic
  tool, an MCP server, an API connector, or any function executed by an
  autonomous LLM agent. Covers attack-surface analysis, least-privilege
  implementation, adversarial test generation, and a final resilience matrix.
---

# Agentic Security Guard

Concevoir, durcir et tester la sécurité des outils (tools/functions) destinés
à être appelés par des agents IA autonomes.

## 1. Analyse de surface d'attaque agentique

Avant d'écrire ou valider du code, évaluer systématiquement 3 risques critiques :

1. **Injection de prompt indirecte** — données externes non fiables (fichiers,
   pages web, sorties d'autres outils) intégrées dans le prompt ou les arguments.
2. **Escalade de privilèges / exécution arbitraire** — shell, SQL, traversée de
   chemin (`../`), exécution de commandes ou de code non contrôlée.
3. **Exfiltration de secrets** — variables d'environnement, tokens, clés API
   exposés dans les sorties retournées au LLM ou dans les logs.

## 2. Implémentation avec principe du moindre privilège

- Forcer la **validation stricte des entrées** : listes blanches, sandboxing de
  répertoires, **absence de `shell=True`**.
- Ajouter un mécanisme d'**approbation humaine (Human-in-the-Loop)** pour toute
  action destructive ou réseau sortante.
- **Filtrer les sorties sensibles** avant retour au LLM (masquage de secrets,
  troncature des données personnelles).

## 3. Génération d'une suite de tests adversariaux

Créer automatiquement un fichier de test (`test_security_<nom_outil>.py` ou
`.ts`) simulant au moins 3 attaques réalistes par injection de prompt :

- Traversée de chemin vers `/etc/passwd` ou `.env`
- Injection de commande via arguments
- Exfiltration de clé API

Vérifier que l'outil bloque chacune de ces attaques.

## 4. Livrable final

Terminer par un tableau Markdown intitulé **« MATRICE DE RÉSILIENCE AGENTIQUE »**
listant chaque vecteur d'attaque testé, le mécanisme de défense implémenté dans
le code et le statut (BLOQUÉ).

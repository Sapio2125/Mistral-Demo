# Rapport SOC — ALRT-2026-0421

## Résumé exécutif

L'alerte ALRT-2026-0421 (source : email_gateway, 2026-11-15T08:47:12Z) a été classée par l'agent soc-triage-analyst comme relevant de la technique MITRE T1566.002, avec une sévérité critique. Les actions de remédiation prioritaires sont listées ci-dessous.

## Technique MITRE ATT&CK

- **Technique** : T1566.002
- **Contexte threat intel** : Tactique et description officielle MITRE ATT&CK pour T1566.002 : https://attack.mitre.org/techniques/T1566/002/

## Sévérité

- **Niveau** : critique
- **Justification** : Phishing ciblé (spearphishing) par lien (T1566.002 - Spearphishing Link) avec usurpation de la marque Microsoft 365 via un domaine lookalike (micros0ft-secure.example.net). Les trois mécanismes d'authentification e-mail (SPF, DKIM, DMARC) sont en échec, confirmant l'origine frauduleuse. La chaîne d'attaque est complète : ouverture de l'e-mail, clic sur le lien et saisie des identifiants sur une page de harvesting par une utilisatrice du département Finance, ce qui constitue une compromission de compte confirmée. Le ciblage d'un compte financier expose l'organisation à un risque élevé de fraude au président (BEC), de détournement de paiements et d'accès à des données sensibles.

## Actions de remédiation

1. Révoquer immédiatement toutes les sessions actives et les jetons d'authentification du compte claire.moreau@example-corp.com, forcer la réinitialisation de son mot de passe et activer l'authentification multifacteur (MFA) si ce n'est pas déjà en place, puis auditer les connexions et actions récentes du compte (règles de messagerie, transferts, changements de coordonnées bancaires).
2. Isoler du réseau le poste FIN-PC-0142 (10.20.14.87), lancer un scan antivirus/EDR complet et vérifier l'absence de mouvement latéral, de persistance ou de vol de session (cookies) issu de la page de phishing.
3. Bloquer les IoCs au niveau de la passerelle e-mail et du proxy/EDR : domaine micros0ft-secure.example.net, adresse IP 203.0.113.47, URL https://micros0ft-secure.example.net/owa/verify?token=9f27ab1c, et rechercher dans les logs toute autre consultation de ces indicateurs par d'autres utilisateurs.

## Source de l'alerte d'origine

- Source : email_gateway
- ID : ALRT-2026-0421
- Date : 2026-11-15T08:47:12Z

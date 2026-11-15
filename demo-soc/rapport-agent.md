# Rapport SOC — ALRT-2026-0421

- Source : email_gateway
- Date de l'alerte : 2026-11-15T08:47:12Z
- Sévérité déclarée : high

## Analyse de l'agent SOC

# Rapport d'analyse SOC — ALRT-2026-0421

## 1. Type d'attaque et chaîne d'attaque (kill chain)

**Type :** Phishing ciblé (spear phishing) avec collecte d'identifiants (credential harvesting), usurpation de marque Microsoft 365.

**Kill chain reconstituée à partir des actions observées :**

| Étape | Détail | Horodatage |
|---|---|---|
| 1. Reconnaissance / livraison | E-mail de phishing envoyé à `claire.moreau@example-corp.com` (service Finance, cible à valeur) depuis `support@micros0ft-secure.example.net` | 08:47:12Z |
| 2. Ingénierie sociale | Objet à pression temporelle (« mot de passe expire dans 24h »), usurpation « Microsoft 365 Support » | — |
| 3. Ouverture | L'utilisateur ouvre l'e-mail | 08:52:03Z |
| 4. Clic | Clic sur le lien `https://micros0ft-secure.example.net/owa/verify?token=9f27ab1c` depuis le poste FIN-PC-0142 (10.20.14.87) | 08:53:41Z |
| 5. Compromission | Saisie des identifiants sur la page de harvesting | 08:54:10Z |
| 6. Impact (potentiel) | Compromission de compte probable → risque d'accès aux données financières, fraude au président (BEC), mouvements latéraux | dès 08:54:10Z |

**Facteurs aggravants techniques :** SPF, DKIM et DMARC tous en échec (le domaine usurpé n'est pas légitime), domaine lookalike `micros0ft-secure.example.net` (substitution 0/O), aucune pièce jointe (pure attaque par lien), cible du département Finance.

## 2. Sévérité

**HAUTE — confirmée, avec recommandation de passage en CRITIQUE si l'authentification multifacteur est absente ou contournable.**

Justification :
- **Credential harvesting confirmé** : l'utilisateur a saisi ses identifiants (action observée, pas seulement supposée) → compromission de compte probable.
- **Cible sensible** : employé du département Finance, donc accès potentiel à des données financières, moyens de paiement, fournisseurs (risque de fraude au faux ordre de virement).
- **Usurpation de marque** de l'IdP (Microsoft 365) : les identifiants volés donnent potentiellement accès à l'ensemble de la messagerie et des services cloud de l'entreprise, pas seulement à la boîte de Claire Moreau.
- **Échec complet de l'authentification e-mail** (SPF/DKIM/DMARC fail) : le mail n'aurait jamais dû passer les contrôles ; défaillance de la passerelle à signaler.
- Fenêtre de compromission courte mais réelle : ~7 minutes entre la réception et la saisie des identifiants.

## 3. Indicateurs de compromission (IoC)

Tous les IoC ci-dessous proviennent exclusivement de l'alerte :

**Adresses e-mail (expéditeur) :**
- `support@micros0ft-secure.example.net` (sender)
- `no-reply@micros0ft-secure.example.net` (reply-to)

**Domaines :**
- `micros0ft-secure.example.net` (domaine lookalike)
- `b0rked.example.net` (domaine du Message-ID)

**URL :**
- `https://micros0ft-secure.example.net/owa/verify?token=9f27ab1c`

**IP :**
- `203.0.113.47` (IP d'envoi/source déclarée)
- `10.20.14.87` (poste interne FIN-PC-0142 — hôte à investiguer, potentiellement compromis)

**Message-ID :**
- `<8f3a2c1d9e@b0rked.example.net>`

**Éléments contextuels :**
- Objet : « Action requise : votre mot de passe expire dans 24h »
- Règle de détection : `EG-PHISH-CRED-HARVEST-042`
- Utilisateur affecté : Claire Moreau (EMP-1187, Finance) — `claire.moreau@example-corp.com`

## 4. Actions immédiates

### 4.1 Confinement (immédiat, < 1h)

1. **Réinitialiser le mot de passe** du compte `claire.moreau@example-corp.com` et **révoquer toutes les sessions actives** (tokens OAuth, sessions webmail, connexions actives Exchange/Entra ID).
2. **Activer/réactiver le MFA** si celui-ci a été contourné ou désactivé ; vérifier les méthodes MFA enregistrées (ajout d'une méthode par l'attaquant ?).
3. **Bloquer les IoC au niveau de la passerelle e-mail et du proxy web** : domaine `micros0ft-secure.example.net`, domaine `b0rked.example.net`, URL complète avec le token, IP `203.0.113.47`.
4. **Rechercher dans les logs** (messagerie + proxy + identité) toute autre réception du même e-mail (Message-ID, domaine, objet) et tout accès à l'URL de harvesting par d'autres utilisateurs.
5. **Isoler le poste FIN-PC-0142 (10.20.14.87)** du réseau le temps de l'investigation (la page de harvesting a pu déposer un malware/cookie de session).
6. **Révoquer les sessions et tokens de l'application Microsoft 365** de l'utilisateur ; vérifier les règles de transfert de courrier créées dans sa boîte (souvent mises en place post-compromission).
7. **Préserver les preuves** : en-têtes complets du mail, logs de la passerelle, logs du proxy pour FIN-PC-0142, journaux d'authentification Entra ID.

### 4.2 Remédiation (court terme)

1. **Audit des connexions** du compte depuis 08:54:10Z : connexions réussies depuis des IP inconnues, téléchargements, envois de mails suspects, créations de règles de boîte, consentements d'applications OAuth.
2. **Recherche d'impact métier** : mails envoyés depuis la boîte de Claire Moreau vers des contacts internes/externes (finance, fournisseurs, banques) après 08:54:10Z → alerter les destinataires, vérifier d'éventuelles demandes de changement de RIB ou de paiement.
3. **Notification** : informer le RSSI, le responsable Finance et la DPO si des données personnelles ont été exposées (obligations RGPD selon le périmètre).
4. **Renforcement des contrôles e-mail** : durcir la politique DMARC (passer à `quarantine`/`reject`), analyser pourquoi un mail avec SPF/DKIM/DMARC fail a été délivré ; ajouter le domaine lookalike à la liste de blocage préventif et surveiller l'enregistrement de nouveaux domaines lookalike « micros0ft ».
5. **Sensibilisation ciblée** : relancer une campagne de sensibilisation auprès du département Finance sur le phishing « mot de passe expiré », avec simulation si possible.
6. **Clôture de l'alerte** uniquement après confirmation de l'absence de persistance (pas de règle de transfert, pas d'app OAuth malveillante, pas de connexion anormale) et validation par le responsable de la sécurité.

---

**Résumé analyste :** Phishing Microsoft 365 réussi contre un compte Finance. Credential harvesting confirmé à 08:54:10Z. Confinement prioritaire sur la réinitialisation/révocation du compte Claire Moreau, le blocage des IoC et l'isolement du poste FIN-PC-0142, puis investigation de l'usage post-compromission du compte.

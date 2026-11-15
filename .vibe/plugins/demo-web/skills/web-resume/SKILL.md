---
name: web-resume
description: Lit une page web via le serveur MCP fetch du plugin et en fait un resume concis en francais.
user-invocable: true
allowed-tools: mcp_fetch.fetch
---

# Resume de page web

1. Demande l'URL a resumer si elle n'est pas fournie dans la requete.
2. Appelle l'outil `fetch` du serveur MCP `fetch` avec cette URL.
3. Redige un resume structure en francais :
   - titre de la page
   - idee principale en 2-3 phrases
   - points cles (3 a 5 puces)
   - lien vers la source

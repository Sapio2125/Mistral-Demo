"""workspace_assistant — Outil agentique sécurisé pour agent IA autonome.

Permet de :
  - lire des fichiers dans un dossier projet (sandboxé)
  - rechercher du texte dans les fichiers du projet
  - envoyer un résumé par HTTP POST vers un webhook externe (HTTPS + whitelist + HITL)

Conçu selon les standards agentic-sec-guard : moindre privilège, validation
stricte des entrées, approbation humaine pour les actions réseau, filtrage
des secrets dans les sorties.
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constantes de sécurité
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 50_000          # Limite de lecture par fichier
MAX_SEARCH_FILE_BYTES = 1_000_000  # Ignore les fichiers > 1 Mo
MAX_MATCHES_PER_FILE = 10        # Limite de lignes retournées par fichier
MAX_SUMMARY_CHARS = 4_000        # Limite du résumé envoyé au webhook
HTTP_TIMEOUT_S = 10

# Motifs de secrets à masquer avant toute sortie vers le LLM
_SECRET_PATTERNS = [
    # Clés/valeurs explicites : api_key = "..." , password: ...
    (re.compile(
        r'(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd|auth)'
        r'(\s*[=:]\s*)(["\']?)[^\s"\']+',
    ), r'\1\2***REDACTED***'),
    # Blocs de clés privées PEM
    (re.compile(
        r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
        re.DOTALL,
    ), '***PRIVATE_KEY_REDACTED***'),
    # Tokens longs (32+ caractères alphanumériques)
    (re.compile(r'\b[A-Za-z0-9_\-]{32,}\b'), '***TOKEN_REDACTED***'),
    # Clés AWS
    (re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), '***AWS_KEY_REDACTED***'),
    # Tokens GitHub
    (re.compile(r'\b(ghp_[a-zA-Z0-9]{36})\b'), '***GITHUB_TOKEN_REDACTED***'),
    # Tokens OpenAI
    (re.compile(r'\b(sk-[a-zA-Z0-9]{20,})\b'), '***API_KEY_REDACTED***'),
]


class SecurityError(Exception):
    """Levée lorsqu'une tentative d'attaque est détectée et bloquée."""


class WorkspaceAssistant:
    """Assistant de workspace sandboxé pour agent autonome.

    Parameters
    ----------
    project_root:
        Chemin absolu du dossier projet servant de bac à sable (sandbox).
    allowed_webhook_domains:
        Liste blanche de domaines autorisés pour le webhook (ex.
        ``["hooks.slack.com"]``). Si vide, tout domaine HTTPS est accepté
        (moins sûr — à réserver aux tests).
    approval_callback:
        Fonction ``(action: str, details: dict) -> bool`` appelée avant toute
        action réseau sortante (Human-in-the-Loop). Retourne ``True`` pour
        autoriser, ``False`` pour bloquer.
    """

    def __init__(
        self,
        project_root: str,
        allowed_webhook_domains: Optional[list[str]] = None,
        approval_callback: Optional[Callable[[str, dict], bool]] = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        if not self.project_root.is_dir():
            raise ValueError(f"project_root n'est pas un dossier valide : {project_root}")
        self.allowed_webhook_domains = allowed_webhook_domains or []
        self._approval_callback = approval_callback or (lambda action, details: False)

    # ------------------------------------------------------------------
    # Utilitaires internes de sécurité
    # ------------------------------------------------------------------

    def _resolve_sandboxed(self, relative_path: str) -> Path:
        """Résout un chemin relatif en garantissant qu'il reste dans le sandbox.

        Bloque : traversée ``../``, chemins absolus, et toute sortie du
        répertoire racine du projet.
        """
        if not isinstance(relative_path, str) or not relative_path.strip():
            raise SecurityError("Chemin vide ou invalide")

        # Rejeter les séparateurs de traversal et les chemins absolus
        if relative_path.startswith(("/", "\\")) or re.search(r"(^|[\\/])\.\.([\\/]|$)", relative_path):
            raise SecurityError(f"Traversée de chemin détectée et bloquée : {relative_path!r}")

        # Normaliser et résoudre
        candidate = (self.project_root / relative_path).resolve()

        # Vérification stricte : le chemin résolu doit être DANS le projet
        try:
            candidate.relative_to(self.project_root)
        except ValueError:
            raise SecurityError(f"Le chemin s'échappe du bac à sable : {relative_path!r}")

        return candidate

    def _filter_sensitive(self, text: str) -> str:
        """Masque les secrets dans un texte avant de le retourner au LLM."""
        for pattern, replacement in _SECRET_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    # ------------------------------------------------------------------
    # Opérations de l'outil
    # ------------------------------------------------------------------

    def read_file(self, relative_path: str, max_bytes: int = MAX_FILE_BYTES) -> str:
        """Lit un fichier du projet (chemin relatif, sandboxé).

        Le contenu est tronqué à ``max_bytes`` et les secrets sont masqués.
        """
        path = self._resolve_sandboxed(relative_path)
        if not path.is_file():
            raise FileNotFoundError(f"Fichier introuvable dans le projet : {relative_path!r}")
        if path.stat().st_size > MAX_SEARCH_FILE_BYTES:
            raise SecurityError(f"Fichier trop volumineux pour être lu : {relative_path!r}")
        content = path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
        return self._filter_sensitive(content)

    def search_text(self, query: str, file_pattern: str = "*") -> list[dict]:
        """Recherche un texte littéral dans les fichiers du projet.

        La requête est traitée comme du texte littéral (``re.escape``) —
        aucune injection regex ni commande n'est possible.
        """
        if not isinstance(query, str) or not query.strip():
            raise SecurityError("Requête de recherche vide")
        if len(query) > 200:
            raise SecurityError("Requête de recherche trop longue (> 200 caractères)")

        # Validation du pattern de fichiers (pas de chemins relatifs)
        if "/" in file_pattern or "\\" in file_pattern or ".." in file_pattern:
            raise SecurityError(f"Pattern de fichier invalide : {file_pattern!r}")

        # Échapper la requête : recherche littérale uniquement
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        results: list[dict] = []

        for f in sorted(self.project_root.rglob(file_pattern)):
            if not f.is_file():
                continue
            try:
                if f.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
                content = f.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            matches = [
                self._filter_sensitive(line.strip())
                for line in content.splitlines()
                if pattern.search(line)
            ]
            if matches:
                results.append({
                    "file": str(f.relative_to(self.project_root)),
                    "matches": matches[:MAX_MATCHES_PER_FILE],
                })
            if len(results) >= 50:  # limite globale de fichiers retournés
                break
        return results

    def send_summary(self, summary: str, webhook_url: str) -> dict:
        """Envoie un résumé vers un webhook externe via HTTPS POST.

        Contrôles appliqués :
          1. L'URL doit être en **HTTPS**.
          2. Le domaine doit être dans la **liste blanche** (si définie).
          3. Le résumé est **tronqué** et les **secrets sont masqués**.
          4. Une **approbation humaine** (HITL) est requise avant l'envoi.
        """
        if not isinstance(summary, str) or not summary.strip():
            raise SecurityError("Résumé vide")
        if len(summary) > MAX_SUMMARY_CHARS:
            summary = summary[:MAX_SUMMARY_CHARS]

        parsed = urlparse(webhook_url)
        if parsed.scheme != "https":
            raise SecurityError(f"Webhook non-HTTPS bloqué : {webhook_url!r}")
        if self.allowed_webhook_domains and parsed.netloc not in self.allowed_webhook_domains:
            raise SecurityError(f"Domaine de webhook non autorisé : {parsed.netloc!r}")

        # Filtrer les secrets avant envoi
        safe_summary = self._filter_sensitive(summary)

        # Human-in-the-Loop : approbation requise pour toute action réseau
        approved = self._approval_callback("webhook_post", {
            "url": webhook_url,
            "summary_preview": safe_summary[:200],
        })
        if not approved:
            raise SecurityError("Action réseau bloquée : approbation humaine refusée (HITL)")

        payload = json.dumps({"summary": safe_summary}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            body = resp.read().decode("utf-8", errors="replace")[:500]
            return {"status": resp.status, "response": body}

"""Agent SOC — analyse d'alertes de sécurité avec le SDK mistralai-agents (1.1.0).

La clé API est lue depuis la variable d'environnement MISTRAL_API_KEY
(par le SDK mistralai) — aucun .env n'est lu ni modifié ici.

Usage :
    uv run python agent_soc.py [chemin_alerte.json]
"""

import asyncio
import json
import sys
from pathlib import Path

from mistralai import agents

MODEL = "mistral-large-latest"

INSTRUCTIONS = """Tu es un analyste SOC (Security Operations Center) senior.
Tu reçois une alerte de sécurité au format JSON et tu produis une analyse structurée.

Pour chaque alerte, tu dois :
1. Identifier le type d'attaque et la chaîne d'attaque probable (kill chain).
2. Évaluer la sévérité (critique / haute / moyenne / basse) et justifier.
3. Lister les indicateurs de compromission (IoC) présents : adresses IP, domaines,
   URLs, pièces jointes, expéditeurs.
4. Recommander des actions immédiates de confinement, puis des actions de remédiation.
5. Indiquer quelles règles de détection seraient pertinentes pour éviter une récidive.

Réponds en français, de façon factuelle et structurée (titres, listes courtes).
Ne jamais inventer d'IoC qui ne figurent pas dans l'alerte.
"""

RACINE = Path(__file__).resolve().parent
DOSSIER_RAPPORTS = RACINE / "rapports"


def creer_agent() -> agents.Agent:
    """Construit l'agent SOC. La clé API vient de MISTRAL_API_KEY (environnement)."""
    return agents.Agent(
        model=MODEL,
        name="soc-analyst",
        instructions=INSTRUCTIONS,
    )


async def analyser_alerte(alerte: dict) -> str:
    """Envoie l'alerte à l'agent SOC et renvoie son analyse textuelle."""
    agent = creer_agent()
    prompt = (
        "Analyse l'alerte de sécurité suivante (JSON) et produis le rapport SOC "
        "demandé dans tes instructions :\n\n"
        + json.dumps(alerte, indent=2, ensure_ascii=False)
    )
    state = await agent.run(prompt)
    if isinstance(state, agents.Busy):
        raise RuntimeError("L'agent est déjà occupé par une autre session (Busy).")
    return state.text


def main() -> None:
    chemin = Path(sys.argv[1]) if len(sys.argv) > 1 else RACINE / "alertes" / "alerte1.json"
    alerte = json.loads(chemin.read_text(encoding="utf-8"))

    analyse = asyncio.run(analyser_alerte(alerte))

    DOSSIER_RAPPORTS.mkdir(exist_ok=True)
    rapport = DOSSIER_RAPPORTS / f"rapport_{alerte.get('id', chemin.stem)}.md"
    contenu = (
        f"# Rapport SOC — {alerte.get('id', 'alerte')}\n\n"
        f"- Source : {alerte.get('source', 'inconnue')}\n"
        f"- Date de l'alerte : {alerte.get('timestamp', 'inconnue')}\n"
        f"- Sévérité déclarée : {alerte.get('severity', 'inconnue')}\n\n"
        f"## Analyse de l'agent SOC\n\n{analyse}\n"
    )
    rapport.write_text(contenu, encoding="utf-8")
    print(f"Rapport généré : {rapport}")


# Instance servie par `agents serve` (découverte au niveau module).
soc = creer_agent()


if __name__ == "__main__":
    main()

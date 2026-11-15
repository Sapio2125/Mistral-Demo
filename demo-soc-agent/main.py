"""Agent SOC — version 2 : lit l'alerte depuis demo-soc/alertes/alerte1.json
et sauvegarde le rapport dans demo-soc/rapport-agent.md.

La clé API est lue depuis MISTRAL_API_KEY (environnement) par le SDK mistralai.
Usage : uv run python main.py
"""

import asyncio
import json
from pathlib import Path

from mistralai import agents

MODEL = "mistral-large-latest"

INSTRUCTIONS = """Tu es un analyste SOC (Security Operations Center) senior.
Tu reçois une alerte de sécurité au format JSON et tu produis une analyse structurée :
1. Type d'attaque et chaîne d'attaque probable (kill chain).
2. Sévérité (critique / haute / moyenne / basse) avec justification.
3. Indicateurs de compromission (IoC) : IP, domaines, URLs, expéditeurs.
4. Actions immédiates de confinement puis remédiation.
Réponds en français, de façon factuelle et structurée.
Ne jamais inventer d'IoC qui ne figurent pas dans l'alerte.
"""

RACINE = Path(__file__).resolve().parent.parent
ALERTE = RACINE / "demo-soc" / "alertes" / "alerte1.json"
RAPPORT = RACINE / "demo-soc" / "rapport-agent.md"


async def main() -> None:
    alerte = json.loads(ALERTE.read_text(encoding="utf-8"))
    agent = agents.Agent(model=MODEL, name="soc-analyst", instructions=INSTRUCTIONS)
    prompt = (
        "Analyse l'alerte de sécurité suivante (JSON) et produis le rapport SOC demandé :\n\n"
        + json.dumps(alerte, indent=2, ensure_ascii=False)
    )
    state = await agent.run(prompt)
    analyse = state.text

    contenu = (
        f"# Rapport SOC — {alerte.get('id', 'alerte')}\n\n"
        f"- Source : {alerte.get('source', 'inconnue')}\n"
        f"- Date de l'alerte : {alerte.get('timestamp', 'inconnue')}\n"
        f"- Sévérité déclarée : {alerte.get('severity', 'inconnue')}\n\n"
        f"## Analyse de l'agent SOC\n\n{analyse}\n"
    )
    RAPPORT.write_text(contenu, encoding="utf-8")
    print(f"Rapport sauvegardé : {RAPPORT}")
    print("\n" + analyse)


if __name__ == "__main__":
    asyncio.run(main())

"""Lance une exécution du workflow "soc-alert-triage" via le client Mistral.

Lit alertes/alerte1.json, exécute le workflow (wait_for_result=True),
affiche le rapport et le sauvegarde dans rapports/rapport-workflow.md.

La clé API est lue depuis MISTRAL_API_KEY (environnement).

Usage :
    uv run python run_workflow.py
"""

import json
from pathlib import Path

from mistralai.client import Mistral

RACINE = Path(__file__).resolve().parent
ALERTE = RACINE / "alertes" / "alerte1.json"
RAPPORT = RACINE / "rapports" / "rapport-workflow.md"


def main() -> None:
    alerte = ALERTE.read_text(encoding="utf-8")

    client = Mistral()  # MISTRAL_API_KEY lu depuis l'environnement
    resultat = client.workflows.execute_workflow(
        workflow_identifier="soc-alert-triage",
        input={"alerte": alerte},
        wait_for_result=True,
    )

    # Le rapport markdown est la sortie du workflow (enveloppe {"result": ...}).
    rapport = getattr(resultat, "output", None) or getattr(resultat, "result", None)
    if isinstance(rapport, dict) and set(rapport) == {"result"}:
        rapport = rapport["result"]
    if not isinstance(rapport, str):
        rapport = json.dumps(rapport, indent=2, ensure_ascii=False)
    rapport = str(rapport)

    print(rapport)

    RAPPORT.parent.mkdir(exist_ok=True)
    RAPPORT.write_text(rapport, encoding="utf-8")
    print(f"\nRapport sauvegardé : {RAPPORT}")


if __name__ == "__main__":
    main()

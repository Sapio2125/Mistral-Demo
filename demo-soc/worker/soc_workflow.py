"""Workflow "soc-alert-triage" — triage complet d'une alerte de sécurité.

Pipeline (SDK mistralai-workflows) :
    classify_alert -> enrich_threat_intel -> build_report

La clé API est lue depuis MISTRAL_API_KEY (environnement) — aucun .env n'est
lu ni modifié ici.

Usage :
    uv run python worker/soc_workflow.py     # démarre le worker local
"""

import json
from datetime import timedelta

from pydantic import BaseModel, Field

from mistralai import agents
from mistralai.workflows import activity, run_worker, workflow

AGENT_NAME = "soc-triage-analyst"


class Classification(BaseModel):
    """Schéma JSON exigé en sortie de l'agent de classification."""

    technique_mitre: str = Field(description="Technique MITRE ATT&CK, ex. T1566.002")
    severite: str = Field(description="critique | haute | moyenne | basse")
    justification: str
    actions: list[str] = Field(description="3 actions de remédiation concrètes")


class Enrichissement(BaseModel):
    """Contexte threat intel sur la technique MITRE (best effort)."""

    technique_mitre: str
    contexte: str = ""


@activity(name="classify_alert", start_to_close_timeout=timedelta(minutes=5))
async def classify_alert(alerte: str) -> Classification:
    """Appelle l'agent soc-triage-analyst et parse sa réponse JSON."""
    import sys
    from pathlib import Path

    racine = Path(__file__).resolve().parent.parent
    if str(racine) not in sys.path:
        sys.path.insert(0, str(racine))
    from agent_soc import INSTRUCTIONS, MODEL

    agent = agents.Agent(model=MODEL, name=AGENT_NAME, instructions=INSTRUCTIONS)
    prompt = (
        "Analyse l'alerte de sécurité suivante (JSON) et réponds UNIQUEMENT "
        "avec un objet JSON structuré contenant exactement les champs : "
        '"technique_mitre" (technique MITRE ATT&CK, ex. T1566.002), "severite" '
        '("critique" | "haute" | "moyenne" | "basse"), "justification", '
        '"actions" (liste de 3 actions de remédiation concrètes). '
        "Ne produis aucun texte hors du JSON.\n\n"
        f"Alerte :\n{alerte}"
    )
    state = await agent.run(prompt)
    texte = state.text.strip()
    # Extraction robuste du bloc JSON (l'agent peut entourer de ```json ... ```).
    if texte.startswith("```"):
        texte = texte.split("```")[1]
        if texte.startswith("json"):
            texte = texte[4:]
        texte = texte.strip()
    return Classification.model_validate_json(texte)


@activity(name="enrich_threat_intel", start_to_close_timeout=timedelta(seconds=60))
async def enrich_threat_intel(technique_mitre: str) -> Enrichissement:
    """Contexte MITRE ATT&CK sur la technique. Résilient : sans contexte si échec."""
    import httpx  # import local : les activités tournent hors du bac à sable Temporal

    enr = Enrichissement(technique_mitre=technique_mitre)
    code = technique_mitre.strip().upper()
    if not code.startswith("T"):
        return enr
    url = f"https://attack.mitre.org/techniques/{code.replace('.', '/')}/"
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as http:
            resp = await http.get(url, headers={"User-Agent": "demo-soc-workflow/1.0"})
        if resp.status_code == 200:
            enr.contexte = (
                f"Tactique et description officielle MITRE ATT&CK pour {code} : {url}"
            )
    except Exception:
        pass  # best effort : on retourne juste la technique
    return enr


@activity(name="build_report", start_to_close_timeout=timedelta(seconds=30))
async def build_report(alerte: str, classification: Classification, enrichissement: Enrichissement) -> str:
    """Assemble le rapport final en markdown (français). Logique purement déterministe."""
    try:
        alerte_obj = json.loads(alerte)
    except json.JSONDecodeError:
        alerte_obj = {}
    source = alerte_obj.get("source", "inconnue")
    alerte_id = alerte_obj.get("id", "inconnue")
    timestamp = alerte_obj.get("timestamp", "inconnue")

    actions_md = "\n".join(f"{i}. {a}" for i, a in enumerate(classification.actions, 1))
    contexte_md = enrichissement.contexte or "Contexte MITRE indisponible (best effort)."

    return (
        f"# Rapport SOC — {alerte_id}\n\n"
        f"## Résumé exécutif\n\n"
        f"L'alerte {alerte_id} (source : {source}, {timestamp}) a été classée par l'agent "
        f"{AGENT_NAME} comme relevant de la technique MITRE {classification.technique_mitre}, "
        f"avec une sévérité {classification.severite}. "
        f"Les actions de remédiation prioritaires sont listées ci-dessous.\n\n"
        f"## Technique MITRE ATT&CK\n\n"
        f"- **Technique** : {classification.technique_mitre}\n"
        f"- **Contexte threat intel** : {contexte_md}\n\n"
        f"## Sévérité\n\n"
        f"- **Niveau** : {classification.severite}\n"
        f"- **Justification** : {classification.justification}\n\n"
        f"## Actions de remédiation\n\n"
        f"{actions_md}\n\n"
        f"## Source de l'alerte d'origine\n\n"
        f"- Source : {source}\n"
        f"- ID : {alerte_id}\n"
        f"- Date : {timestamp}\n"
    )


@workflow.define(name="soc-alert-triage", workflow_display_name="SOC Alert Triage")
class SocAlertTriage:
    """Orchestre le triage complet : classification, enrichissement, rapport."""

    @workflow.entrypoint
    async def run(self, alerte: str) -> str:
        classification = await classify_alert(alerte)
        enrichissement = await enrich_threat_intel(classification.technique_mitre)
        rapport = await build_report(alerte, classification, enrichissement)
        return rapport


async def _main() -> None:
    await run_worker(workflows=[SocAlertTriage])


if __name__ == "__main__":
    import asyncio

    asyncio.run(_main())
